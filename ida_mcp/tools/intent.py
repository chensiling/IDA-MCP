"""MCP 工具（intent 域）。

从单文件 server.py 拆分。共享项（mcp 实例、resolve_identifier、format_output、
错误翻译、辅助函数、常量）在 .._base。导入本模块即触发 @mcp.tool 注册。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def explore_function(identifier: str, max_lines: int = DEFAULT_MAX_LINES) -> str:
    """Understand what a single function does, in one call. Aggregates everything
    needed to reason about it: pseudocode, callees (each tagged as import and with
    a deterministic category like crypto/network if known), callers, referenced
    strings, and structural features. Prefer this over calling analyze_function +
    decompile + search separately. Categories are deterministic name-table hints,
    NOT semantic conclusions — you decide what the function actually does."""
    try:
        ea = resolve_identifier(identifier)
        info = api.get_func_info(ea)
        start_ea = info["ea"]

        # 伪代码（截断可见）
        try:
            code = api.decompile(start_ea)
            pseudocode, total_lines, truncated = _truncate_lines(code, max_lines)
        except IDAError as e:
            if e.code == "DECOMPILE_FAILED":
                pseudocode, total_lines, truncated = "", 0, False
            else:
                raise

        # callees：标注是否导入 + 确定性分类提示
        import_names = {imp["name"] for imp in api.get_imports()}
        callees = []
        for c in api.get_func_callees(start_ea)[:INTENT_CALLEE_LIMIT]:
            nm = c["to_func_name"]
            cat = categorize_import(nm)
            callees.append({
                "name": nm,
                "import": nm in import_names,
                "category": cat.lower() if cat else None,
            })

        # callers（去重 + 过滤非函数）
        caller_map = {}
        for c in api.get_func_callers(start_ea):
            key = c["from_func_ea"]
            if key == BADADDR:
                continue
            if key in caller_map:
                caller_map[key]["call_count"] += 1
            else:
                caller_map[key] = {"name": c["from_func_name"],
                                   "ea": ea_to_hex(key), "call_count": 1}
        callers = list(caller_map.values())[:INTENT_CALLER_LIMIT]

        # 引用字符串
        seen_str = {}
        for sr in api.get_func_string_refs(start_ea):
            seen_str.setdefault(sr["string_ea"],
                                {"value": sr["value"],
                                 "ea": ea_to_hex(sr["string_ea"])})
        referenced_strings = list(seen_str.values())[:INTENT_STRING_LIMIT]

        # features（确定性事实）
        FUNC_LIB = 0x00000004
        features = {"is_library": bool(info["flags"] & FUNC_LIB),
                    "basic_block_count": None, "cyclomatic_complexity": None,
                    "has_loops": None}
        try:
            blocks = api.get_basic_blocks(start_ea)
        except IDAError:
            blocks = None
        if blocks is not None:
            nc = len(blocks)
            ec = sum(len(b["succs"]) for b in blocks)
            features["basic_block_count"] = nc
            features["cyclomatic_complexity"] = ec - nc + 2
            features["has_loops"] = any(
                any(s <= b["start"] for s in b["succs"]) for b in blocks)

        # 汇总出现的确定性类别（提示信号，非结论）
        categories = sorted({c["category"] for c in callees if c["category"]})

        return format_output({
            "name": info["name"],
            "ea": ea_to_hex(start_ea),
            "size": info["size"],
            "pseudocode": pseudocode,
            "pseudocode_truncated": truncated,
            "total_lines": total_lines,
            "callees": callees,
            "callers": callers,
            "referenced_strings": referenced_strings,
            "features": features,
            "callee_categories": categories,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def explore_data(identifier: str) -> str:
    """Understand a data address or global variable in one call: its name, type,
    raw byte preview (and decoded string if applicable), containing segment, and
    — crucially — which functions READ it versus WRITE it (reference kind is
    split into reads/writes/address-taken). Use this to reason about a global's
    role and data flow. Complements trace_data: this gives a data-centric
    profile (type/value/read-write); trace_data drills into each reference site's
    code. Categories/roles are for you to infer; the tool only reports facts."""
    try:
        ea = resolve_identifier(identifier)

        # 名称
        try:
            name = api.get_name(ea)["name"]
        except IDAError:
            name = ""

        # 类型
        try:
            dtype = api.get_data_type(ea)["type"]
        except IDAError:
            dtype = ""

        # 字节预览
        try:
            byte_hex = api.get_bytes(ea, DATA_BYTES_PREVIEW)["hex_bytes"]
        except IDAError:
            byte_hex = ""

        # 若该地址是字符串，给出解码值（复用 get_strings 匹配同一 ea，避免改字节）
        string_value = None
        try:
            for s in api.get_strings():
                if s["ea"] == ea:
                    string_value = s["value"]
                    break
        except IDAError:
            pass

        # 所属段
        segment = _segment_of(ea)

        # 引用按读/写/取址分类（与 trace_data 的差异化重点）
        readers, writers, addr_taken, other = [], [], [], []
        total_refs = 0
        try:
            xrefs = api.get_xrefs_to(ea)
        except IDAError:
            xrefs = []
        for x in xrefs:
            total_refs += 1
            t = x.get("type", "")
            cf = _containing_function(x["from_ea"])
            site = {"ea": ea_to_hex(x["from_ea"]),
                    "function": cf["name"] if cf else None}
            if t == "Data_Write":
                bucket = writers
            elif t == "Data_Read":
                bucket = readers
            elif t == "Data_Offset":
                bucket = addr_taken
            else:
                bucket = other
            if len(bucket) < DATA_XREF_LIMIT:
                bucket.append(site)

        def dedup(lst):
            seen, out = set(), []
            for s in lst:
                key = s["function"] or s["ea"]
                if key not in seen:
                    seen.add(key)
                    out.append(s)
            return out

        return format_output({
            "ea": ea_to_hex(ea),
            "name": name,
            "type": dtype,
            "bytes_preview": byte_hex,
            "string_value": string_value,
            "segment": segment,
            "reference_summary": {
                "total": total_refs,
                "read_count": len(readers),
                "write_count": len(writers),
                "address_taken_count": len(addr_taken),
            },
            "read_by": dedup(readers),
            "written_by": dedup(writers),
            "address_taken_by": dedup(addr_taken),
            "other_refs": dedup(other),
        })
    except IDAError as e:
        return error_result(e)
@mcp.tool()
def survey_capabilities() -> str:
    """Build a behavioral profile of the whole binary: imports grouped by
    deterministic capability category (crypto/network/file/process/registry/
    anti_debug/kernel_*), and for each imported API the functions that call it.
    Use to answer 'what can this program do and where'. Categories are
    deterministic name-table hints, NOT verdicts — you decide if the behavior is
    malicious/benign. This is one call instead of binary_overview + many searches."""
    try:
        imports = api.get_imports()
        # 按类别分桶；每个导入补上"调用它的函数"（去重，最多 5 个）
        buckets = {}
        for imp in imports:
            cat = categorize_import(imp["name"])
            if not cat:
                continue   # OTHER 不进能力画像，减噪；用 binary_overview 看全量
            entry = {"api": imp["name"], "called_by": []}
            try:
                refs = api.get_xrefs_to(imp["ea"])
            except IDAError:
                refs = []
            seen = set()
            for ref in refs:
                cf = _containing_function(ref["from_ea"])
                nm = cf["name"] if cf else None
                if nm and nm not in seen:
                    seen.add(nm)
                    entry["called_by"].append(nm)
                if len(entry["called_by"]) >= 5:
                    break
            buckets.setdefault(cat.lower(), []).append(entry)

        # 汇总每类的"涉及函数"并集，方便 LLM 定位热点
        summary = {}
        for cat, entries in buckets.items():
            funcs = sorted({f for e in entries for f in e["called_by"]})
            summary[cat] = {"api_count": len(entries),
                            "involved_function_count": len(funcs)}

        return format_output({
            "categories": summary,
            "detail": buckets,
            "note": "Only categorized imports are shown. Categories are "
                    "deterministic hints from known API name tables, not "
                    "behavioral verdicts. Use binary_overview for full imports.",
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def review_string_usage(query: str, limit: int = 15) -> str:
    """Find strings matching a query and show HOW they are used: for each match,
    the functions that reference it plus a short pseudocode snippet of the first
    referencing function. Use to answer 'where is this string used and why'
    without manually chaining search + trace_data + decompile."""
    try:
        q = query.lower()
        matches = []
        for s in api.get_strings():
            if q in s["value"].lower():
                matches.append(s)
        total = len(matches)
        # 排序：完全匹配 > 前缀 > 包含
        def rank(v):
            vl = v.lower()
            return (0 if vl == q else 1 if vl.startswith(q) else 2, len(v))
        matches.sort(key=lambda s: rank(s["value"]))
        truncated = total > limit
        results = []
        for s in matches[:limit]:
            try:
                refs = api.get_xrefs_to(s["ea"])
            except IDAError:
                refs = []
            ref_funcs = []
            seen = set()
            first_func_ea = None
            for ref in refs:
                cf = _containing_function(ref["from_ea"])
                if cf:
                    if first_func_ea is None:
                        first_func_ea = resolve_identifier(cf["name"]) \
                            if cf.get("name") else None
                    if cf["name"] not in seen:
                        seen.add(cf["name"])
                        ref_funcs.append(cf["name"])
                if len(ref_funcs) >= 5:
                    break
            # 第一个引用函数的伪代码片段
            snippet = ""
            if ref_funcs:
                try:
                    fea = resolve_identifier(ref_funcs[0])
                    code = api.decompile(fea)
                    snippet, _, _ = _truncate_lines(code, 15)
                except IDAError:
                    snippet = ""
            results.append({
                "value": s["value"],
                "ea": ea_to_hex(s["ea"]),
                "referenced_by": ref_funcs,
                "first_ref_snippet": snippet,
            })
        return format_output({
            "query": query,
            "total": total,
            "truncated": truncated,
            "results": results,
        })
    except IDAError as e:
        return error_result(e)


DATA_XREF_LIMIT = 20
DATA_BYTES_PREVIEW = 16
