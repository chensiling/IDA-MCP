"""MCP 工具（intent 域）。
"""

from typing import Optional

from .._base import *  # noqa: F401,F403
from .._contracts import (CursorError, decode_data_cursor,
                          encode_data_cursor)


@mcp.tool(annotations=READ_ONLY_TOOL)
def explore_function(identifier: str, max_lines: MaxLines = DEFAULT_MAX_LINES,
                     f: str = None) -> str:
    """Understand what a single function does, in one call. Aggregates everything
    needed to reason about it: pseudocode, callees (each tagged as import and with
    a deterministic category like crypto/network if known), callers, referenced
    strings, and structural features. Prefer this over calling analyze_function +
    decompile + search separately. Categories are deterministic name-table hints,
    NOT semantic conclusions — you decide what the function actually does."""
    r = _route_if_remote(f, "explore_function",
                         identifier=identifier, max_lines=max_lines)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        ea = resolve_identifier(identifier)
        info = api.get_func_info(ea)
        start_ea = info["ea"]

        try:
            code = api.decompile(start_ea)
            pseudocode, total_lines, truncated = _truncate_lines(code, max_lines)
        except IDAError as e:
            if e.code == "DECOMPILE_FAILED":
                pseudocode, total_lines, truncated = "", 0, False
            else:
                raise

        import_names = {imp["name"] for imp in api.get_imports()}
        all_callees = api.get_func_callees(start_ea)
        callees_total = len(all_callees)
        callees_truncated = callees_total > INTENT_CALLEE_LIMIT
        callees = []
        for c in all_callees[:INTENT_CALLEE_LIMIT]:
            nm = c["to_func_name"]
            cat = categorize_import(nm)
            callees.append({
                "name": nm,
                "import": nm in import_names,
                "category": cat.lower() if cat else None,
            })

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
        all_callers = list(caller_map.values())
        callers_total = len(all_callers)
        callers_truncated = callers_total > INTENT_CALLER_LIMIT
        callers = all_callers[:INTENT_CALLER_LIMIT]

        seen_str = {}
        for sr in api.get_func_string_refs(start_ea):
            seen_str.setdefault(sr["string_ea"],
                                {"value": sr["value"],
                                 "ea": ea_to_hex(sr["string_ea"])})
        all_referenced_strings = list(seen_str.values())
        referenced_strings_total = len(all_referenced_strings)
        referenced_strings_truncated = (
            referenced_strings_total > INTENT_STRING_LIMIT)
        referenced_strings = all_referenced_strings[:INTENT_STRING_LIMIT]

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
            features["has_loops"] = _cfg_has_cycle(blocks)

        categories = sorted({c["category"] for c in callees if c["category"]})

        return format_output({
            "name": info["name"],
            "ea": ea_to_hex(start_ea),
            "size": info["size"],
            "pseudocode": pseudocode,
            "pseudocode_truncated": truncated,
            "total_lines": total_lines,
            "callees": callees,
            "callees_total": callees_total,
            "callees_truncated": callees_truncated,
            "callers": callers,
            "callers_total": callers_total,
            "callers_truncated": callers_truncated,
            "referenced_strings": referenced_strings,
            "referenced_strings_total": referenced_strings_total,
            "referenced_strings_truncated": referenced_strings_truncated,
            "features": features,
            "callee_categories": categories,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def explore_data(identifier: str, read_offset: DataReadOffset = 0,
                 read_size: DataReadSize = DATA_BYTES_PREVIEW,
                 dereference_depth: DereferenceDepth = 0,
                 xref_limit: ResultLimit = DATA_XREF_LIMIT,
                 cursor: Optional[str] = None, f: str = None) -> str:
    """Read a configurable raw-byte window for an `identifier` given as a symbol
    name or hex/decimal address string, and follow a bounded chain only with exact
    IDA pointer type evidence. Classify references into independently cursor-paged
    read, write, address-taken, and other roles. Use this data profile for values
    and roles; use trace_data for code context at reference sites."""
    r = _route_if_remote(
        f, "explore_data", identifier=identifier, read_offset=read_offset,
        read_size=read_size, dereference_depth=dereference_depth,
        xref_limit=xref_limit, cursor=cursor)
    if r: return r
    try:
        read_offset = _validate_bounded_int(
            read_offset, "read_offset", 0, 1048576)
        read_size = _validate_bounded_int(
            read_size, "read_size", 1, 4096)
        dereference_depth = _validate_bounded_int(
            dereference_depth, "dereference_depth", 0, 4)
        xref_limit = _validate_positive_int(
            xref_limit, "xref_limit", 500)
        if cursor is not None and not isinstance(cursor, str):
            raise IDAError("INVALID_PARAM", "cursor must be a string or null")

        ea = resolve_identifier(identifier)
        target_fingerprint = api.get_database_fingerprint()
        if cursor is None:
            offsets = {
                "read_by_offset": 0,
                "written_by_offset": 0,
                "address_taken_by_offset": 0,
                "other_refs_offset": 0,
            }
        else:
            try:
                offsets = decode_data_cursor(
                    cursor, target_fingerprint, ea, read_offset, read_size,
                    dereference_depth)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e

        profile = api.get_data_profile(
            ea, read_offset=read_offset, read_size=read_size,
            dereference_depth=dereference_depth)
        role_names = (
            "read_by", "written_by", "address_taken_by", "other_refs")
        site_counts = {role: 0 for role in role_names}
        grouped = {role: {} for role in role_names}
        for xref in api.get_xrefs_to(ea):
            site = xref["from_ea"]
            xref_type = xref.get("type", "")
            if xref_type == "Data_Read":
                role = "read_by"
            elif xref_type == "Data_Write":
                role = "written_by"
            elif xref_type == "Data_Offset":
                role = "address_taken_by"
            else:
                role = "other_refs"
            site_counts[role] += 1

            if "from_func_ea" in xref:
                function_ea = xref["from_func_ea"]
                function_name = xref.get("from_func_name")
                if function_ea is None:
                    group_key = ("site", site)
                else:
                    group_key = ("function", function_ea)
            else:
                try:
                    func_info = api.get_func_info(site)
                except IDAError as e:
                    if e.code != "NO_FUNCTION":
                        raise
                    function_ea = None
                    function_name = None
                    group_key = ("site", site)
                else:
                    function_ea = func_info["ea"]
                    function_name = func_info["name"]
                    group_key = ("function", function_ea)

            representative = (site, xref_type)
            group = grouped[role].get(group_key)
            if group is None:
                grouped[role][group_key] = {
                    "ea": site,
                    "function": function_name,
                    "function_ea": function_ea,
                    "xref_type": xref_type,
                    "site_count": 1,
                    "_representative": representative,
                }
            else:
                group["site_count"] += 1
                if representative < group["_representative"]:
                    group["ea"] = site
                    group["xref_type"] = xref_type
                    group["_representative"] = representative

        references = {}
        for role in role_names:
            items = list(grouped[role].values())
            items.sort(key=lambda item: (
                item["function_ea"] if item["function_ea"] is not None
                else BADADDR,
                item["function"] or "",
                item["ea"],
                item["xref_type"],
            ))
            for item in items:
                item.pop("_representative", None)
            references[role] = items
        role_specs = (
            ("read_by", "read_by_offset"),
            ("written_by", "written_by_offset"),
            ("address_taken_by", "address_taken_by_offset"),
            ("other_refs", "other_refs_offset"),
        )
        pages = {}
        summary_roles = {}
        next_offsets = {}
        for role, offset_name in role_specs:
            items = references[role]
            offset = offsets[offset_name]
            total = len(items)
            if offset > total:
                raise IDAError(
                    "INVALID_PARAM",
                    f"cursor {role} offset exceeds the current total")
            end = min(offset + xref_limit, total)
            page = items[offset:end]
            pages[role] = page
            next_offsets[offset_name] = end
            summary_roles[role] = {
                "offset": offset,
                "returned": len(page),
                "total": total,
                "has_more": end < total,
            }

        has_more = any(
            value["has_more"] for value in summary_roles.values())
        next_cursor = None
        if has_more:
            try:
                next_cursor = encode_data_cursor(
                    target_fingerprint, ea, read_offset, read_size,
                    dereference_depth,
                    next_offsets["read_by_offset"],
                    next_offsets["written_by_offset"],
                    next_offsets["address_taken_by_offset"],
                    next_offsets["other_refs_offset"],
                )
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e

        raw_reference_total = sum(site_counts.values())
        output = {
            "ea": profile["ea"],
            "name": profile["name"],
            "type": profile["type"],
            "type_size": profile["type_size"],
            "bytes_preview": profile["read"]["hex_bytes"],
            "string_value": profile["string_value"],
            "segment": profile["segment"],
            "read": profile["read"],
            "dereference": profile["dereference"],
            "reference_summary": {
                "total": raw_reference_total,
                "read_count": site_counts["read_by"],
                "write_count": site_counts["written_by"],
                "address_taken_count": site_counts["address_taken_by"],
                "other_count": site_counts["other_refs"],
            },
        }
        for role, _offset_name in role_specs:
            role_summary = summary_roles[role]
            output[role] = pages[role]
            output[f"{role}_total"] = role_summary["total"]
            output[f"{role}_truncated"] = (
                role_summary["total"] > role_summary["returned"])
        output["summary"] = {
            "offset": sum(next_offsets.values()),
            **summary_roles,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
        return format_output(output)
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def survey_capabilities(f: str = None) -> str:
    """Build a behavioral profile of the whole binary: imports grouped by
    deterministic capability category (crypto/network/file/process/registry/
    anti_debug/kernel_*), and for each imported API the functions that call it.
    Use to answer 'what can this program do and where'. Categories are
    deterministic name-table hints, NOT verdicts — you decide if the behavior is
    malicious/benign. This is one call instead of binary_overview + many searches."""
    r = _route_if_remote(f, "survey_capabilities")
    if r: return r
    try:
        imports = api.get_imports()
        buckets = {}
        for imp in imports:
            cat = categorize_import(imp["name"])
            if not cat:
                continue
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


@mcp.tool(annotations=READ_ONLY_TOOL)
def review_string_usage(query: str, limit: ResultLimit = 15,
                        f: str = None) -> str:
    """Find strings matching a query and show HOW they are used: for each match,
    the functions that reference it plus a short pseudocode snippet of the first
    referencing function. Use to answer 'where is this string used and why'
    without manually chaining search + trace_data + decompile."""
    r = _route_if_remote(f, "review_string_usage",
                         query=query, limit=limit)
    if r: return r
    try:
        limit = _validate_positive_int(limit, "limit", 500)
        q = query.lower()
        matches = []
        for s in api.get_strings():
            if q in s["value"].lower():
                matches.append(s)
        total = len(matches)
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
            for ref in refs:
                cf = _containing_function(ref["from_ea"])
                if cf:
                    if cf["name"] not in seen:
                        seen.add(cf["name"])
                        ref_funcs.append(cf["name"])
                if len(ref_funcs) >= 5:
                    break
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


_ALL_TOOLS.update({
    "explore_function": explore_function,
    "explore_data": explore_data,
    "survey_capabilities": survey_capabilities,
    "review_string_usage": review_string_usage,
})
