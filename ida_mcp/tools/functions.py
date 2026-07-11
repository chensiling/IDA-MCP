"""MCP 工具（functions 域）。
"""

from .._base import *  # noqa: F401,F403


def _bounded_section(items, limit):
    page = items[:limit]
    return {
        "items": page,
        "total": len(items),
        "returned": len(page),
        "complete": len(page) == len(items),
    }


def _slice_window(total_lines, anchor_line, max_lines):
    count = min(total_lines, max_lines)
    if count == 0:
        return 0, 0
    desired = anchor_line - count // 2
    start = min(max(desired, 0), total_lines - count)
    return start, start + count


def _slice_decompilation(result, requested_ea, function_start, function_end,
                         slice_mode, max_lines):
    lines = result["lines"]
    total_lines = result["total_lines"]
    effective_mode = slice_mode
    if slice_mode == "auto":
        effective_mode = (
            "start" if requested_ea == function_start else "address")

    anchor_line = None
    statement_ea = None
    reason = None
    if effective_mode == "start":
        anchor_line = 0 if lines else None
        if lines:
            statement_ea = lines[0].get("statement_ea")
        anchor_match = "function_start"
    else:
        candidates = []
        for index, line in enumerate(lines):
            candidate = line.get("statement_ea")
            if isinstance(candidate, bool) or not isinstance(candidate, int):
                continue
            if (function_end is not None
                    and not function_start <= candidate < function_end):
                continue
            candidates.append((index, candidate))
        exact = next(
            ((index, ea) for index, ea in candidates
             if ea == requested_ea), None)
        if exact is not None:
            anchor_line, statement_ea = exact
            anchor_match = "exact_statement"
        elif candidates:
            anchor_line, statement_ea = min(
                candidates,
                key=lambda item: (abs(item[1] - requested_ea), item[0]),
            )
            anchor_match = "nearest_statement"
        else:
            anchor_match = "unavailable"
            reason = (
                "no_pseudocode_lines" if not lines
                else "no_trustworthy_statement_candidates")

    window_anchor = anchor_line if anchor_line is not None else 0
    start_line, end_line = _slice_window(
        total_lines, window_anchor, max_lines)
    selected = lines[start_line:end_line]
    return {
        "pseudocode": "\n".join(line["text"] for line in selected),
        "total_lines": total_lines,
        "truncated": end_line - start_line < total_lines,
        "slice": {
            "requested_mode": slice_mode,
            "mode": effective_mode,
            "start_line": start_line,
            "end_line": end_line,
            "anchor_line": anchor_line,
            "statement_ea": statement_ea,
            "anchor_match": anchor_match,
            "reason": reason,
        },
    }


def _slice_disassembly(result, slice_mode, effective_mode, max_lines):
    instructions = result["instructions"]
    has_lookahead = len(instructions) > max_lines
    page = instructions[:max_lines]
    if has_lookahead:
        next_ea = instructions[max_lines]["ea"]
        total_lines = len(instructions) if result["complete"] else None
        truncated = True
        complete = False
        stop_reason = "count_limit"
    elif result["complete"]:
        next_ea = None
        total_lines = len(page)
        truncated = False
        complete = True
        stop_reason = result["stop_reason"]
    else:
        next_ea = result.get("next_ea")
        total_lines = None
        truncated = True
        complete = False
        stop_reason = result["stop_reason"]
    return {
        "pseudocode": "\n".join(
            f"{ea_to_hex(item['ea'])}  {item['disasm']}" for item in page),
        "total_lines": total_lines,
        "truncated": truncated,
        "next_ea": next_ea,
        "complete": complete,
        "stop_reason": stop_reason,
        "slice": {
            "requested_mode": slice_mode,
            "mode": effective_mode,
            "start_line": 0,
            "end_line": len(page),
            "anchor_line": None,
            "statement_ea": None,
            "anchor_match": "unavailable",
            "reason": "decompilation_failed",
        },
    }


@mcp.tool(annotations=READ_ONLY_TOOL)
def analyze_function(identifier: str, max_lines: MaxLines = DEFAULT_MAX_LINES,
                     include_cfg: bool = False,
                     include_callsites: bool = False,
                     detail_limit: ResultLimit = 200,
                     f: str = None) -> str:
    """Deeply analyze a single function: decompiled pseudocode, call relationships,
    referenced strings, and structural features. Use when you need full context
    about a specific function. Accepts a function name or address string such as
    "0x401000"."""
    r = _route_if_remote(
        f, "analyze_function", identifier=identifier, max_lines=max_lines,
        include_cfg=include_cfg, include_callsites=include_callsites,
        detail_limit=detail_limit)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        include_cfg = _validate_bool(include_cfg, "include_cfg")
        include_callsites = _validate_bool(
            include_callsites, "include_callsites")
        detail_limit = _validate_positive_int(
            detail_limit, "detail_limit", 500)
        ea = resolve_identifier(identifier)
        info = api.get_func_info(ea)
        start_ea = info["ea"]

        try:
            pseudocode, total_lines, truncated = _truncate_lines(
                api.decompile(start_ea), max_lines)
        except IDAError as e:
            if e.code == "DECOMPILE_FAILED":
                pseudocode, total_lines, truncated = "", 0, False
            else:
                raise

        import_names = {imp["name"] for imp in api.get_imports()}
        called_functions = [
            {"name": c["to_func_name"], "import": c["to_func_name"] in import_names}
            for c in api.get_func_callees(start_ea)
        ]

        caller_map = {}
        non_function_ref_count = 0
        for c in api.get_func_callers(start_ea):
            key = c["from_func_ea"]
            if key == BADADDR:
                non_function_ref_count += 1
                continue
            if key in caller_map:
                caller_map[key]["call_count"] += 1
            else:
                caller_map[key] = {"name": c["from_func_name"],
                                    "ea": ea_to_hex(c["from_func_ea"]),
                                    "call_count": 1}
        callers = list(caller_map.values())

        seen_str = {}
        for sr in api.get_func_string_refs(start_ea):
            seen_str.setdefault(sr["string_ea"],
                                {"value": sr["value"],
                                 "ea": ea_to_hex(sr["string_ea"])})
        referenced_strings = list(seen_str.values())

        FUNC_LIB = 0x00000004
        features = {"is_library": bool(info["flags"] & FUNC_LIB),
                    "basic_block_count": None, "cyclomatic_complexity": None,
                    "has_loops": None}
        try:
            blocks = api.get_basic_blocks(start_ea)
        except IDAError:
            if include_cfg:
                raise
            blocks = None
        if blocks is not None:
            node_count = len(blocks)
            edge_count = sum(len(b["succs"]) for b in blocks)
            features["basic_block_count"] = node_count
            features["cyclomatic_complexity"] = edge_count - node_count + 2
            features["has_loops"] = _cfg_has_cycle(blocks)

        cfg = None
        if include_cfg:
            cfg_items = []
            for block in sorted(blocks, key=lambda item: item["start"]):
                cfg_items.append({
                    "start": block["start"],
                    "end": block["end"],
                    "succs": sorted(block.get("succs", ())),
                    "preds": sorted(block.get("preds", ())),
                })
            cfg = _bounded_section(cfg_items, detail_limit)

        static_callsites = None
        if include_callsites:
            callsites = sorted(
                api.get_func_callsites(start_ea),
                key=lambda item: (
                    item["from_ea"],
                    item.get("direct_target_ea", item["to_ea"]),
                    item["to_ea"], item.get("type", ""),
                    item.get("to_func_name", ""),
                ),
            )
            callsite_items = [{
                "callsite_ea": item["from_ea"],
                "ea": item["to_ea"],
                "direct_target_ea": item.get(
                    "direct_target_ea", item["to_ea"]),
                "function": item.get("to_func_name", ""),
                "xref_type": item.get("type", ""),
            } for item in callsites]
            static_callsites = _bounded_section(
                callsite_items, detail_limit)

        return format_output({
            "name": info["name"], "ea": ea_to_hex(start_ea), "size": info["size"],
            "pseudocode": pseudocode, "called_functions": called_functions,
            "callers": callers, "non_function_ref_count": non_function_ref_count,
            "referenced_strings": referenced_strings,
            "features": features, "cfg": cfg,
            "static_callsites": static_callsites,
            "pseudocode_truncated": truncated,
            "total_lines": total_lines,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def decompile(identifier: str, max_lines: MaxLines = DEFAULT_MAX_LINES,
              slice_mode: SliceMode = "auto",
              f: str = None) -> str:
    """Get only the decompiled pseudocode of a function. Lighter than
    analyze_function — use when you already have call/xref context and just need
    the code. Falls back to disassembly if decompilation fails."""
    r = _route_if_remote(
        f, "decompile", identifier=identifier, max_lines=max_lines,
        slice_mode=slice_mode)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        if (not isinstance(slice_mode, str)
                or slice_mode not in {"auto", "start", "address"}):
            raise IDAError(
                "INVALID_PARAM",
                "slice_mode must be one of ['address', 'auto', 'start']")
        requested_ea = resolve_identifier(identifier)
        info = api.get_func_info(requested_ea)
        function_ea = info["ea"]
        function_name = info["name"]
        try:
            sliced = _slice_decompilation(
                api.decompile_with_addresses(function_ea, None),
                requested_ea, function_ea, info.get("end"), slice_mode,
                max_lines)
            source = "decompilation"
        except IDAError as e:
            if e.code != "DECOMPILE_FAILED":
                raise
            effective_mode = slice_mode
            if slice_mode == "auto":
                effective_mode = (
                    "start" if requested_ea == function_ea else "address")
            disasm_ea = (
                function_ea if effective_mode == "start" else requested_ea)
            sliced = _slice_disassembly(
                api.get_disassembly(disasm_ea, max_lines + 1),
                slice_mode, effective_mode, max_lines)
            source = "disassembly"
        return format_output({
            "name": function_name,
            "ea": ea_to_hex(function_ea),
            "requested_ea": ea_to_hex(requested_ea),
            "function_ea": ea_to_hex(function_ea),
            "function_name": function_name,
            "source": source,
            **sliced,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def disassemble(identifier: str, count: ResultLimit = 100,
                f: str = None) -> str:
    """Read bounded machine instructions with bytes and IDA-recorded static flow
    references. Use it to verify pseudocode or inspect code without Hex-Rays;
    unresolved indirect control flow may not have a target reference."""
    r = _route_if_remote(f, "disassemble", identifier=identifier, count=count)
    if r: return r
    try:
        count = _validate_positive_int(count, "count", 500)
        requested_ea = resolve_identifier(identifier)
        result = api.get_disassembly(requested_ea, count)
        result["requested_ea"] = requested_ea
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def decompile_with_addresses(identifier: str,
                             max_lines: MaxLines = DEFAULT_MAX_LINES,
                             f: str = None) -> str:
    """Decompile a function with best-effort statement addresses and separately
    labelled referenced targets. Pseudocode lines do not map one-to-one to machine
    instructions. Heavier than plain decompile; use decompile if you do not need
    address-role hints."""
    r = _route_if_remote(f, "decompile_with_addresses",
                         identifier=identifier, max_lines=max_lines)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        requested_ea = resolve_identifier(identifier)
        info = api.get_func_info(requested_ea)
        function_ea = info["ea"]
        function_name = info["name"]
        result = api.decompile_with_addresses(function_ea, max_lines)
        for ln in result["lines"]:
            for field in ("ea", "statement_ea", "callsite_ea"):
                if ln.get(field) is not None:
                    ln[field] = ea_to_hex(ln[field])
            ln["referenced_targets"] = [
                ea_to_hex(target)
                for target in ln.get("referenced_targets", [])
            ]
        result.update({
            "name": function_name,
            "ea": ea_to_hex(function_ea),
            "requested_ea": ea_to_hex(requested_ea),
            "function_ea": ea_to_hex(function_ea),
            "function_name": function_name,
        })
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def get_stack_frame(identifier: str, f: str = None) -> str:
    """Get a function's stack frame layout: each stack variable's name, offset,
    size, and type. identifier accepts a function name or address string.
    Use to understand local buffer layout (e.g. for overflow analysis)."""
    r = _route_if_remote(f, "get_stack_frame", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        members = api.get_stack_frame(ea)
        return format_output({"count": len(members), "members": members})
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def get_switch(identifier: str, f: str = None) -> str:
    """Get switch/jump-table information for an indirect jump instruction:
    the number of cases and each case's values and target address. identifier
    accepts an address string pointing at the indirect jump."""
    r = _route_if_remote(f, "get_switch", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.get_switch_info(ea)
        result["ea"] = ea_to_hex(result["ea"])
        for c in result["cases"]:
            c["target"] = ea_to_hex(c["target"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "analyze_function": analyze_function,
    "decompile": decompile,
    "disassemble": disassemble,
    "decompile_with_addresses": decompile_with_addresses,
    "get_stack_frame": get_stack_frame,
    "get_switch": get_switch,
})
