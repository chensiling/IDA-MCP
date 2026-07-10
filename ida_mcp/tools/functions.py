"""MCP 工具（functions 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def analyze_function(identifier: str, max_lines: int = DEFAULT_MAX_LINES,
                     f: str = None) -> str:
    """Deeply analyze a single function: decompiled pseudocode, call relationships,
    referenced strings, and structural features. Use when you need full context
    about a specific function. Accepts function name, address (hex string like
    "0x401000"), or integer."""
    r = _route_if_remote(f, "analyze_function",
                         identifier=identifier, max_lines=max_lines)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
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
            blocks = None
        if blocks is not None:
            node_count = len(blocks)
            edge_count = sum(len(b["succs"]) for b in blocks)
            features["basic_block_count"] = node_count
            features["cyclomatic_complexity"] = edge_count - node_count + 2
            features["has_loops"] = _cfg_has_cycle(blocks)

        return format_output({
            "name": info["name"], "ea": ea_to_hex(start_ea), "size": info["size"],
            "pseudocode": pseudocode, "called_functions": called_functions,
            "callers": callers, "non_function_ref_count": non_function_ref_count,
            "referenced_strings": referenced_strings,
            "features": features, "pseudocode_truncated": truncated,
            "total_lines": total_lines,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def decompile(identifier: str, max_lines: int = DEFAULT_MAX_LINES,
              f: str = None) -> str:
    """Get only the decompiled pseudocode of a function. Lighter than
    analyze_function — use when you already have call/xref context and just need
    the code. Falls back to disassembly if decompilation fails."""
    r = _route_if_remote(f, "decompile",
                         identifier=identifier, max_lines=max_lines)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        ea = resolve_identifier(identifier)
        try:
            name = api.get_name(ea)["name"]
        except IDAError:
            name = ""
        source, text, total_lines, truncated = _decompile_or_disasm(ea, max_lines)
        return format_output({"name": name, "ea": ea_to_hex(ea), "source": source,
                              "pseudocode": text, "total_lines": total_lines,
                              "truncated": truncated})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def decompile_with_addresses(identifier: str,
                             max_lines: int = DEFAULT_MAX_LINES,
                             f: str = None) -> str:
    """Decompile a function and annotate each pseudocode line with its
    corresponding address. Use when you need to correlate pseudocode lines to
    machine addresses (e.g. to set a breakpoint or map a bug to an instruction).
    Heavier than plain decompile; use decompile if you don't need addresses."""
    r = _route_if_remote(f, "decompile_with_addresses",
                         identifier=identifier, max_lines=max_lines)
    if r: return r
    try:
        max_lines = _validate_positive_int(max_lines, "max_lines", 2000)
        ea = resolve_identifier(identifier)
        result = api.decompile_with_addresses(ea, max_lines)
        for ln in result["lines"]:
            if ln["ea"] is not None:
                ln["ea"] = ea_to_hex(ln["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_stack_frame(identifier: str, f: str = None) -> str:
    """Get a function's stack frame layout: each stack variable's name, offset,
    size, and type. identifier accepts a function name, hex address, or integer.
    Use to understand local buffer layout (e.g. for overflow analysis)."""
    r = _route_if_remote(f, "get_stack_frame", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        members = api.get_stack_frame(ea)
        return format_output({"count": len(members), "members": members})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_switch(identifier: str, f: str = None) -> str:
    """Get switch/jump-table information for an indirect jump instruction:
    the number of cases and each case's values and target address. identifier
    accepts a hex address or integer pointing at the indirect jump."""
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
    "decompile_with_addresses": decompile_with_addresses,
    "get_stack_frame": get_stack_frame,
    "get_switch": get_switch,
})
