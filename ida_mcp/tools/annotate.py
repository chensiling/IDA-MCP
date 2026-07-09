"""MCP 工具（annotate 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def rename(identifier: str, new_name: str, f: str = None) -> str:
    """Rename a function, global variable, or address. Returns the old and new
    names on success. On name conflict, suggests an alternative name — no need to
    guess."""
    r = _route_if_remote(f, "rename", identifier=identifier, new_name=new_name)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        try:
            result = api.rename(ea, new_name)
        except IDAError as e:
            if e.code == "NAME_CONFLICT":
                return format_output({"success": False, "ea": ea_to_hex(ea),
                                      "attempted_name": new_name,
                                      "conflict": str(e),
                                      "suggestion": _suggest_name(new_name)})
            raise
        return format_output({"success": True, "ea": ea_to_hex(ea),
                              "old_name": result["old_name"],
                              "new_name": result["new_name"]})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_comment(identifier: str, position: str = "line",
                repeatable: bool = False, f: str = None) -> str:
    """Read a comment. position: 'line' (regular comment at an address, shown in
    both disassembly and pseudocode), 'function' (whole-function comment),
    'anterior' (lines above), or 'posterior' (lines below). identifier accepts a
    name, hex address, or integer."""
    r = _route_if_remote(f, "get_comment", identifier=identifier,
                         position=position, repeatable=repeatable)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        if position == "function":
            result = api.get_func_comment(ea, repeatable)
            result["ea"] = ea_to_hex(result["ea"])
            return format_output(result)
        if position == "anterior":
            result = api.get_extra_comment(ea, anterior=True)
            result["ea"] = ea_to_hex(result["ea"])
            return format_output(result)
        if position == "posterior":
            result = api.get_extra_comment(ea, anterior=False)
            result["ea"] = ea_to_hex(result["ea"])
            return format_output(result)
        result = api.get_comment(ea, repeatable)
        return format_output({"ea": ea_to_hex(ea), "comment": result["comment"]})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def set_comment(identifier: str, comment: str, position: str = "line",
                repeatable: bool = False, f: str = None) -> str:
    """Set a comment. position: 'line' (regular comment at an address, appears in
    disassembly and pseudocode), 'function' (whole-function comment), 'anterior'
    (lines above the address), or 'posterior' (lines below). Empty comment
    deletes. identifier accepts a name, hex address, or integer."""
    r = _route_if_remote(f, "set_comment", identifier=identifier,
                         comment=comment, position=position,
                         repeatable=repeatable)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        if position == "function":
            return format_output(api.set_func_comment(ea, comment, repeatable))
        if position == "anterior":
            return format_output(api.set_extra_comment(ea, comment, anterior=True))
        if position == "posterior":
            return format_output(api.set_extra_comment(ea, comment, anterior=False))
        return format_output(api.set_comment(ea, comment, repeatable))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def patch_bytes(identifier: str, hex_bytes: str, f: str = None) -> str:
    """Patch bytes in the IDA database (does NOT modify the original binary file).
    Returns old and new bytes for verification. Use with caution — patches are
    persistent in the IDB."""
    r = _route_if_remote(f, "patch_bytes", identifier=identifier,
                         hex_bytes=hex_bytes)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        cleaned = hex_bytes.replace(" ", "")
        if len(cleaned) % 2 != 0:
            return format_output({"error": {"code": "INVALID_PARAM",
                                  "message": "hex_bytes must have even length"}})
        try:
            bytes.fromhex(cleaned)
        except ValueError:
            return format_output({"error": {"code": "INVALID_PARAM",
                                  "message": "hex_bytes is not valid hex"}})
        result = api.patch_bytes(ea, cleaned)
        return format_output({"success": True, "address": ea_to_hex(ea),
                              "old_bytes": result["old_bytes"],
                              "new_bytes": result["new_bytes"],
                              "length": result["length"]})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def undefine(identifier: str, f: str = None) -> str:
    """Convert the instruction or data at an address back to undefined bytes.
    identifier accepts a name, hex address, or integer. Use before redefining a
    region (e.g. make_code / make_data)."""
    r = _route_if_remote(f, "undefine", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.undefine_item(ea)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def make_code(identifier: str, f: str = None) -> str:
    """Convert bytes at an address into a disassembled instruction (code).
    identifier accepts a name, hex address, or integer. Returns the instruction
    length. Use when IDA left real code as raw bytes."""
    r = _route_if_remote(f, "make_code", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.make_code(ea)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def make_data(identifier: str, data_type: str = "dword", f: str = None) -> str:
    """Convert bytes at an address into a data item. data_type is one of
    byte/word/dword/qword. identifier accepts a name, hex address, or integer."""
    r = _route_if_remote(f, "make_data", identifier=identifier,
                         data_type=data_type)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.make_data(ea, data_type)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def make_string(identifier: str, str_type: str = "c", f: str = None) -> str:
    """Convert bytes at an address into a string literal. str_type is 'c' (ASCII,
    default) or 'unicode' (UTF-16). identifier accepts a name, hex address, or
    integer. Returns the decoded string value."""
    r = _route_if_remote(f, "make_string", identifier=identifier,
                         str_type=str_type)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.make_string(ea, str_type)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "rename": rename,
    "get_comment": get_comment,
    "set_comment": set_comment,
    "patch_bytes": patch_bytes,
    "undefine": undefine,
    "make_code": make_code,
    "make_data": make_data,
    "make_string": make_string,
})
