"""MCP 工具（types 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def list_types(name_filter: str = "", limit: int = 100, f: str = None) -> str:
    """List the local types (structs, unions, enums, typedefs) defined in the IDB.
    Use name_filter to search by substring (case-insensitive) — recommended, as
    IDBs often have thousands of types. Returns ordinal, name, and kind."""
    r = _route_if_remote(f, "list_types", name_filter=name_filter, limit=limit)
    if r: return r
    try:
        limit = _validate_positive_int(limit, "limit", 500)
        types = api.list_local_types(name_filter or None)
        total = len(types)
        truncated = total > limit
        return format_output({
            "total": total,
            "truncated": truncated,
            "name_filter": name_filter or None,
            "types": types[:limit],
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_type(name: str, f: str = None) -> str:
    """Get the full definition of a named type (struct/union/enum/typedef):
    its C definition, size, and members (with offsets/values). Use before
    applying a type or to understand a data structure."""
    r = _route_if_remote(f, "get_type", name=name)
    if r: return r
    try:
        return format_output(api.get_type(name))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def create_type(c_declaration: str, f: str = None) -> str:
    """Create or update local type(s) from a C declaration (e.g.
    'struct Foo { int a; char *b; };' or 'typedef ... ;' or an enum). Accepts
    multiple declarations. The types then become applyable via apply_type."""
    r = _route_if_remote(f, "create_type", c_declaration=c_declaration)
    if r: return r
    try:
        return format_output(api.create_type(c_declaration))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def delete_type(name: str, f: str = None) -> str:
    """Delete a named type from the IDB's Local Types. Use to remove a
    struct/union/enum/typedef you no longer need."""
    r = _route_if_remote(f, "delete_type", name=name)
    if r: return r
    try:
        return format_output(api.delete_type(name))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def apply_type(identifier: str, c_type: str, f: str = None) -> str:
    """Apply a C type to a data address or variable (e.g. c_type='MY_STRUCT' or
    'int[4]'). identifier accepts a name, hex address, or integer. Use to lay a
    struct/array over raw data."""
    r = _route_if_remote(f, "apply_type", identifier=identifier, c_type=c_type)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.apply_type(ea, c_type)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_function_prototype(identifier: str, f: str = None) -> str:
    """Get a function's prototype (signature) string. identifier accepts a
    function name, hex address, or integer. Use to inspect argument/return types
    before refining them."""
    r = _route_if_remote(f, "get_function_prototype", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        result = api.get_func_prototype(ea)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def set_function_prototype(identifier: str, prototype: str,
                           f: str = None) -> str:
    """Set a function's prototype from a C declaration (e.g.
    'int __fastcall f(int argc, char **argv);'). identifier accepts a name, hex
    address, or integer. Improves decompilation by fixing argument types."""
    r = _route_if_remote(f, "set_function_prototype",
                         identifier=identifier, prototype=prototype)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.set_func_prototype(ea, prototype))
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "list_types": list_types,
    "get_type": get_type,
    "create_type": create_type,
    "delete_type": delete_type,
    "apply_type": apply_type,
    "get_function_prototype": get_function_prototype,
    "set_function_prototype": set_function_prototype,
})
