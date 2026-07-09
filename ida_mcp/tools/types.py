"""MCP 工具（types 域）。

从单文件 server.py 拆分。共享项（mcp 实例、resolve_identifier、format_output、
错误翻译、辅助函数、常量）在 .._base。导入本模块即触发 @mcp.tool 注册。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def list_types(name_filter: str = "", limit: int = 100) -> str:
    """List the local types (structs, unions, enums, typedefs) defined in the IDB.
    Use name_filter to search by substring (case-insensitive) — recommended, as
    IDBs often have thousands of types. Returns ordinal, name, and kind."""
    try:
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
def get_type(name: str) -> str:
    """Get the full definition of a named type (struct/union/enum/typedef):
    its C definition, size, and members (with offsets/values). Use before
    applying a type or to understand a data structure."""
    try:
        return format_output(api.get_type(name))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def create_type(c_declaration: str) -> str:
    """Create or update local type(s) from a C declaration (e.g.
    'struct Foo { int a; char *b; };' or 'typedef ... ;' or an enum). Accepts
    multiple declarations. The types then become applyable via apply_type."""
    try:
        return format_output(api.create_type(c_declaration))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def delete_type(name: str) -> str:
    """Delete a named type from the IDB's Local Types. Use to remove a
    struct/union/enum/typedef you no longer need."""
    try:
        return format_output(api.delete_type(name))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def apply_type(identifier: str, c_type: str) -> str:
    """Apply a C type to a data address or variable (e.g. c_type='MY_STRUCT' or
    'int[4]'). identifier accepts a name, hex address, or integer. Use to lay a
    struct/array over raw data."""
    try:
        ea = resolve_identifier(identifier)
        result = api.apply_type(ea, c_type)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def get_function_prototype(identifier: str) -> str:
    """Get a function's prototype (signature) string. identifier accepts a
    function name, hex address, or integer. Use to inspect argument/return types
    before refining them."""
    try:
        ea = resolve_identifier(identifier)
        result = api.get_func_prototype(ea)
        result["ea"] = ea_to_hex(result["ea"])
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def set_function_prototype(identifier: str, prototype: str) -> str:
    """Set a function's prototype from a C declaration (e.g.
    'int __fastcall f(int argc, char **argv);'). identifier accepts a name, hex
    address, or integer. Improves decompilation by fixing argument types."""
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.set_func_prototype(ea, prototype))
    except IDAError as e:
        return error_result(e)


# ---------------------------------------------------------------------------
# Hex-Rays 深化工具（批次 B）
# ---------------------------------------------------------------------------
