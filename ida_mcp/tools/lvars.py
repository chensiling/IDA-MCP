"""MCP 工具（lvars 域）。

从单文件 server.py 拆分。共享项（mcp 实例、resolve_identifier、format_output、
错误翻译、辅助函数、常量）在 .._base。导入本模块即触发 @mcp.tool 注册。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def list_local_variables(identifier: str) -> str:
    """List a function's local variables and parameters (name, type, size,
    is_arg, used). identifier accepts a name, hex address, or integer. Use to see
    what variables exist before renaming or retyping them."""
    try:
        ea = resolve_identifier(identifier)
        lvars = api.get_func_lvars(ea)
        return format_output({"count": len(lvars), "variables": lvars})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def rename_local_variable(identifier: str, old_name: str, new_name: str) -> str:
    """Rename a local variable inside a function's decompilation. identifier
    accepts a function name, hex address, or integer. Use meaningful names to
    make pseudocode readable."""
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.rename_lvar(ea, old_name, new_name))
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def set_local_variable_type(identifier: str, var_name: str, new_type: str) -> str:
    """Set the type of a local variable inside a function (new_type is a C type
    string like 'int *' or 'MY_STRUCT *'). identifier accepts a function name,
    hex address, or integer. Fixing a variable's type often improves the whole
    decompilation."""
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.set_lvar_type(ea, var_name, new_type))
    except IDAError as e:
        return error_result(e)
