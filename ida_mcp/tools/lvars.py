"""MCP 工具（lvars 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool(annotations=READ_ONLY_TOOL)
def list_local_variables(identifier: str, f: str = None) -> str:
    """List a function's local variables and parameters (name, type, size,
    is_arg, used). identifier accepts a name or address string. Use to see
    what variables exist before renaming or retyping them."""
    r = _route_if_remote(f, "list_local_variables", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        lvars = api.get_func_lvars(ea)
        return format_output({"count": len(lvars), "variables": lvars})
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=WRITE_TOOL)
def rename_local_variable(identifier: str, old_name: str, new_name: str,
                          f: str = None) -> str:
    """Rename a local variable inside a function's decompilation. identifier
    accepts a function name or address string. Use meaningful names to
    make pseudocode readable."""
    r = _route_if_remote(f, "rename_local_variable",
                         identifier=identifier, old_name=old_name,
                         new_name=new_name)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.rename_lvar(ea, old_name, new_name))
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=WRITE_TOOL)
def set_local_variable_type(identifier: str, var_name: str, new_type: str,
                            f: str = None) -> str:
    """Set the type of a local variable inside a function (new_type is a C type
    string like 'int *' or 'MY_STRUCT *'). identifier accepts a function name,
    name or address string. Fixing a variable's type often improves the whole
    decompilation."""
    r = _route_if_remote(f, "set_local_variable_type",
                         identifier=identifier, var_name=var_name,
                         new_type=new_type)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        return format_output(api.set_lvar_type(ea, var_name, new_type))
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "list_local_variables": list_local_variables,
    "rename_local_variable": rename_local_variable,
    "set_local_variable_type": set_local_variable_type,
})
