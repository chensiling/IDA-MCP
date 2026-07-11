"""MCP 工具（types 域）。
"""

from typing import Optional

from .._base import *  # noqa: F401,F403
from .._contracts import CursorError, decode_type_cursor, encode_type_cursor


@mcp.tool(annotations=READ_ONLY_TOOL)
def list_types(name_filter: str = "", limit: ResultLimit = 100,
               cursor: Optional[str] = None, f: str = None) -> str:
    """List local IDB types in stable ordinal pages, using name_filter as a
    case-insensitive substring filter. Continue with cursor and a variable limit;
    rows label kind as exact or explicitly unavailable."""
    r = _route_if_remote(
        f, "list_types", name_filter=name_filter, limit=limit, cursor=cursor)
    if r: return r
    try:
        limit = _validate_positive_int(limit, "limit", 500)
        if not isinstance(name_filter, str):
            raise IDAError("INVALID_PARAM", "name_filter must be a string")
        if (cursor is not None
                and (not isinstance(cursor, str) or not cursor)):
            raise IDAError(
                "INVALID_PARAM", "cursor must be a non-empty string or null")
        target_fingerprint = api.get_database_fingerprint()
        if cursor is None:
            offset = 0
        else:
            try:
                offset = decode_type_cursor(
                    cursor, "list_types", target_fingerprint, name_filter)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e
        types = api.list_local_types(name_filter or None)
        types = sorted(types, key=lambda item: item["ordinal"])
        total = len(types)
        if offset > total:
            raise IDAError(
                "INVALID_PARAM",
                f"cursor offset {offset} exceeds current total {total}")
        page = types[offset:offset + limit]
        next_offset = offset + len(page)
        has_more = next_offset < total
        next_cursor = None
        if has_more:
            try:
                next_cursor = encode_type_cursor(
                    "list_types", target_fingerprint, name_filter,
                    next_offset)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor state: {e}") from e
        return format_output({
            "total": total,
            "truncated": total > len(page),
            "name_filter": name_filter or None,
            "types": page,
            "summary": {
                "total": total,
                "offset": offset,
                "returned": len(page),
                "has_more": has_more,
                "next_cursor": next_cursor,
            },
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def get_type(name: str, member_limit: ResultLimit = 100,
             cursor: Optional[str] = None,
             definition_offset: TypeDefinitionOffset = 0,
             definition_limit: TypeDefinitionLimit = 16384,
             f: str = None) -> str:
    """Get the local type selected by exact name, including exact size/kind, a
    declaration-order member page, and a bounded C-definition window. Continue
    members with cursor; definition_offset and definition_limit are independent."""
    r = _route_if_remote(
        f, "get_type", name=name, member_limit=member_limit, cursor=cursor,
        definition_offset=definition_offset, definition_limit=definition_limit)
    if r: return r
    try:
        member_limit = _validate_positive_int(
            member_limit, "member_limit", 500)
        definition_offset = _validate_bounded_int(
            definition_offset, "definition_offset", 0, 10000000)
        definition_limit = _validate_bounded_int(
            definition_limit, "definition_limit", 1, 65536)
        if not isinstance(name, str) or not name:
            raise IDAError(
                "INVALID_PARAM", "name must be a non-empty string")
        if (cursor is not None
                and (not isinstance(cursor, str) or not cursor)):
            raise IDAError(
                "INVALID_PARAM", "cursor must be a non-empty string or null")
        target_fingerprint = api.get_database_fingerprint()
        if cursor is None:
            member_offset = 0
        else:
            try:
                member_offset = decode_type_cursor(
                    cursor, "get_type", target_fingerprint, name)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e

        result = api.get_type(name)
        members = result.get("members", [])
        member_total = len(members)
        if member_offset > member_total:
            raise IDAError(
                "INVALID_PARAM",
                f"cursor offset {member_offset} exceeds current member total "
                f"{member_total}")
        member_page = members[member_offset:member_offset + member_limit]
        member_next_offset = member_offset + len(member_page)
        member_has_more = member_next_offset < member_total
        member_next_cursor = None
        if member_has_more:
            try:
                member_next_cursor = encode_type_cursor(
                    "get_type", target_fingerprint, name,
                    member_next_offset)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor state: {e}") from e

        definition = result["definition"]
        definition_total = len(definition)
        if definition_offset > definition_total:
            raise IDAError(
                "INVALID_PARAM",
                f"definition_offset {definition_offset} exceeds current "
                f"definition length {definition_total}")
        definition_end = min(
            definition_offset + definition_limit, definition_total)
        definition_window = definition[definition_offset:definition_end]
        definition_complete = definition_end >= definition_total

        result["members"] = member_page
        result["definition"] = definition_window
        result["summary"] = {
            "total": member_total,
            "offset": member_offset,
            "returned": len(member_page),
            "has_more": member_has_more,
            "next_cursor": member_next_cursor,
        }
        result.update({
            "definition_offset": definition_offset,
            "definition_returned": len(definition_window),
            "definition_total_chars": definition_total,
            "definition_complete": definition_complete,
            "definition_next_offset": (
                None if definition_complete else definition_end),
        })
        return format_output(result)
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=WRITE_TOOL)
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


@mcp.tool(annotations=WRITE_TOOL)
def delete_type(name: str, f: str = None) -> str:
    """Delete a named type from the IDB's Local Types. Use to remove a
    struct/union/enum/typedef you no longer need."""
    r = _route_if_remote(f, "delete_type", name=name)
    if r: return r
    try:
        return format_output(api.delete_type(name))
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=WRITE_TOOL)
def apply_type(identifier: str, c_type: str, f: str = None) -> str:
    """Apply a C type to a data address or variable (e.g. c_type='MY_STRUCT' or
    'int[4]'). identifier accepts a name or address string. Use to lay a
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


@mcp.tool(annotations=READ_ONLY_TOOL)
def get_function_prototype(identifier: str, f: str = None) -> str:
    """Get a function's prototype (signature) string. identifier accepts a
    function name or address string. Use to inspect argument/return types
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


@mcp.tool(annotations=WRITE_TOOL)
def set_function_prototype(identifier: str, prototype: str,
                           f: str = None) -> str:
    """Set a function's prototype from a C declaration (e.g.
    'int __fastcall f(int argc, char **argv);'). identifier accepts a name, hex
    address string. Improves decompilation by fixing argument types."""
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
