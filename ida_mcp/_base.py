"""Layer 3 共享基础（_base）：mcp 实例、常量、错误翻译、地址/数字转换、共享辅助。

FastMCP + streamable-http，跑在 IDA 内嵌 Python 里。工具直接调用 ida_api 的原子函数
（不再经 TCP/ida_client）。语义组装规则与原 ida_mcp_server.py 一致。
"""

import hashlib
import json
import os
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .runtime_contract import (
    EXPECTED_TOOL_COUNT, READ_ONLY_GUIDANCE, UNKNOWN_TOOL_GUIDANCE,
)

try:
    from . import ida_api as api
    from .ida_api import IDAError
except ImportError:
    api = None

    class IDAError(Exception):
        def __init__(self, code, message):
            super().__init__(message)
            self.code = code

try:
    from .categories import categorize_import
except ImportError:
    def categorize_import(name):
        return None

# tools/ 各域用 `from .._base import *` 引入共享项。显式声明 __all__，
# 确保下划线前缀的辅助函数（import * 默认跳过）也被导出。
__all__ = [
    # 转发依赖
    "api", "IDAError", "categorize_import",
    # 实例与常量
    "mcp", "HTTP_HOST", "HTTP_PORT", "EXPECTED_TOOL_COUNT",
    "READ_ONLY_TOOL", "WRITE_TOOL",
    "MaxLines", "ResultLimit", "CallGraphDepth", "ReachabilityDepth",
    "DataReadOffset", "DataReadSize", "DereferenceDepth",
    "TypeDefinitionOffset", "TypeDefinitionLimit",
    "SearchType", "GraphDirection", "CommentPosition", "DataType",
    "StringType", "SliceMode", "XrefScope",
    "INTERNAL_PORT",
    "DEFAULT_MAX_LINES", "DEFAULT_SEARCH_LIMIT", "DEFAULT_XREF_LIMIT",
    "DEFAULT_XREF_LIGHT_LIMIT", "STRING_MIN_LENGTH", "STRINGS_LIMIT",
    "ENTRY_PREVIEW_LINES", "CONTEXT_PREVIEW_LINES", "BADADDR",
    "CALLGRAPH_MAX_DEPTH", "CALLGRAPH_NODE_LIMIT",
    "INTENT_CALLEE_LIMIT", "INTENT_CALLER_LIMIT", "INTENT_STRING_LIMIT",
    "DATA_XREF_LIMIT", "DATA_BYTES_PREVIEW",
    "ERROR_MESSAGES", "_ADDR_FIELDS", "_ADDR_LIST_FIELDS",
    # 错误 / 转换 / 输出
    "MCPToolError", "tool_error_payload", "raise_tool_error",
    "translate_error", "error_result", "ea_to_hex", "resolve_identifier",
    "format_output", "_to_hex", "_to_dec", "_normalize_numbers",
    # 共享辅助
    "_truncate_lines", "_decompile_or_disasm", "_try_parse_int",
    "_validate_positive_int", "_validate_bounded_int", "_validate_bool",
    "_cfg_has_cycle",
    "_containing_function", "_suggest_name", "_func_start",
    "_callees_of", "_callers_of", "_segment_of",
    # 多实例
    "_ALL_TOOLS", "_MULTI_ROUTER", "get_file_id", "_route_if_remote",
    "_get_router",
]

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8765
INTERNAL_PORT = 8766
DEFAULT_MAX_LINES = 200
DEFAULT_SEARCH_LIMIT = 30
DEFAULT_XREF_LIMIT = 30
DEFAULT_XREF_LIGHT_LIMIT = 50
STRING_MIN_LENGTH = 4
STRINGS_LIMIT = 50
ENTRY_PREVIEW_LINES = 30
CONTEXT_PREVIEW_LINES = 20

# IDA BADADDR（64 位）：get_func_callers 对不属于任何函数的引用点返回此值
BADADDR = 0xFFFFFFFFFFFFFFFF

mcp = FastMCP("ida-mcp", host=HTTP_HOST, port=HTTP_PORT)

READ_ONLY_TOOL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
WRITE_TOOL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)

MaxLines = Annotated[int, Field(ge=1, le=2000)]
ResultLimit = Annotated[int, Field(ge=1, le=500)]
CallGraphDepth = Annotated[int, Field(ge=1, le=5)]
ReachabilityDepth = Annotated[int, Field(ge=1, le=10)]
DataReadOffset = Annotated[int, Field(ge=0, le=1048576)]
DataReadSize = Annotated[int, Field(ge=1, le=4096)]
DereferenceDepth = Annotated[int, Field(ge=0, le=4)]
TypeDefinitionOffset = Annotated[int, Field(ge=0, le=10000000)]
TypeDefinitionLimit = Annotated[int, Field(ge=1, le=65536)]
SearchType = Literal[
    "string", "function", "import", "immediate", "global", "data",
    "export", "all",
]
GraphDirection = Literal["callees", "callers", "both"]
CommentPosition = Literal["line", "function", "anterior", "posterior"]
DataType = Literal["byte", "word", "dword", "qword"]
StringType = Literal["c", "unicode"]
SliceMode = Literal["auto", "start", "address"]
XrefScope = Literal["auto", "address", "function"]

# ---- 多实例：工具注册表与路由器 ----
_ALL_TOOLS = {}
_MULTI_ROUTER = None


def _get_router():
    return _MULTI_ROUTER


def get_file_id(path, instance_id=None):
    """Return an ID for one loaded IDA instance, not just for a file path."""
    normalized = os.path.normcase(os.path.realpath(path))
    owner = os.getpid() if instance_id is None else instance_id
    payload = f"{normalized}\0{owner}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _route_if_remote(f, tool_name, **kwargs):
    router = _get_router()
    if router is None:
        return ""
    result = router.dispatch(tool_name, f, kwargs)
    if (isinstance(result, dict) and set(result) == {"error"}
            and isinstance(result["error"], dict)):
        raise_tool_error(result)
    return format_output(result)


# ---------------------------------------------------------------------------
# 错误翻译
# ---------------------------------------------------------------------------
ERROR_MESSAGES = {
    "NO_FUNCTION": "No function found at the specified address. The address may "
                   "point to data or unanalyzed code.",
    "NO_ENTRY": "The binary has no entry point recorded in the database.",
    "DECOMPILE_FAILED": "Decompilation failed. Falling back to disassembly view.",
    "NAME_CONFLICT": "The name is already in use. See the 'suggestion' field for an "
                     "available alternative.",
    "RENAME_FAILED": "The rename operation failed for a reason other than a name "
                     "conflict (the target address may not be renamable).",
    "NAME_NOT_FOUND": "No symbol with that name exists in the database.",
    "PATCH_FAILED": "The patch could not be applied or failed verification.",
    "READ_FAILED": "Could not read bytes at the specified address. It may be "
                   "outside any loaded segment.",
    "COMMENT_FAILED": "Failed to set the comment at the specified address.",
    "INVALID_PARAM": "Invalid argument. Check the value format (e.g. hex bytes must "
                     "be an even-length hex string).",
    "RESOLVE_FAILED": "Could not resolve the identifier. Try using an exact address "
                      "(e.g., '0x401000') or check the function name spelling.",
    "INTERNAL": "An unexpected internal error occurred.",
    "EXECUTE_SYNC_FAILED": "IDA could not schedule the operation on its main thread.",
    "HEXRAYS_UNAVAILABLE": "The Hex-Rays decompiler is unavailable or could not be initialized.",
    "TYPE_NOT_FOUND": "The requested local type does not exist.",
    "TYPE_READ_FAILED": "IDA could not read the complete local type definition.",
    "TYPE_PARSE_FAILED": "IDA could not parse the supplied type declaration.",
    "SET_TYPE_FAILED": "IDA could not apply the supplied type.",
    "NO_SWITCH": "No switch or jump table exists at the specified address.",
    "NO_FRAME": "The function has no stack frame information.",
    "NO_TYPE": "No type information is available for the requested item.",
    "DELETE_TYPE_FAILED": "IDA could not delete the requested local type.",
    "RENAME_LVAR_FAILED": "IDA could not rename the requested local variable.",
    "SET_LVAR_TYPE_FAILED": "IDA could not apply the type to the requested local variable.",
    "UNDEFINE_FAILED": "IDA could not undefine the item at the specified address.",
    "MAKE_CODE_FAILED": "IDA could not create an instruction at the specified address.",
    "MAKE_DATA_FAILED": "IDA could not create the requested data item.",
    "MAKE_STRING_FAILED": "IDA could not create a string at the specified address.",
    "MULTI_FILE": "Select a connected IDA target with list_files and pass its f value.",
    "UNKNOWN_FILE": "The selected IDA target is unavailable. Refresh targets with list_files.",
    "WORKER_ERROR": "The selected IDA Worker failed to return a valid result.",
    "WORKER_TIMEOUT": "Connecting to the selected IDA Worker timed out.",
    "RESULT_UNKNOWN": "The Worker received the request, but completion could not be confirmed. Verify state before retrying.",
    "READ_ONLY": READ_ONLY_GUIDANCE,
    "UNKNOWN_TOOL": UNKNOWN_TOOL_GUIDANCE,
}



# —— 分散常量（图/意图/数据工具用）——
CALLGRAPH_MAX_DEPTH = 5
CALLGRAPH_NODE_LIMIT = 200
INTENT_CALLEE_LIMIT = 40
INTENT_CALLER_LIMIT = 20
INTENT_STRING_LIMIT = 40
DATA_XREF_LIMIT = 20
DATA_BYTES_PREVIEW = 16


# —— 共享辅助 ——

class MCPToolError(ToolError):
    """FastMCP tool error that preserves a transport-safe structured payload."""

    def __init__(self, payload):
        self.payload = payload
        super().__init__(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def tool_error_payload(error):
    """Build the canonical MCP error payload without losing specific details."""
    if isinstance(error, dict):
        payload = error if set(error) == {"error"} else {"error": error}
        detail = dict(payload["error"])
        code = str(detail.get("code") or "INTERNAL")
        message = str(detail.get("message") or "Unknown tool error")
    else:
        code = str(getattr(error, "code", "INTERNAL"))
        message = str(error)
        detail = {"code": code, "message": message}
    detail["code"] = code
    detail["message"] = message
    guidance = ERROR_MESSAGES.get(code)
    if guidance and not detail.get("guidance"):
        detail["guidance"] = guidance
    return {"error": detail}


def raise_tool_error(error):
    raise MCPToolError(tool_error_payload(error))


def translate_error(e):
    """Compatibility helper for status results that need generic guidance."""
    return ERROR_MESSAGES.get(e.code) or str(e)



def error_result(e):
    """Compatibility name retained for tools; failures now use MCP isError."""
    raise_tool_error(e)


# ---------------------------------------------------------------------------
# 地址转换 / 输出
# ---------------------------------------------------------------------------

def ea_to_hex(ea):
    return hex(ea)



def resolve_identifier(identifier):
    """入参 → int EA。接受 hex 串 / 十进制 / 十进制串 / 函数名。"""
    if isinstance(identifier, bool):
        raise IDAError("RESOLVE_FAILED", f"cannot resolve identifier: {identifier!r}")
    if isinstance(identifier, int):
        return identifier
    if isinstance(identifier, str):
        s = identifier.strip()
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                raise IDAError("RESOLVE_FAILED", f"could not resolve '{identifier}'")
        if s.isdigit():
            return int(s)
        try:
            return api.get_ea_by_name(s)["ea"]
        except IDAError as e:
            if e.code == "NAME_NOT_FOUND":
                raise IDAError("RESOLVE_FAILED", f"could not resolve '{identifier}'")
            raise
    raise IDAError("RESOLVE_FAILED", f"cannot resolve identifier: {identifier!r}")



def format_output(data):
    return json.dumps(_normalize_numbers(data), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 数字统一规范（出口）：所有整数一律转字符串，进制转换全在 MCP 层完成。
#   - 地址类字段（白名单）→ 十六进制字符串 "0x..."
#   - 其余整数            → 十进制字符串 "123"
#   - 已是字符串的值      → 原样保留（兼容工具内已手动转过的地址）
#   - bool 保持 bool；float 保持不变；递归处理 dict/list
# LLM 永远只看到字符串，无需做任何进制换算或担心大整数精度。
# ---------------------------------------------------------------------------
_ADDR_FIELDS = frozenset({
    "ea", "start", "end", "target", "address",
    "image_base", "min_ea", "max_ea", "entry_ea",
    "string_ea", "ref_ea", "from_ea", "to_ea", "from_func_ea", "func_ea",
    "requested_ea", "function_ea", "function_end_ea", "next_ea",
    "statement_ea", "callsite_ea", "direct_target_ea", "target_ea",
    "read_ea", "raw_value",
})
_ADDR_LIST_FIELDS = frozenset({
    "succs", "preds", "targets", "sites", "referenced_targets",
})



def _to_hex(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return hex(v)
    return v   # 已是字符串等，原样



def _to_dec(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return str(v)
    return v



def _normalize_numbers(obj, key=None):
    # 地址数组字段：元素转 hex
    if isinstance(obj, list):
        if key in _ADDR_LIST_FIELDS:
            return [_to_hex(x) if not isinstance(x, (dict, list))
                    else _normalize_numbers(x) for x in obj]
        return [_normalize_numbers(x) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out[k] = _normalize_numbers(v, k)
            elif k in _ADDR_FIELDS:
                out[k] = _to_hex(v)
            else:
                out[k] = _to_dec(v)
        return out
    # 顶层标量（极少见）：非地址按十进制
    return _to_dec(obj)



# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _truncate_lines(text, max_lines):
    lines = text.split("\n")
    total = len(lines)
    if total > max_lines:
        return "\n".join(lines[:max_lines]), total, True
    return text, total, False



def _decompile_or_disasm(ea, max_lines):
    try:
        code = api.decompile(ea)
        text, total, truncated = _truncate_lines(code, max_lines)
        return "decompilation", text, total, truncated
    except IDAError as e:
        if e.code != "DECOMPILE_FAILED":
            raise
        disasm = api.get_disasm(ea, max_lines)
        lines = [f"{ea_to_hex(d['ea'])}  {d['disasm']}" for d in disasm]
        return "disassembly", "\n".join(lines), len(lines), False



def _try_parse_int(text):
    s = text.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _validate_positive_int(value, name, maximum):
    """Validate a bounded MCP control parameter and return it unchanged."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise IDAError("INVALID_PARAM", f"{name} must be an integer")
    if value < 1 or value > maximum:
        raise IDAError(
            "INVALID_PARAM", f"{name} must be between 1 and {maximum}")
    return value


def _validate_bounded_int(value, name, minimum, maximum):
    """Validate an integer range without accepting bool as an integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise IDAError("INVALID_PARAM", f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise IDAError(
            "INVALID_PARAM",
            f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_bool(value, name):
    """Reject integer/string coercions when tools are called directly."""
    if not isinstance(value, bool):
        raise IDAError("INVALID_PARAM", f"{name} must be a boolean")
    return value


def _cfg_has_cycle(blocks):
    """Detect a directed cycle in a basic-block graph using DFS colors."""
    graph = {block["start"]: tuple(block.get("succs", ())) for block in blocks}
    colors = {}

    def visit(node):
        color = colors.get(node, 0)
        if color == 1:
            return True
        if color == 2:
            return False
        colors[node] = 1
        for successor in graph.get(node, ()):
            if successor in graph and visit(successor):
                return True
        colors[node] = 2
        return False

    return any(visit(node) for node in graph if colors.get(node, 0) == 0)



def _containing_function(ea):
    try:
        info = api.get_func_info(ea)
        return {"name": info["name"], "ea": ea_to_hex(info["ea"])}
    except IDAError:
        return None


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

def _suggest_name(base):
    for i in range(100):
        candidate = f"{base}_{i}"
        try:
            api.get_ea_by_name(candidate)
        except IDAError as e:
            if e.code == "NAME_NOT_FOUND":
                return candidate
            return candidate
    return f"{base}_0"



def _func_start(ea):
    """取包含 ea 的函数起始地址（不在函数内返回 None）。"""
    try:
        return api.get_func_info(ea)["ea"]
    except IDAError:
        return None



def _callees_of(ea):
    """返回 ea 函数的被调函数起始地址集合（仅限真实函数）。"""
    out = []
    for c in api.get_func_callees(ea):
        fs = _func_start(c["to_ea"])
        if fs is not None:
            out.append((fs, c["to_func_name"]))
    return out



def _callers_of(ea):
    """返回调用 ea 函数的函数起始地址集合。"""
    out = []
    for c in api.get_func_callers(ea):
        fea = c["from_func_ea"]
        if fea != BADADDR:
            out.append((fea, c["from_func_name"]))
    return out



def _segment_of(ea):
    """返回包含 ea 的段 {name, permissions}，找不到返回 None。"""
    try:
        for seg in api.get_segments():
            if seg["start"] <= ea < seg["end"]:
                return {"name": seg["name"], "permissions": seg["perm"]}
    except IDAError:
        pass
    return None
