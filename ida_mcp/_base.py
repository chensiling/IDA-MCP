"""Layer 3 共享基础（_base）：mcp 实例、常量、错误翻译、地址/数字转换、共享辅助。

FastMCP + streamable-http，跑在 IDA 内嵌 Python 里。工具直接调用 ida_api 的原子函数
（不再经 TCP/ida_client）。语义组装规则与原 ida_mcp_server.py 一致。
"""

import json

from mcp.server.fastmcp import FastMCP

from . import ida_api as api
from .ida_api import IDAError
from .categories import categorize_import

# tools/ 各域用 `from .._base import *` 引入共享项。显式声明 __all__，
# 确保下划线前缀的辅助函数（import * 默认跳过）也被导出。
__all__ = [
    # 转发依赖
    "api", "IDAError", "categorize_import",
    # 实例与常量
    "mcp", "HTTP_HOST", "HTTP_PORT",
    "DEFAULT_MAX_LINES", "DEFAULT_SEARCH_LIMIT", "DEFAULT_XREF_LIMIT",
    "DEFAULT_XREF_LIGHT_LIMIT", "STRING_MIN_LENGTH", "STRINGS_LIMIT",
    "ENTRY_PREVIEW_LINES", "CONTEXT_PREVIEW_LINES", "BADADDR",
    "CALLGRAPH_MAX_DEPTH", "CALLGRAPH_NODE_LIMIT",
    "INTENT_CALLEE_LIMIT", "INTENT_CALLER_LIMIT", "INTENT_STRING_LIMIT",
    "DATA_XREF_LIMIT", "DATA_BYTES_PREVIEW",
    "ERROR_MESSAGES", "_ADDR_FIELDS", "_ADDR_LIST_FIELDS",
    # 错误 / 转换 / 输出
    "translate_error", "error_result", "ea_to_hex", "resolve_identifier",
    "format_output", "_to_hex", "_to_dec", "_normalize_numbers",
    # 共享辅助
    "_truncate_lines", "_decompile_or_disasm", "_try_parse_int",
    "_containing_function", "_suggest_name", "_func_start",
    "_callees_of", "_callers_of", "_segment_of",
]

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8765

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

def translate_error(e):
    return ERROR_MESSAGES.get(e.code) or str(e)



def error_result(e):
    return format_output({"error": {"code": e.code, "message": translate_error(e)}})


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
            return api.get_func_by_name(s)["ea"]
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
})
_ADDR_LIST_FIELDS = frozenset({"succs", "preds", "targets", "sites"})



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
            api.get_func_by_name(candidate)
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
