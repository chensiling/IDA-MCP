"""IDA API 原子操作层。

所有 IDA API 调用经 run_in_main 封送到主线程。每个函数是一项 IDA 底层能力的薄封装，
不做跨原子组合、分类、截断（那是 server.py 的职责）。

移植自原 ida_mcp_bridge.py 的原子命令，去掉 TCP/命令注册，改为直接可调用函数。
"""

from typing import Any

import idaapi
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_name
import ida_segment
import ida_nalt
import ida_entry
import ida_lines
import ida_xref  # noqa: F401  常量引用
import ida_search
import ida_gdl
import ida_typeinf
import ida_idp
import ida_loader
import ida_frame
import ida_ida
import ida_auto
import ida_ua
import idautils
import idc

SEARCH_HARD_LIMIT = 500  # 单次原子搜索的硬上限，防止全库扫描无界返回


class IDAError(Exception):
    """携带稳定错误码的 IDA 操作异常。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


_HEX_RAYS_INITIALIZED = False


def ensure_hexrays():
    """Initialize Hex-Rays before using any decompiler API.

    Must be called from the IDA main thread.  Keeping this check in the shared
    atomic layer gives every decompiler-backed operation the same failure
    contract when the current IDA edition has no compatible decompiler.
    """
    global _HEX_RAYS_INITIALIZED
    if _HEX_RAYS_INITIALIZED:
        return
    try:
        available = ida_hexrays.init_hexrays_plugin()
    except Exception as e:  # noqa: BLE001
        raise IDAError("DECOMPILE_FAILED",
                       f"failed to initialize Hex-Rays: {e}")
    if not available:
        raise IDAError("DECOMPILE_FAILED",
                       "Hex-Rays decompiler is not available")
    _HEX_RAYS_INITIALIZED = True


# ---------------------------------------------------------------------------
# 主线程封送
# ---------------------------------------------------------------------------
def run_in_main(fn, write=False) -> Any:
    """在 IDA 主线程执行 fn()，返回其结果。

    execute_sync 返回状态码而非 fn 结果，故结果/异常经 box 带出。
    异常原样重抛，保留 IDAError 错误码。write=True 用于修改操作。
    """
    box = {}

    def wrapper():
        try:
            box["value"] = fn()
        except Exception as e:  # noqa: BLE001
            box["error"] = e
        return 1

    flags = idaapi.MFF_WRITE if write else idaapi.MFF_READ
    status = idaapi.execute_sync(wrapper, flags)
    if status == -1:
        raise IDAError("INTERNAL", "failed to execute IDA API call on main thread")
    if "error" in box:
        raise box["error"]
    if "value" not in box:
        raise IDAError("INTERNAL", "IDA API call did not execute")
    return box["value"]


# ---------------------------------------------------------------------------
# 反汇编 / 反编译 / 函数
# ---------------------------------------------------------------------------
