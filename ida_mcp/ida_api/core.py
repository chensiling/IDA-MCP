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
import idautils
import idc

SEARCH_HARD_LIMIT = 500  # 单次原子搜索的硬上限，防止全库扫描无界返回


class IDAError(Exception):
    """携带稳定错误码的 IDA 操作异常。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


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
    idaapi.execute_sync(wrapper, flags)
    if "error" in box:
        raise box["error"]
    return box.get("value")


# ---------------------------------------------------------------------------
# 反汇编 / 反编译 / 函数
# ---------------------------------------------------------------------------
