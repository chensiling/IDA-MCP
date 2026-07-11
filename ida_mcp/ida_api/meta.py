"""IDA 原子操作（meta 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

import hashlib
import json
import os

from .core import *  # noqa: F401,F403


def get_database_fingerprint():
    """Return a path-safe hash binding a cursor to the current IDA target."""
    def do():
        def canonical_path(value):
            if not value:
                return ""
            return os.path.normcase(os.path.abspath(str(value)))

        identity = {
            "idb_path": canonical_path(
                idaapi.get_path(idaapi.PATH_TYPE_IDB)),
            "input_path": canonical_path(ida_nalt.get_input_file_path()),
            "image_base": ida_nalt.get_imagebase(),
            "min_ea": ida_ida.inf_get_min_ea(),
            "max_ea": ida_ida.inf_get_max_ea(),
            "auto_is_ok": bool(ida_auto.auto_is_ok()),
        }
        canonical = json.dumps(
            identity, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return run_in_main(do)


def get_analysis_status():
    """Return a non-blocking snapshot of IDA analysis capabilities."""
    def do():
        state = ida_auto.get_auto_state()
        state_name = "UNKNOWN"
        for name in (
                "AU_NONE", "AU_UNK", "AU_CODE", "AU_WEAK", "AU_PROC",
                "AU_TAIL", "AU_TRSP", "AU_USED", "AU_TYPE", "AU_LIBF",
                "AU_LBF2", "AU_LBF3", "AU_CHLB", "AU_FINAL"):
            if getattr(ida_auto, name, object()) == state:
                state_name = name
                break

        try:
            hexrays_available = bool(ida_hexrays.init_hexrays_plugin())
            hexrays_status = (
                "available" if hexrays_available
                else "Hex-Rays decompiler is not available")
        except Exception as e:  # noqa: BLE001
            hexrays_available = False
            hexrays_status = f"Hex-Rays initialization failed: {e}"

        return {
            "auto_analysis_complete": bool(ida_auto.auto_is_ok()),
            "auto_state": {"name": state_name, "value": state},
            "hexrays_available": hexrays_available,
            "hexrays_status": hexrays_status,
            "ida_kernel_version": idaapi.get_kernel_version(),
        }

    return run_in_main(do)


def get_binary_info():
    """二进制全局元信息：文件名/格式/架构/位数/字节序/image base/入口/地址范围。"""
    def do():
        try:
            bits = ida_ida.inf_get_app_bitness()
        except Exception:  # noqa: BLE001
            bits = None
        return {
            "filename": ida_nalt.get_root_filename() or "",
            "file_type": ida_loader.get_file_type_name() or "",
            "processor": ida_idp.get_idp_name() or "",
            "bitness": bits,
            "endian": "big" if ida_ida.inf_is_be() else "little",
            "image_base": ida_nalt.get_imagebase(),
            "min_ea": ida_ida.inf_get_min_ea(),
            "max_ea": ida_ida.inf_get_max_ea(),
            "entry_ea": ida_ida.inf_get_start_ea(),
        }

    return run_in_main(do)


def get_switch_info(ea):
    """取某间接跳转指令的 switch/jump table 信息。返回 {ea, ncases, cases:[{values,target}]}。"""
    def do():
        si = ida_nalt.get_switch_info(ea)
        if not si:
            raise IDAError("NO_SWITCH", f"no switch at {hex(ea)}")
        res = ida_xref.calc_switch_cases(ea, si)
        if not res:
            raise IDAError("NO_SWITCH", f"cannot compute switch cases at {hex(ea)}")
        cases = []
        for idx in range(len(res.cases)):
            cur = res.cases[idx]
            values = [cur[c] for c in range(len(cur))]
            cases.append({"values": values, "target": res.targets[idx]})
        return {"ea": ea, "ncases": len(cases), "cases": cases}

    return run_in_main(do)


def get_stack_frame(ea):
    """取函数栈帧变量。返回 [{name, offset, size, type}]。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        tif = ida_typeinf.tinfo_t()
        if not tif.get_func_frame(func):
            raise IDAError("NO_FRAME", f"no stack frame for function at {hex(ea)}")
        members = []
        try:
            for udm in tif.iter_struct():
                members.append({
                    "name": udm.name,
                    "offset": udm.offset // 8,   # bit → byte
                    "size": udm.size // 8,
                    "type": str(udm.type),
                })
        except Exception:  # noqa: BLE001
            pass
        return members

    return run_in_main(do)


# ---------------------------------------------------------------------------
# patch / 数据定义扩展（批次 E）
# ---------------------------------------------------------------------------
