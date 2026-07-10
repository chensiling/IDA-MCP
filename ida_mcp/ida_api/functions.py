"""IDA 原子操作（functions 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def decompile(ea):
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        ensure_hexrays()
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise IDAError("DECOMPILE_FAILED", str(e))
        if cfunc is None:
            raise IDAError("DECOMPILE_FAILED",
                           f"decompilation returned None at {hex(func.start_ea)}")
        return str(cfunc)

    return run_in_main(do)


def get_disasm(ea, count):
    def do():
        result = []
        cur = ea
        for _ in range(count):
            if cur == idaapi.BADADDR or not ida_bytes.is_loaded(cur):
                break
            line = ida_lines.tag_remove(idc.generate_disasm_line(cur, 0) or "")
            item_size = ida_bytes.get_item_size(cur)
            raw = ida_bytes.get_bytes(cur, item_size) or b""
            result.append({"ea": cur, "disasm": line, "bytes": raw.hex()})
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt
        return result

    return run_in_main(do)


def get_func_list():
    def do():
        result = []
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea)
            func = ida_funcs.get_func(ea)
            size = func.size() if func else 0
            result.append({"ea": ea, "name": name, "size": size})
        return result

    return run_in_main(do)


def get_func_info(ea):
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        return {
            "ea": func.start_ea,
            "name": ida_funcs.get_func_name(func.start_ea),
            "start": func.start_ea,
            "end": func.end_ea,
            "size": func.size(),
            "flags": func.flags,
        }

    return run_in_main(do)


def get_func_by_name(name):
    def do():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            raise IDAError("NAME_NOT_FOUND", f"name not found: {name}")
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"'{name}' is not a function")
        return {"ea": func.start_ea,
                "name": ida_funcs.get_func_name(func.start_ea)}

    return run_in_main(do)


def get_entry_point():
    def do():
        if ida_entry.get_entry_qty() <= 0:
            raise IDAError("NO_ENTRY", "no entry point in database")
        ordinal = ida_entry.get_entry_ordinal(0)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ida_name.get_name(ea)
        return {"ea": ea, "name": name}

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 段 / 导入 / 导出 / 字符串
# ---------------------------------------------------------------------------
