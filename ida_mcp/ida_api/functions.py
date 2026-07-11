"""IDA 原子操作（functions 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403
from .._contracts import is_valid_ea


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


def get_disassembly(ea, count):
    """Read bounded disassembly, bytes, and static code references in one batch."""
    def do():
        func = ida_funcs.get_func(ea)
        if func:
            function_ea = func.start_ea
            function_end_ea = func.end_ea
            function_name = (ida_funcs.get_func_name(function_ea)
                             or ida_name.get_name(function_ea)
                             or hex(function_ea))
        else:
            function_ea = None
            function_end_ea = None
            function_name = None

        instructions = []
        cur = ea
        next_ea = None
        complete = False
        stop_reason = None
        for _ in range(count):
            if cur == idaapi.BADADDR:
                complete = function_end_ea is None
                stop_reason = (
                    "loaded_range_end" if complete else "traversal_stalled")
                break
            if function_end_ea is not None and cur >= function_end_ea:
                complete = True
                stop_reason = "function_end"
                break
            if not ida_bytes.is_loaded(cur):
                complete = function_end_ea is None
                stop_reason = (
                    "loaded_range_end" if complete else "traversal_stalled")
                break

            item_size = max(ida_bytes.get_item_size(cur), 1)
            if function_end_ea is not None:
                item_size = min(item_size, function_end_ea - cur)
            raw = ida_bytes.get_bytes(cur, item_size) or b""
            line = ida_lines.tag_remove(idc.generate_disasm_line(cur, 0) or "")

            flow_refs = []
            for xref in idautils.XrefsFrom(cur, ida_xref.XREF_FAR):
                is_code = getattr(xref, "iscode", False)
                if callable(is_code):
                    is_code = is_code()
                if not is_code:
                    continue
                direct_target_ea = xref.to
                target_func = ida_funcs.get_func(direct_target_ea)
                if target_func:
                    target_ea = target_func.start_ea
                    target_name = (
                        ida_funcs.get_func_name(target_ea)
                        or ida_name.get_name(target_ea)
                        or hex(target_ea))
                else:
                    target_ea = direct_target_ea
                    target_name = (ida_name.get_name(target_ea)
                                   or hex(target_ea))
                flow_refs.append({
                    "direct_target_ea": direct_target_ea,
                    "target_ea": target_ea,
                    "target_name": target_name,
                    "type": (idautils.XrefTypeName(xref.type)
                             or str(xref.type)),
                })

            instructions.append({
                "ea": cur,
                "bytes": raw.hex(),
                "disasm": line,
                "flow_refs": flow_refs,
            })

            nxt = idc.next_head(cur)
            if nxt == idaapi.BADADDR or nxt <= cur:
                complete = function_end_ea is None
                stop_reason = (
                    "loaded_range_end" if complete else "traversal_stalled")
                cur = None
                break
            cur = nxt
            if function_end_ea is not None and cur >= function_end_ea:
                complete = True
                stop_reason = "function_end"
                cur = None
                break
        else:
            if cur is not None and ida_bytes.is_loaded(cur):
                next_ea = cur
                stop_reason = "count_limit"
            elif function_end_ea is not None:
                stop_reason = "traversal_stalled"
            else:
                complete = True
                stop_reason = "loaded_range_end"

        return {
            "function_ea": function_ea,
            "function_name": function_name,
            "function_end_ea": function_end_ea,
            "instructions": instructions,
            "next_ea": next_ea,
            "complete": complete,
            "stop_reason": stop_reason,
        }

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
        ea = ida_ida.inf_get_start_ea()
        if not is_valid_ea(ea, idaapi.BADADDR):
            raise IDAError("NO_ENTRY", "no entry point in database")
        name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea)
        return {"ea": ea, "name": name}

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 段 / 导入 / 导出 / 字符串
# ---------------------------------------------------------------------------
