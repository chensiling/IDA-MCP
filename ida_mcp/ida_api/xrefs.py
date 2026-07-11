"""IDA 原子操作（xrefs 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def get_xrefs_to(ea):
    def do():
        refs = []
        function_cache = {}
        for xref in idautils.XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            if func is None:
                from_func_ea = None
                from_func_name = None
            else:
                from_func_ea = func.start_ea
                if from_func_ea not in function_cache:
                    function_cache[from_func_ea] = (
                        ida_funcs.get_func_name(from_func_ea) or "")
                from_func_name = function_cache[from_func_ea]
            refs.append({"from_ea": xref.frm,
                         "type": idautils.XrefTypeName(xref.type),
                         "from_func_ea": from_func_ea,
                         "from_func_name": from_func_name})
        return refs

    return run_in_main(do)


def get_xrefs_from(ea):
    def do():
        refs = []
        for xref in idautils.XrefsFrom(ea):
            refs.append({"to_ea": xref.to,
                         "type": idautils.XrefTypeName(xref.type)})
        return refs

    return run_in_main(do)


def get_func_callees(ea):
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        seen = {}
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item_ea, ida_xref.XREF_FAR):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    target = xref.to
                    callee = ida_funcs.get_func(target)
                    if callee:
                        key = callee.start_ea
                        name = ida_funcs.get_func_name(key)
                    else:
                        key = target
                        name = ida_name.get_name(target) or hex(target)
                    if key not in seen:
                        seen[key] = {"to_ea": key, "to_func_name": name}
        return list(seen.values())

    return run_in_main(do)


def get_func_callers(ea):
    def do():
        func = ida_funcs.get_func(ea)
        start = func.start_ea if func else ea
        result = []
        for xref in idautils.XrefsTo(start):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            from_func = ida_funcs.get_func(xref.frm)
            if from_func:
                from_func_ea = from_func.start_ea
                from_func_name = ida_funcs.get_func_name(from_func_ea)
            else:
                from_func_ea = idaapi.BADADDR
                from_func_name = ida_name.get_name(xref.frm) or ""
            result.append({"from_ea": xref.frm,
                           "from_func_ea": from_func_ea,
                           "from_func_name": from_func_name,
                           "type": idautils.XrefTypeName(xref.type)})
        return result

    return run_in_main(do)


def get_func_callsites(ea):
    """Return every static callsite in a function without deduplication."""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        result = []
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.XrefsFrom(item_ea, ida_xref.XREF_FAR):
                if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                    continue
                target = xref.to
                callee = ida_funcs.get_func(target)
                if callee:
                    to_ea = callee.start_ea
                    target_name = (ida_funcs.get_func_name(to_ea)
                                   or ida_name.get_name(to_ea)
                                   or hex(to_ea))
                else:
                    to_ea = target
                    target_name = ida_name.get_name(to_ea) or hex(to_ea)
                result.append({
                    "from_ea": item_ea,
                    "to_ea": to_ea,
                    "direct_target_ea": target,
                    "to_func_name": target_name,
                    "type": idautils.XrefTypeName(xref.type),
                })
        return result

    return run_in_main(do)


def get_func_string_refs(ea):
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        result = []
        for item_ea in idautils.FuncItems(func.start_ea):
            for ref in idautils.DataRefsFrom(item_ea):
                flags = ida_bytes.get_flags(ref)
                if ida_bytes.is_strlit(flags):
                    strtype = ida_nalt.get_str_type(ref)
                    s = ida_bytes.get_strlit_contents(ref, -1, strtype)
                    if s is not None:
                        result.append({
                            "ref_ea": item_ea,
                            "string_ea": ref,
                            "value": s.decode("utf-8", errors="replace"),
                        })
        return result

    return run_in_main(do)


def get_basic_blocks(ea):
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        flow = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
        blocks = []
        for block in flow:
            blocks.append({
                "start": block.start_ea,
                "end": block.end_ea,
                "succs": [s.start_ea for s in block.succs()],
                "preds": [p.start_ea for p in block.preds()],
            })
        return blocks

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 名称 / 字节
# ---------------------------------------------------------------------------
