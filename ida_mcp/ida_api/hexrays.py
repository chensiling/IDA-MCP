"""IDA 原子操作（hexrays 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def _decompile_cfunc(ea):
    """内部：反编译并返回 cfunc，失败抛 IDAError。调用方须在主线程内。"""
    func = ida_funcs.get_func(ea)
    if not func:
        raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
    ensure_hexrays()
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise IDAError("DECOMPILE_FAILED", str(e))
    if cfunc is None:
        raise IDAError("DECOMPILE_FAILED", f"decompilation returned None at {hex(ea)}")
    return func, cfunc


def get_func_lvars(ea):
    """列出函数的局部变量与参数。返回 [{name, type, size, is_arg, used}]。"""
    def _val(obj):
        # 兼容不同 IDA 版本：属性可能是 bool 也可能是方法
        return obj() if callable(obj) else obj

    def do():
        _func, cfunc = _decompile_cfunc(ea)
        result = []
        for lv in cfunc.get_lvars():
            result.append({
                "name": lv.name,
                "type": str(lv.tif),
                "size": lv.width,
                "is_arg": bool(_val(lv.is_arg_var)),
                "used": bool(_val(lv.used)),
            })
        return result

    return run_in_main(do)


def rename_lvar(ea, old_name, new_name):
    """重命名函数内局部变量。返回 {success, old_name, new_name}。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        ensure_hexrays()
        if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
            raise IDAError("RENAME_LVAR_FAILED",
                           f"failed to rename lvar '{old_name}' "
                           f"(not found or name conflict)")
        return {"success": True, "old_name": old_name, "new_name": new_name}

    return run_in_main(do, write=True)


def set_lvar_type(ea, var_name, new_type):
    """设置函数内局部变量的类型。new_type 为 C 类型字符串（如 'int *'）。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        ensure_hexrays()
        # 解析目标类型字符串为 tinfo_t
        tif = ida_typeinf.tinfo_t()
        decl = new_type if new_type.strip().endswith(";") else new_type + ";"
        if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), decl,
                                  ida_typeinf.PT_SIL) is None:
            raise IDAError("INVALID_PARAM", f"cannot parse type: {new_type}")
        locator = ida_hexrays.lvar_locator_t()
        if not ida_hexrays.locate_lvar(locator, func.start_ea, var_name):
            raise IDAError("SET_LVAR_TYPE_FAILED",
                           f"local variable not found: '{var_name}'")
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = locator
        info.type = tif
        if not ida_hexrays.modify_user_lvar_info(
                func.start_ea, ida_hexrays.MLI_TYPE, info):
            raise IDAError("SET_LVAR_TYPE_FAILED",
                           f"failed to set type of lvar '{var_name}'")
        return {"success": True, "name": var_name, "type": new_type}

    return run_in_main(do, write=True)


def decompile_with_addresses(ea, max_lines):
    """反编译并给每行标注对应地址。返回 {lines:[{line_no, ea, text}], total_lines, truncated}。"""
    def do():
        _func, cfunc = _decompile_cfunc(ea)
        sv = cfunc.get_pseudocode()   # strvec_t，每项 .line 带颜色标签
        total = len(sv)
        out = []
        n = min(total, max_lines)
        for i in range(n):
            line = sv[i].line
            plain = ida_lines.tag_remove(line)
            # 扫描该行多个 x 坐标，取第一个有效地址（x=0 常落在缩进空白处取不到）
            line_ea = idaapi.BADADDR
            try:
                for x in range(len(plain)):
                    phead = ida_hexrays.ctree_item_t()
                    pitem = ida_hexrays.ctree_item_t()
                    ptail = ida_hexrays.ctree_item_t()
                    if cfunc.get_line_item(line, x, True, phead, pitem, ptail):
                        for it in (pitem, ptail, phead):
                            it_ea = it.get_ea()
                            if it_ea is not None and it_ea != idaapi.BADADDR:
                                line_ea = it_ea
                                break
                    if line_ea != idaapi.BADADDR:
                        break
            except Exception:  # noqa: BLE001
                pass
            out.append({
                "line_no": i,
                "ea": None if line_ea == idaapi.BADADDR else line_ea,
                "text": plain,
            })
        return {"lines": out, "total_lines": total, "truncated": total > max_lines}

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 注释扩展（批次 C）：函数注释 + 前置/后置行注释
# ---------------------------------------------------------------------------
