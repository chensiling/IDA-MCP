"""IDA 原子操作（hexrays 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403
from .._contracts import classify_pseudocode_addresses


_CTREE_OP_NAMES = None


def _ctree_op_name(op):
    global _CTREE_OP_NAMES
    if op is None:
        return None
    if _CTREE_OP_NAMES is None:
        _CTREE_OP_NAMES = {}
        for name in dir(ida_hexrays):
            if not name.startswith(("cot_", "cit_")):
                continue
            try:
                value = getattr(ida_hexrays, name)
                if isinstance(value, int):
                    _CTREE_OP_NAMES.setdefault(value, name)
            except Exception:  # noqa: BLE001
                continue
    return _CTREE_OP_NAMES.get(op)


def _ctree_address_candidate(item, source):
    """Preserve ctree evidence needed to distinguish sites from targets."""
    try:
        wrapper_ea = item.get_ea()
    except Exception:  # noqa: BLE001
        wrapper_ea = None
    citype = getattr(item, "citype", None)
    node = None
    node_kind = None
    vdi_expr = getattr(ida_hexrays, "VDI_EXPR", None)
    if vdi_expr is not None and citype == vdi_expr:
        try:
            citem = item.it
            is_expression = bool(citem.is_expr())
            node_kind = "expression" if is_expression else "instruction"
            node = item.e if is_expression else item.i
        except Exception:  # noqa: BLE001
            node = None
            node_kind = None
    elif vdi_expr is None:
        # Compatibility fallback for small mocks and older bindings without the
        # cursor item type constant.
        for attribute, kind in (("e", "expression"),
                                ("i", "instruction")):
            try:
                candidate = getattr(item, attribute)
            except Exception:  # noqa: BLE001
                continue
            if candidate is not None:
                node = candidate
                node_kind = kind
                break
    op = getattr(node, "op", None) if node is not None else None

    object_ops = {getattr(ida_hexrays, "cot_obj", object())}
    call_op = getattr(ida_hexrays, "cot_call", object())
    parsed_ctree_node = (
        node is not None
        and node_kind in {"expression", "instruction"}
        and op is not None
    )
    node_ea = None
    if parsed_ctree_node:
        try:
            candidate_ea = node.ea
            if (not isinstance(candidate_ea, bool)
                    and candidate_ea is not None
                    and candidate_ea != idaapi.BADADDR):
                node_ea = candidate_ea
        except Exception:  # noqa: BLE001
            pass
    ea = node_ea if node_ea is not None else wrapper_ea
    if op in object_ops:
        role = "reference"
    elif parsed_ctree_node and (
            node_kind == "instruction" or op == call_op
            or source == "phead"):
        role = "statement"
    else:
        role = "unknown"

    return {
        "ea": ea,
        "role": role,
        "source": source,
        "citype": citype,
        "ctree_kind": node_kind,
        "ctree_op": _ctree_op_name(op),
        "ctree_op_value": op,
    }


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


def _collect_pseudocode_lines(func, cfunc, max_lines=None):
    """Collect plain pseudocode and best-effort address roles from one cfunc."""
    sv = cfunc.get_pseudocode()   # strvec_t，每项 .line 带颜色标签
    total = len(sv)
    out = []
    n = total if max_lines is None else min(total, max_lines)
    for i in range(n):
        line = sv[i].line
        plain = ida_lines.tag_remove(line)
        candidates = []
        try:
            for x in range(len(plain)):
                phead = ida_hexrays.ctree_item_t()
                pitem = ida_hexrays.ctree_item_t()
                ptail = ida_hexrays.ctree_item_t()
                if cfunc.get_line_item(line, x, True, phead, pitem, ptail):
                    for source, item in (
                            ("pitem", pitem), ("ptail", ptail),
                            ("phead", phead)):
                        candidate = _ctree_address_candidate(item, source)
                        if (candidate["ea"] is not None
                                and candidate["ea"] != idaapi.BADADDR):
                            candidates.append(candidate)
        except Exception:  # noqa: BLE001
            pass
        mapping = classify_pseudocode_addresses(
            candidates, func.start_ea, func.end_ea, idaapi.BADADDR)
        out.append({
            "line_no": i,
            "ea": mapping["statement_ea"],
            "statement_ea": mapping["statement_ea"],
            "referenced_targets": mapping["referenced_targets"],
            "mapping_reason": mapping["mapping_reason"],
            "text": plain,
        })
    return {
        "lines": out,
        "total_lines": total,
        "truncated": max_lines is not None and total > max_lines,
    }


def decompile_with_addresses(ea, max_lines=None):
    """反编译并返回逐行 best-effort 语句地址与引用目标。"""
    def do():
        func, cfunc = _decompile_cfunc(ea)
        return _collect_pseudocode_lines(func, cfunc, max_lines)

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 注释扩展（批次 C）：函数注释 + 前置/后置行注释
# ---------------------------------------------------------------------------
