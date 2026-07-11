"""IDA 原子操作（types 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403
from .._contracts import bitfield_byte_envelope, read_bitfield_marker


def _classify_tif_kind(tif):
    """Return the exact kind, propagating predicate failures to the caller."""
    if tif.is_udt():
        return "union" if tif.is_union() else "struct"
    if tif.is_enum():
        return "enum"
    if tif.is_typeref():
        return "typedef"
    return "other"


def _strict_tif_kind(tif, name):
    try:
        return _classify_tif_kind(tif)
    except Exception as e:  # noqa: BLE001
        raise IDAError(
            "TYPE_READ_FAILED",
            f"failed to classify type '{name}': {e}") from e


def _best_effort_tif_kind(tif):
    try:
        return _classify_tif_kind(tif), "exact"
    except Exception:  # noqa: BLE001
        return "unknown", "unavailable"


def list_local_types(name_filter=None):
    """列出 IDB 本地类型（Local Types），返回 [{ordinal, name, kind}]。
    name_filter 非空时只返回名称包含该子串（不区分大小写）的类型。"""
    def do():
        result = []
        nf = name_filter.casefold() if name_filter else None
        limit = idc.get_ordinal_limit()   # 本地类型数 + 1
        if not limit or limit <= 1:
            return result
        for ordinal in range(1, limit):
            name = idc.get_numbered_type_name(ordinal)
            if not name:
                continue
            if nf and nf not in name.casefold():
                continue
            kind = "unknown"
            kind_status = "unavailable"
            try:
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(ida_typeinf.get_idati(), ordinal):
                    kind, kind_status = _best_effort_tif_kind(tif)
            except Exception:  # noqa: BLE001
                pass
            result.append({
                "ordinal": ordinal,
                "name": name,
                "kind": kind,
                "kind_status": kind_status,
            })
        return result

    return run_in_main(do)


def get_type(name):
    """按名称取完整类型详情和声明顺序成员。"""
    def do():
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), name):
            raise IDAError("TYPE_NOT_FOUND", f"type not found: {name}")
        kind = _strict_tif_kind(tif, name)
        # 完整定义：PRTYPE_MULTI 多行 + PRTYPE_TYPE 类型声明 + PRTYPE_DEF 展开定义体
        try:
            definition = tif._print(
                None,
                ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_DEF,
            )
        except Exception:  # noqa: BLE001
            definition = str(tif)
            definition_source = "string_fallback"
        else:
            if definition:
                definition_source = "ida_print"
            else:
                definition = str(tif)
                definition_source = "string_fallback"
        size = tif.get_size()
        info = {
            "name": name,
            "kind": kind,
            "definition": definition,
            "definition_source": definition_source,
            "size": size if size != idaapi.BADSIZE else None,
        }
        members = []
        if kind in ("struct", "union"):
            try:
                for member_index, udm in enumerate(tif.iter_udt()):
                    bit_offset = udm.offset
                    bit_width = udm.size
                    offset, size = bitfield_byte_envelope(
                        bit_offset, bit_width)
                    members.append({
                        "member_index": member_index,
                        "name": udm.name,
                        "offset": offset,
                        "size": size,
                        "bit_offset": bit_offset,
                        "bit_width": bit_width,
                        "is_bitfield": read_bitfield_marker(udm),
                        "type": str(udm.type),
                    })
            except Exception as e:  # noqa: BLE001
                raise IDAError(
                    "TYPE_READ_FAILED",
                    f"failed to read members for type '{name}': {e}") from e
        elif kind == "enum":
            try:
                for member_index, edm in enumerate(tif.iter_enum()):
                    members.append({
                        "member_index": member_index,
                        "name": edm.name,
                        "value": edm.value,
                    })
            except Exception as e:  # noqa: BLE001
                raise IDAError(
                    "TYPE_READ_FAILED",
                    f"failed to read members for type '{name}': {e}") from e
        info["members"] = members
        return info

    return run_in_main(do)


def create_type(c_declaration):
    """用 C 声明创建/更新一个或多个 local type。返回 {success}。"""
    def do():
        # parse_decls 把声明解析并存入 til，返回错误数（0 = 成功）。
        # 注意：返回值是错误数而非类型数，0 才代表全部成功。
        errors = ida_typeinf.parse_decls(
            ida_typeinf.get_idati(), c_declaration, None, ida_typeinf.HTI_DCL)
        if errors != 0:
            raise IDAError("TYPE_PARSE_FAILED",
                           f"{errors} error(s) parsing type declaration")
        return {"success": True}

    return run_in_main(do, write=True)


def delete_type(name):
    """从 Local Types 删除一个命名类型。返回 {success}。"""
    def do():
        til = ida_typeinf.get_idati()
        # 先确认存在，给出明确错误
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            raise IDAError("TYPE_NOT_FOUND", f"type not found: {name}")
        if not ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE):
            raise IDAError("DELETE_TYPE_FAILED", f"failed to delete type: {name}")
        return {"success": True}

    return run_in_main(do, write=True)


def get_func_prototype(ea):
    """取函数原型字符串。返回 {ea, name, prototype}。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        proto = idc.get_type(func.start_ea)
        if not proto:
            proto = idc.guess_type(func.start_ea)   # 未显式设类型时猜测
        if not proto:
            raise IDAError("NO_TYPE", f"no type info for function at {hex(ea)}")
        return {
            "ea": func.start_ea,
            "name": ida_funcs.get_func_name(func.start_ea),
            "prototype": proto,
        }

    return run_in_main(do)


def set_func_prototype(ea, prototype):
    """设置函数原型（C 声明，如 'int __fastcall f(int a, char *b);'）。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        decl = prototype if prototype.strip().endswith(";") else prototype + ";"
        if idc.SetType(func.start_ea, decl) != 1:
            raise IDAError("SET_TYPE_FAILED",
                           f"failed to set prototype at {hex(ea)}")
        return {"success": True,
                "prototype": idc.get_type(func.start_ea) or prototype}

    return run_in_main(do, write=True)


def apply_type(ea, c_type):
    """把 C 类型应用到地址（数据或函数）。c_type 如 'MY_STRUCT' 或 'int[4]'。"""
    def do():
        decl = c_type if c_type.strip().endswith(";") else c_type + ";"
        if idc.SetType(ea, decl) != 1:
            raise IDAError("SET_TYPE_FAILED",
                           f"failed to apply type at {hex(ea)}")
        return {"success": True, "ea": ea, "type": idc.get_type(ea) or c_type}

    return run_in_main(do, write=True)


def get_data_type(ea):
    """取某地址的当前类型声明。返回 {ea, type}。"""
    def do():
        return {"ea": ea, "type": idc.get_type(ea) or ""}

    return run_in_main(do)


# ---------------------------------------------------------------------------
# Hex-Rays 深化（批次 B）：局部变量 + 伪代码行地址映射
# ---------------------------------------------------------------------------
