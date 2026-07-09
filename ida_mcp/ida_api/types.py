"""IDA 原子操作（types 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def _tif_kind(tif):
    """判断 tinfo_t 的种类，返回 'struct'/'union'/'enum'/'typedef'/'other'。"""
    try:
        if tif.is_udt():
            return "union" if tif.is_union() else "struct"
        if tif.is_enum():
            return "enum"
        if tif.is_typeref():
            return "typedef"
    except Exception:  # noqa: BLE001
        pass
    return "other"


def list_local_types(name_filter=None):
    """列出 IDB 本地类型（Local Types），返回 [{ordinal, name, kind}]。
    name_filter 非空时只返回名称包含该子串（不区分大小写）的类型。"""
    def do():
        result = []
        nf = name_filter.lower() if name_filter else None
        limit = idc.get_ordinal_limit()   # 本地类型数 + 1
        if not limit or limit <= 1:
            return result
        for ordinal in range(1, limit):
            name = idc.get_numbered_type_name(ordinal)
            if not name:
                continue
            if nf and nf not in name.lower():
                continue
            tif = ida_typeinf.tinfo_t()
            kind = "other"
            if tif.get_numbered_type(ida_typeinf.get_idati(), ordinal):
                kind = _tif_kind(tif)
            result.append({"ordinal": ordinal, "name": name, "kind": kind})
        return result

    return run_in_main(do)


def get_type(name):
    """按名称取类型详情。返回 {name, kind, definition, members?}。"""
    def do():
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), name):
            raise IDAError("TYPE_NOT_FOUND", f"type not found: {name}")
        kind = _tif_kind(tif)
        # 完整定义：PRTYPE_MULTI 多行 + PRTYPE_TYPE 类型声明 + PRTYPE_DEF 展开定义体
        try:
            definition = tif._print(
                None,
                ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_DEF,
            ) or str(tif)
        except Exception:  # noqa: BLE001
            definition = str(tif)
        info = {
            "name": name,
            "kind": kind,
            "definition": definition,
            "size": tif.get_size() if tif.get_size() != idaapi.BADSIZE else None,
        }
        if kind in ("struct", "union"):
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
            info["members"] = members
        elif kind == "enum":
            members = []
            try:
                for edm in tif.iter_enum():
                    members.append({"name": edm.name, "value": edm.value})
            except Exception:  # noqa: BLE001
                pass
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
