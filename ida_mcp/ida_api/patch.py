"""IDA 原子操作（patch 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def undefine_item(ea):
    """把指定地址的指令/数据转为未定义字节。返回 {success}。"""
    def do():
        if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE):
            raise IDAError("UNDEFINE_FAILED", f"failed to undefine at {hex(ea)}")
        return {"success": True, "ea": ea}

    return run_in_main(do, write=True)


def make_code(ea):
    """把指定地址转换为代码（反汇编）。返回 {success, length}。"""
    def do():
        length = idc.create_insn(ea)
        if length == 0:
            raise IDAError("MAKE_CODE_FAILED",
                           f"failed to create instruction at {hex(ea)}")
        return {"success": True, "ea": ea, "length": length}

    return run_in_main(do, write=True)


_DATA_MAKERS = {
    "byte": (lambda ea: idc.create_byte(ea), 1),
    "word": (lambda ea: idc.create_word(ea), 2),
    "dword": (lambda ea: idc.create_dword(ea), 4),
    "qword": (lambda ea: idc.create_qword(ea), 8),
}


def make_data(ea, data_type="dword"):
    """把指定地址转换为数据。data_type: byte/word/dword/qword。返回 {success, type, size}。"""
    def do():
        dt = data_type.lower()
        if dt not in _DATA_MAKERS:
            raise IDAError("INVALID_PARAM",
                           f"data_type must be one of {sorted(_DATA_MAKERS)}")
        maker, size = _DATA_MAKERS[dt]
        if maker(ea) != 1:
            raise IDAError("MAKE_DATA_FAILED",
                           f"failed to create {dt} at {hex(ea)}")
        return {"success": True, "ea": ea, "type": dt, "size": size}

    return run_in_main(do, write=True)


def make_string(ea, str_type="c"):
    """把指定地址转换为字符串字面量。str_type: c(默认) / unicode。返回 {success, value}。"""
    def do():
        if not isinstance(str_type, str):
            raise IDAError("INVALID_PARAM", "str_type must be a string")
        kind = str_type.lower()
        string_types = {
            "c": ida_nalt.STRTYPE_C,
            "unicode": ida_nalt.STRTYPE_C_16,
            "utf16": ida_nalt.STRTYPE_C_16,
            "wide": ida_nalt.STRTYPE_C_16,
        }
        if kind not in string_types:
            raise IDAError(
                "INVALID_PARAM",
                "str_type must be one of: c, unicode, utf16, wide")
        strtype = string_types[kind]
        if not ida_bytes.create_strlit(ea, 0, strtype):
            raise IDAError("MAKE_STRING_FAILED",
                           f"failed to create string at {hex(ea)}")
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
        value = raw.decode("utf-8", errors="replace") if raw else ""
        return {"success": True, "ea": ea, "value": value}

    return run_in_main(do, write=True)
