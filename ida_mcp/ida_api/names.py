"""IDA 原子操作（names 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def get_ea_by_name(name):
    """Resolve an exact IDB name without normalizing it to a function start."""
    def do():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            raise IDAError("NAME_NOT_FOUND", f"name not found: {name}")
        return {"ea": ea, "name": ida_name.get_name(ea) or str(name)}

    return run_in_main(do)


def get_name(ea):
    def do():
        return {"name": ida_name.get_name(ea) or ""}

    return run_in_main(do)


def get_bytes(ea, size):
    def do():
        raw = ida_bytes.get_bytes(ea, size)
        if raw is None:
            raise IDAError("READ_FAILED", f"cannot read {size} bytes at {hex(ea)}")
        return {"hex_bytes": raw.hex()}

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 搜索
# ---------------------------------------------------------------------------
def rename(ea, new_name):
    def do():
        old_name = ida_name.get_name(ea) or ""
        ok = ida_name.set_name(ea, new_name,
                               ida_name.SN_NOWARN | ida_name.SN_CHECK)
        if not ok:
            existing = ida_name.get_name_ea(idaapi.BADADDR, new_name)
            if existing != idaapi.BADADDR:
                raise IDAError(
                    "NAME_CONFLICT",
                    f"name '{new_name}' already used at {hex(existing)}")
            raise IDAError("RENAME_FAILED",
                           f"failed to rename {hex(ea)} to '{new_name}'")
        return {"success": True, "old_name": old_name, "new_name": new_name}

    return run_in_main(do, write=True)


def patch_bytes(ea, hex_bytes):
    def do():
        cleaned = hex_bytes.replace(" ", "")
        if len(cleaned) % 2 != 0:
            raise IDAError("INVALID_PARAM", "hex_bytes must have even length")
        try:
            new_raw = bytes.fromhex(cleaned)
        except ValueError:
            raise IDAError("INVALID_PARAM", "hex_bytes is not valid hex")
        length = len(new_raw)
        old_raw = ida_bytes.get_bytes(ea, length)
        if old_raw is None:
            raise IDAError("PATCH_FAILED",
                           f"cannot read original bytes at {hex(ea)}")
        ida_bytes.patch_bytes(ea, new_raw)
        if ida_bytes.get_bytes(ea, length) != new_raw:
            raise IDAError("PATCH_FAILED",
                           f"patch verification failed at {hex(ea)}")
        return {"success": True, "old_bytes": old_raw.hex(),
                "new_bytes": new_raw.hex(), "length": length}

    return run_in_main(do, write=True)


def get_comment(ea, repeatable=False):
    def do():
        return {"comment": ida_bytes.get_cmt(ea, repeatable) or ""}

    return run_in_main(do)


def set_comment(ea, comment, repeatable=False):
    def do():
        if not ida_bytes.set_cmt(ea, comment, repeatable):
            raise IDAError("COMMENT_FAILED", f"failed to set comment at {hex(ea)}")
        return {"success": True}

    return run_in_main(do, write=True)


# ---------------------------------------------------------------------------
# 类型系统（批次 A）
# ---------------------------------------------------------------------------
