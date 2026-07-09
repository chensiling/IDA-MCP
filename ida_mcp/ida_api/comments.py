"""IDA 原子操作（comments 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def get_func_comment(ea, repeatable=False):
    """读函数注释。返回 {ea, comment}。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        cmt = ida_funcs.get_func_cmt(func, repeatable)
        return {"ea": func.start_ea, "comment": cmt or ""}

    return run_in_main(do)


def set_func_comment(ea, comment, repeatable=False):
    """设置函数注释（空串删除）。返回 {success}。"""
    def do():
        func = ida_funcs.get_func(ea)
        if not func:
            raise IDAError("NO_FUNCTION", f"no function at {hex(ea)}")
        if not ida_funcs.set_func_cmt(func, comment, repeatable):
            raise IDAError("COMMENT_FAILED",
                           f"failed to set func comment at {hex(ea)}")
        return {"success": True}

    return run_in_main(do, write=True)


def get_extra_comment(ea, anterior=True):
    """读前置(anterior)/后置(posterior)行注释，合并多行。返回 {ea, comment}。"""
    def do():
        base = ida_lines.E_PREV if anterior else ida_lines.E_NEXT
        lines = []
        idx = 0
        while True:
            s = idc.get_extra_cmt(ea, base + idx)
            if s is None:
                break
            lines.append(s)
            idx += 1
        return {"ea": ea, "comment": "\n".join(lines)}

    return run_in_main(do)


def set_extra_comment(ea, comment, anterior=True):
    """设置前置/后置行注释（多行按 \\n 拆分；空串清除）。返回 {success, lines}。"""
    def do():
        base = ida_lines.E_PREV if anterior else ida_lines.E_NEXT
        # 先清除已有的连续 extra 行
        i = 0
        while idc.get_extra_cmt(ea, base + i) is not None:
            ida_lines.del_extra_cmt(ea, base + i)
            i += 1
        if comment == "":
            return {"success": True, "lines": 0}
        parts = comment.split("\n")
        for n, line in enumerate(parts):
            idc.update_extra_cmt(ea, base + n, line)
        return {"success": True, "lines": len(parts)}

    return run_in_main(do, write=True)


# ---------------------------------------------------------------------------
# 元信息 / 反汇增强（批次 D）
# ---------------------------------------------------------------------------
