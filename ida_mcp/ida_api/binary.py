"""IDA 原子操作（binary 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def get_segments():
    def do():
        result = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            perm = seg.perm
            perm_str = "{}{}{}".format(
                "r" if perm & ida_segment.SEGPERM_READ else "-",
                "w" if perm & ida_segment.SEGPERM_WRITE else "-",
                "x" if perm & ida_segment.SEGPERM_EXEC else "-",
            )
            result.append({
                "name": ida_segment.get_segm_name(seg),
                "start": seg.start_ea,
                "end": seg.end_ea,
                "size": seg.end_ea - seg.start_ea,
                "perm": perm_str,
            })
        return result

    return run_in_main(do)


def get_imports():
    def do():
        result = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i) or ""

            def cb(ea, name, ordinal, _module=module):
                if name:
                    result.append({"name": name, "ea": ea, "module": _module})
                return True

            ida_nalt.enum_import_names(i, cb)
        return result

    return run_in_main(do)


def get_exports():
    def do():
        result = []
        for index, ordinal, ea, name in idautils.Entries():
            result.append({"name": name, "ea": ea, "ordinal": ordinal})
        return result

    return run_in_main(do)


def get_strings():
    def do():
        result = []
        for s in idautils.Strings():
            try:
                value = str(s)
            except Exception:  # noqa: BLE001
                continue
            result.append({"value": value, "ea": s.ea,
                           "length": s.length, "type": s.strtype})
        return result

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 交叉引用 / 调用关系
# ---------------------------------------------------------------------------
