"""IDA 原子操作（search 域）。

拆分自单文件 ida_api.py。共享基础设施（IDA 模块导入、IDAError、run_in_main、
SEARCH_HARD_LIMIT）在 core.py，此处 `from .core import *` 引入。函数体与拆分前
逐字节一致。
"""

from .core import *  # noqa: F401,F403


def search_text(pattern):
    def do():
        result = []
        ea = ida_search.find_text(
            idaapi.inf_get_min_ea(), 0, 0, pattern,
            ida_search.SEARCH_DOWN | ida_search.SEARCH_CASE)
        while ea != idaapi.BADADDR:
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
            result.append({"ea": ea, "line": line})
            if len(result) >= SEARCH_HARD_LIMIT:
                break
            nxt = ida_search.find_text(
                ea + 1, 0, 0, pattern,
                ida_search.SEARCH_DOWN | ida_search.SEARCH_CASE)
            if nxt <= ea:
                break
            ea = nxt
        return result

    return run_in_main(do)


def search_bytes(hex_pattern):
    def do():
        cleaned = hex_pattern.replace(" ", "")
        if len(cleaned) % 2 != 0:
            raise IDAError("INVALID_PARAM", "hex_pattern must have even length")
        try:
            bytes.fromhex(cleaned)
        except ValueError:
            raise IDAError("INVALID_PARAM", "hex_pattern is not valid hex")
        byte_str = " ".join(cleaned[i:i + 2] for i in range(0, len(cleaned), 2))
        result = []
        patterns = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(
            patterns, idaapi.inf_get_min_ea(), byte_str, 16)
        if err:
            return result
        ea = idaapi.inf_get_min_ea()
        end = idaapi.inf_get_max_ea()
        while ea < end:
            found = ida_bytes.bin_search(
                ea, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)
            found_ea = found[0] if isinstance(found, tuple) else found
            if found_ea == idaapi.BADADDR:
                break
            result.append({"ea": found_ea})
            if len(result) >= SEARCH_HARD_LIMIT:
                break
            ea = found_ea + 1
        return result

    return run_in_main(do)


def search_imm(value):
    def do():
        result = []
        ea = idaapi.inf_get_min_ea()
        end = idaapi.inf_get_max_ea()
        while ea < end and ea != idaapi.BADADDR:
            # find_imm 运行时返回 (ea, opnum) 元组；stub 误标为 int，故忽略类型检查
            found, _op = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)  # type: ignore
            if found == idaapi.BADADDR:
                break
            result.append({"ea": found,
                           "func_name": ida_funcs.get_func_name(found) or ""})
            if len(result) >= SEARCH_HARD_LIMIT:
                break
            ea = found + 1
        return result

    return run_in_main(do)


# ---------------------------------------------------------------------------
# 写操作
# ---------------------------------------------------------------------------
