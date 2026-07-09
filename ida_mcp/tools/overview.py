"""MCP 工具（overview 域）。

从单文件 server.py 拆分。共享项（mcp 实例、resolve_identifier、format_output、
错误翻译、辅助函数、常量）在 .._base。导入本模块即触发 @mcp.tool 注册。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def binary_overview() -> str:
    """Get a high-level overview of the loaded binary: entry point with decompiled
    preview, imports grouped by category, notable strings with references, and
    section layout. Call this first when starting analysis of a new binary."""
    try:
        entry = api.get_entry_point()
        imports = api.get_imports()
        strings = api.get_strings()
        segments = api.get_segments()

        try:
            preview, _, _ = _truncate_lines(api.decompile(entry["ea"]),
                                            ENTRY_PREVIEW_LINES)
        except IDAError:
            preview = None

        grouped = {}
        for imp in imports:
            grouped.setdefault(categorize_import(imp["name"]) or "OTHER",
                               []).append(imp["name"])

        candidates = []
        for s in strings:
            if s["length"] < STRING_MIN_LENGTH:
                continue
            try:
                refs = api.get_xrefs_to(s["ea"])
            except IDAError:
                refs = []
            referenced_by = None
            if refs:
                first = refs[0]["from_ea"]
                try:
                    referenced_by = api.get_name(first)["name"] or ea_to_hex(first)
                except IDAError:
                    referenced_by = ea_to_hex(first)
            candidates.append({"value": s["value"], "length": s["length"],
                               "ref_count": len(refs),
                               "referenced_by": referenced_by})
        candidates.sort(key=lambda c: c["ref_count"], reverse=True)
        strings_truncated = len(candidates) > STRINGS_LIMIT
        strings_of_interest = [
            {"value": c["value"], "referenced_by": c["referenced_by"],
             "length": c["length"]}
            for c in candidates[:STRINGS_LIMIT]
        ]

        sections = [
            {"name": seg["name"], "start": ea_to_hex(seg["start"]),
             "end": ea_to_hex(seg["end"]), "size": seg["size"],
             "permissions": seg["perm"]}
            for seg in segments
        ]

        return format_output({
            "entry_point": {"ea": ea_to_hex(entry["ea"]), "name": entry["name"],
                            "pseudocode_preview": preview},
            "imports": grouped,
            "strings_of_interest": strings_of_interest,
            "sections": sections,
            "strings_truncated": strings_truncated,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def binary_info() -> str:
    """Get low-level binary metadata: file name, file format, processor,
    bitness, endianness, image base, entry point, and address range. Complements
    binary_overview (which focuses on imports/strings/sections)."""
    try:
        info = api.get_binary_info()
        for k in ("image_base", "min_ea", "max_ea", "entry_ea"):
            if info.get(k) is not None:
                info[k] = ea_to_hex(info[k])
        return format_output(info)
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def check_connection() -> str:
    """Check whether IDA has a binary loaded and the MCP server is responsive.
    Use this first if other tools misbehave, to confirm the analysis session is
    ready."""
    try:
        entry = api.get_entry_point()
        return format_output({"connected": True,
                              "entry_point": {"ea": ea_to_hex(entry["ea"]),
                                              "name": entry["name"]}})
    except IDAError as e:
        return format_output({"connected": True,
                              "error": {"code": e.code, "message": translate_error(e)}})


# ---------------------------------------------------------------------------
# 类型系统工具（批次 A）
# ---------------------------------------------------------------------------
