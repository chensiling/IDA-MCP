"""MCP 工具（overview 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool(annotations=READ_ONLY_TOOL)
def binary_overview(f: str = None) -> str:
    """Get a high-level overview of the loaded binary: entry point with decompiled
    preview, imports grouped by category, notable strings with references, and
    section layout. Call this first when starting analysis of a new binary."""
    r = _route_if_remote(f, "binary_overview")
    if r: return r
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


@mcp.tool(annotations=READ_ONLY_TOOL)
def binary_info(f: str = None) -> str:
    """Get low-level binary metadata: file name, file format, processor,
    bitness, endianness, image base, entry point, and address range. Complements
    binary_overview (which focuses on imports/strings/sections)."""
    r = _route_if_remote(f, "binary_info")
    if r: return r
    try:
        info = api.get_binary_info()
        for k in ("image_base", "min_ea", "max_ea", "entry_ea"):
            if info.get(k) is not None:
                info[k] = ea_to_hex(info[k])
        return format_output(info)
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def check_connection(f: str = None) -> str:
    """Check whether IDA has a binary loaded and the MCP server is responsive.
    Use this first if other tools misbehave, to confirm the analysis session is
    ready."""
    r = _route_if_remote(f, "check_connection")
    if r: return r
    try:
        entry = api.get_entry_point()
        return format_output({"connected": True,
                              "entry_point": {"ea": ea_to_hex(entry["ea"]),
                                              "name": entry["name"]}})
    except IDAError as e:
        return format_output({"connected": True,
                              "error": tool_error_payload(e)["error"]})


@mcp.tool(annotations=READ_ONLY_TOOL)
def analysis_status(f: str = None) -> str:
    """Get a non-blocking snapshot of IDA auto-analysis, Hex-Rays availability,
    and the IDA kernel version. Use it to distinguish transport connectivity from
    analysis readiness; this tool never waits for auto-analysis to finish."""
    r = _route_if_remote(f, "analysis_status")
    if r: return r
    try:
        return format_output(api.get_analysis_status())
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
def list_files() -> str:
    """List all connected IDA instances (files) in this multi-instance session.
    Returns target identity, read-only state, capabilities, and protocol/tool
    versions. Use the returned 'fid' as another tool's 'f' value and check write
    and Hex-Rays availability before choosing an operation."""
    router = _get_router()
    if router is None:
        return format_output({
            "files": [],
            "note": "Multi-instance support is not active. "
                    "This is the only IDA instance."
        })
    try:
        files = router._list_files()
        return format_output({
            "count": len(files),
            "files": files,
        })
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "binary_overview": binary_overview,
    "binary_info": binary_info,
    "check_connection": check_connection,
    "analysis_status": analysis_status,
    "list_files": list_files,
})
