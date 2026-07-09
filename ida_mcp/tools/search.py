"""MCP 工具（search 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def search(query: str, type: str = "all", limit: int = DEFAULT_SEARCH_LIMIT,
           f: str = None) -> str:
    """Search the IDA database for functions, strings, imports, or immediate
    values. Returns results with context (containing function, nearby code) so
    you can assess relevance without extra calls. Categories (crypto, network,
    etc.) are deterministic labels based on known API name tables, not heuristic
    guesses. type is one of: string, function, import, immediate, all."""
    r = _route_if_remote(f, "search", query=query, type=type, limit=limit)
    if r: return r
    try:
        valid_types = {"string", "function", "import", "immediate", "all"}
        if type not in valid_types:
            return format_output({"error": {
                "code": "INVALID_PARAM",
                "message": f"type must be one of {sorted(valid_types)}"}})

        q_lower = query.lower()

        def match_rank(name):
            nl = name.lower()
            if nl == q_lower:
                return True, 0
            if nl.startswith(q_lower):
                return True, 1
            if q_lower in nl:
                return True, 2
            return False, 3

        results = []
        if type in ("string", "all"):
            for s in api.get_strings():
                ok, rank = match_rank(s["value"])
                if ok:
                    results.append({"_rank": rank, "type": "string",
                                    "value": s["value"], "ea": s["ea"]})
        if type in ("function", "all"):
            for f in api.get_func_list():
                ok, rank = match_rank(f["name"])
                if ok:
                    results.append({"_rank": rank, "type": "function",
                                    "value": f["name"], "ea": f["ea"]})
        if type in ("import", "all"):
            for imp in api.get_imports():
                ok, rank = match_rank(imp["name"])
                if ok:
                    results.append({"_rank": rank, "type": "import",
                                    "value": imp["name"], "ea": imp["ea"]})

        note = None
        if type in ("immediate", "all"):
            parsed = _try_parse_int(query)
            if parsed is None:
                if type == "immediate":
                    note = ("query is not a numeric value; immediate search "
                            "requires a number")
            else:
                for hit in api.search_imm(parsed):
                    results.append({"_rank": 0, "type": "immediate",
                                    "value": parsed, "ea": hit["ea"]})

        by_ea = {}
        for r in results:
            key = r["ea"]
            if key not in by_ea or r["_rank"] < by_ea[key]["_rank"]:
                by_ea[key] = r
        deduped = sorted(by_ea.values(), key=lambda r: (r["_rank"], r["ea"]))

        total = len(deduped)
        truncated = total > limit
        top = deduped[:limit]

        categories = set()
        out_results = []
        for r in top:
            ea = r["ea"]
            entry = {"type": r["type"],
                     "value": r["value"] if r["type"] != "immediate" else hex(r["value"]),
                     "ea": ea_to_hex(ea)}
            cat = categorize_import(r["value"]) if isinstance(r["value"], str) else None
            entry["category"] = cat.lower() if cat else None
            if cat:
                categories.add(cat.lower())
            if r["type"] == "function":
                entry["containing_function"] = r["value"]
            else:
                cf = _containing_function(ea)
                entry["containing_function"] = cf["name"] if cf else None
            if r["type"] in ("string", "import"):
                try:
                    refs = api.get_xrefs_to(ea)
                except IDAError:
                    refs = []
                ref_names = []
                seen_refs = set()
                for ref in refs:
                    cf = _containing_function(ref["from_ea"])
                    nm = cf["name"] if cf else ea_to_hex(ref["from_ea"])
                    if nm in seen_refs:
                        continue
                    seen_refs.add(nm)
                    ref_names.append(nm)
                    if len(ref_names) >= 3:
                        break
                entry["referenced_by"] = ref_names
            out_results.append(entry)

        summary = {"total": total, "categories": sorted(categories),
                   "truncated": truncated}
        if note:
            summary["note"] = note
        return format_output({"query": query, "type": type,
                              "summary": summary, "results": out_results})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def trace_data(identifier: str, f: str = None) -> str:
    """Trace all cross-references to a given address or symbol. Returns each
    reference with its containing function and a code context snippet, so you can
    understand HOW and WHERE the target is used without separate calls."""
    r = _route_if_remote(f, "trace_data", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        xrefs = api.get_xrefs_to(ea)

        grouped = {}
        order = []
        for xref in xrefs:
            from_ea = xref["from_ea"]
            cf = _containing_function(from_ea)
            func_ea = cf["ea"] if cf else None
            key = func_ea if func_ea is not None else ea_to_hex(from_ea)
            if key not in grouped:
                grouped[key] = {"function": cf["name"] if cf else None, "sites": []}
                order.append(key)
            grouped[key]["sites"].append(from_ea)

        total_sites = len(xrefs)
        truncated = len(order) > DEFAULT_XREF_LIMIT
        order = order[:DEFAULT_XREF_LIMIT]

        refs = []
        for key in order:
            g = grouped[key]
            first_site = g["sites"][0]
            try:
                disasm = api.get_disasm(first_site, 1)
                instruction = disasm[0]["disasm"] if disasm else ""
            except IDAError:
                instruction = ""
            context = ""
            if g["function"] is not None:
                func_start = resolve_identifier(g["function"])
                try:
                    ctx, _, _ = _truncate_lines(api.decompile(func_start),
                                                CONTEXT_PREVIEW_LINES)
                    context = ctx
                except IDAError:
                    try:
                        d = api.get_disasm(func_start, 10)
                        context = "\n".join(
                            f"{ea_to_hex(x['ea'])}  {x['disasm']}" for x in d)
                    except IDAError:
                        context = ""
            refs.append({"ea": ea_to_hex(first_site), "function": g["function"],
                         "instruction": instruction, "context": context,
                         "site_count": len(g["sites"])})

        return format_output({"address": ea_to_hex(ea), "total_sites": total_sites,
                              "refs": refs, "truncated": truncated})
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def cross_references(identifier: str, f: str = None) -> str:
    """Get incoming and outgoing cross-references for a function or address.
    Lighter than trace_data — returns reference lists without code context
    snippets. Use when you need the reference graph structure, not the code at
    each site."""
    r = _route_if_remote(f, "cross_references", identifier=identifier)
    if r: return r
    try:
        ea = resolve_identifier(identifier)
        try:
            name = api.get_name(ea)["name"]
        except IDAError:
            name = ""

        from_list = []
        for xref in api.get_xrefs_to(ea)[:DEFAULT_XREF_LIGHT_LIMIT]:
            from_ea = xref["from_ea"]
            cf = _containing_function(from_ea)
            try:
                d = api.get_disasm(from_ea, 1)
                instruction = d[0]["disasm"] if d else ""
            except IDAError:
                instruction = ""
            from_list.append({"function": cf["name"] if cf else None,
                              "ea": ea_to_hex(from_ea), "instruction": instruction})

        to_list = []
        for xref in api.get_xrefs_from(ea)[:DEFAULT_XREF_LIGHT_LIMIT]:
            to_ea = xref["to_ea"]
            try:
                nm = api.get_name(to_ea)["name"]
            except IDAError:
                nm = ""
            try:
                d = api.get_disasm(ea, 1)
                instruction = d[0]["disasm"] if d else ""
            except IDAError:
                instruction = ""
            to_list.append({"function": nm, "ea": ea_to_hex(to_ea),
                            "instruction": instruction})

        return format_output({"target": {"name": name, "ea": ea_to_hex(ea)},
                              "from": from_list, "to": to_list})
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "search": search,
    "trace_data": trace_data,
    "cross_references": cross_references,
})
