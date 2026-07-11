"""MCP 工具（search 域）。
"""

from collections import OrderedDict
import hashlib
import json
import re
import secrets
import threading
from typing import Optional

from .._base import *  # noqa: F401,F403
from .._contracts import (CursorError, decode_search_cursor,
                          decode_xref_cursor, encode_search_cursor,
                          encode_xref_cursor)


# Keep the legacy domains ahead of new roles so existing `all` queries remain
# compatible. Exports still outrank generic named data at the same address.
_SEARCH_TYPE_PRIORITY = {
    "string": 0,
    "function": 1,
    "import": 2,
    "immediate": 3,
    "export": 4,
    "global": 5,
}
_SEARCH_SOURCE_LIMIT = 500
_SEARCH_CURSOR_CHECKPOINT_LIMIT = 4096
_SEARCH_CURSOR_CHECKPOINTS = OrderedDict()
_SEARCH_CURSOR_CHECKPOINT_IDS = set()
_SEARCH_CURSOR_CHECKPOINT_LOCK = threading.RLock()
_CHECKPOINT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
_CHECKPOINT_ID_ATTEMPTS = 64


def _candidate_digest(items):
    digest = hashlib.sha256()
    for item in items:
        encoded = json.dumps([
            item["_rank"], item["type"], item["ea"], str(item["value"]),
        ], ensure_ascii=False, separators=(",", ":"))
        digest.update(encoded.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _generate_checkpoint_id():
    return secrets.token_urlsafe(24)


def _issue_numeric_all_cursor(target_fingerprint, query, search_type, offset,
                              state, candidate_digest, progress):
    with _SEARCH_CURSOR_CHECKPOINT_LOCK:
        checkpoint_id = None
        for _attempt in range(_CHECKPOINT_ID_ATTEMPTS):
            candidate = _generate_checkpoint_id()
            if (_CHECKPOINT_ID_RE.fullmatch(candidate) is not None
                    and candidate not in _SEARCH_CURSOR_CHECKPOINT_IDS):
                checkpoint_id = candidate
                break
        if checkpoint_id is None:
            raise IDAError(
                "INTERNAL", "failed to allocate a unique checkpoint id")

        issued_state = dict(state)
        issued_state["checkpoint_id"] = checkpoint_id
        cursor = encode_search_cursor(
            "search", target_fingerprint, query, search_type, offset,
            state=issued_state)
        if cursor in _SEARCH_CURSOR_CHECKPOINTS:
            raise IDAError(
                "INTERNAL", "unique checkpoint produced an existing cursor")
        checkpoint = {
            "checkpoint_id": checkpoint_id,
            "offset": offset,
            "state": issued_state,
            "candidate_digest": candidate_digest,
            "progress": dict(progress),
        }
        _SEARCH_CURSOR_CHECKPOINTS[cursor] = checkpoint
        _SEARCH_CURSOR_CHECKPOINT_IDS.add(checkpoint_id)
        _SEARCH_CURSOR_CHECKPOINTS.move_to_end(cursor)
        while len(_SEARCH_CURSOR_CHECKPOINTS) > _SEARCH_CURSOR_CHECKPOINT_LIMIT:
            _old_cursor, old_checkpoint = (
                _SEARCH_CURSOR_CHECKPOINTS.popitem(last=False))
            _SEARCH_CURSOR_CHECKPOINT_IDS.discard(
                old_checkpoint["checkpoint_id"])
        return cursor


def _get_numeric_all_checkpoint(cursor):
    with _SEARCH_CURSOR_CHECKPOINT_LOCK:
        checkpoint = _SEARCH_CURSOR_CHECKPOINTS.get(cursor)
        if checkpoint is None:
            return None
        _SEARCH_CURSOR_CHECKPOINTS.move_to_end(cursor)
        return {
            "offset": checkpoint["offset"],
            "state": dict(checkpoint["state"]),
            "candidate_digest": checkpoint["candidate_digest"],
            "progress": dict(checkpoint["progress"]),
        }


@mcp.tool(annotations=READ_ONLY_TOOL)
def search(query: str, type: SearchType = "all",
           limit: ResultLimit = DEFAULT_SEARCH_LIMIT,
           cursor: Optional[str] = None,
           f: str = None) -> str:
    """Search functions, strings, imports, named data, exports, or immediates.
    Returns a stable resumable discovery page with bounded identity and reference
    summaries. Use trace_data when instruction-level use context is required."""
    r = _route_if_remote(
        f, "search", query=query, type=type, limit=limit, cursor=cursor)
    if r: return r
    try:
        limit = _validate_positive_int(limit, "limit", 500)
        if not isinstance(query, str):
            raise IDAError("INVALID_PARAM", "query must be a string")
        valid_types = {
            "string", "function", "import", "immediate", "global", "data",
            "export", "all",
        }
        if not isinstance(type, str) or type not in valid_types:
            raise IDAError(
                "INVALID_PARAM", f"type must be one of {sorted(valid_types)}")
        if cursor is not None and not isinstance(cursor, str):
            raise IDAError("INVALID_PARAM", "cursor must be a string or null")

        target_fingerprint = api.get_database_fingerprint()
        if cursor is None:
            offset = 0
            cursor_state = None
        else:
            try:
                decoded = decode_search_cursor(
                    cursor, "search", target_fingerprint, query, type,
                    include_state=True)
                offset = decoded["offset"]
                cursor_state = decoded["state"]
            except CursorError as e:
                raise IDAError("INVALID_PARAM", f"invalid cursor: {e}") from e

        q_lower = query.casefold()

        def match_rank(name):
            nl = name.casefold()
            if nl == q_lower:
                return True, 0
            if nl.startswith(q_lower):
                return True, 1
            if q_lower in nl:
                return True, 2
            return False, 3

        named_results = []

        def add_named(result_type, value, ea):
            if not isinstance(value, str):
                return
            ok, rank = match_rank(value)
            if ok:
                named_results.append({
                    "_rank": rank, "type": result_type,
                    "value": value, "ea": ea,
                })

        if type in ("string", "all"):
            for s in api.get_strings():
                add_named("string", s["value"], s["ea"])
        if type in ("function", "all"):
            for func in api.get_func_list():
                add_named("function", func["name"], func["ea"])
        if type in ("import", "all"):
            for imp in api.get_imports():
                add_named("import", imp["name"], imp["ea"])
        if type in ("global", "data", "all"):
            for item in api.get_globals():
                add_named("global", item["name"], item["ea"])
        if type in ("export", "all"):
            for item in api.get_exports():
                add_named("export", item["name"], item["ea"])

        note = None
        parsed = _try_parse_int(query) if type in ("immediate", "all") else None
        if type == "immediate" and parsed is None:
            note = ("query is not a numeric value; immediate search "
                    "requires a number")

        def role_key(item):
            return (_SEARCH_TYPE_PRIORITY[item["type"]], item["_rank"],
                    str(item["value"]))

        def result_key(item):
            return (item["_rank"], _SEARCH_TYPE_PRIORITY[item["type"]],
                    item["ea"], str(item["value"]))

        by_ea = {}
        for item in named_results:
            existing = by_ea.get(item["ea"])
            if existing is None or role_key(item) < role_key(existing):
                by_ea[item["ea"]] = item
        named = sorted(by_ea.values(), key=result_key)

        def invalid_state(message):
            raise IDAError("INVALID_PARAM", f"invalid cursor state: {message}")

        def require_int(state, name):
            value = state.get(name)
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 0):
                invalid_state(f"{name} must be a non-negative integer")
            return value

        def immediate_page(source_offset, page_limit):
            page = api.search_imm(parsed, source_offset, page_limit)
            if not isinstance(page, dict) or set(page) != {
                    "items", "next_offset", "complete"}:
                raise IDAError("INTERNAL", "invalid immediate page contract")
            items = page["items"]
            next_offset = page["next_offset"]
            complete = page["complete"]
            if (not isinstance(items, list) or isinstance(next_offset, bool)
                    or not isinstance(next_offset, int)
                    or next_offset != source_offset + len(items)
                    or not isinstance(complete, bool)):
                raise IDAError("INTERNAL", "invalid immediate page contract")
            if not complete and not items:
                raise IDAError(
                    "INTERNAL", "incomplete immediate page made no progress")
            previous_ea = None
            for hit in items:
                if (not isinstance(hit, dict)
                        or isinstance(hit.get("ea"), bool)
                        or not isinstance(hit.get("ea"), int)
                        or (previous_ea is not None
                            and hit["ea"] <= previous_ea)):
                    raise IDAError(
                        "INTERNAL", "immediate page is not strictly EA-sorted")
                previous_ea = hit["ea"]
            return page

        top = []
        total = None
        next_state = None
        numeric_all_digest = None
        numeric_all_progress = None

        if type == "immediate" and parsed is not None:
            if cursor is None:
                source_offset = 0
            else:
                if (not isinstance(cursor_state, dict)
                        or set(cursor_state) != {"phase", "source_offset"}
                        or cursor_state.get("phase") != "immediate"):
                    invalid_state("expected immediate phase")
                source_offset = require_int(cursor_state, "source_offset")
                if source_offset != offset:
                    invalid_state("source offset does not match public offset")
            page = immediate_page(source_offset, limit)
            top = [{"_rank": 0, "type": "immediate", "value": parsed,
                    "ea": hit["ea"]} for hit in page["items"]]
            has_more = not page["complete"]
            page_end = offset + len(top)
            total = page_end if page["complete"] else None
            next_state = {
                "phase": "immediate", "source_offset": page["next_offset"],
            }
        elif type == "all" and parsed is not None:
            before = [item for item in named
                      if (item["_rank"], _SEARCH_TYPE_PRIORITY[item["type"]])
                      < (0, _SEARCH_TYPE_PRIORITY["immediate"])]
            before_eas = {item["ea"] for item in before}
            after = [item for item in named if item["ea"] not in before_eas]
            numeric_all_digest = _candidate_digest(named)

            if cursor is None:
                phase = "before"
                source_offset = 0
                named_offset = 0
                numeric_all_progress = {
                    "before_returned": 0,
                    "immediate_returned": 0,
                    "after_returned": 0,
                }
            else:
                if (not isinstance(cursor_state, dict)
                        or set(cursor_state) != {
                            "phase", "source_offset", "named_offset",
                            "checkpoint_id"}):
                    invalid_state("expected all-search phase state")
                phase = cursor_state.get("phase")
                if phase not in {"before", "immediate", "after"}:
                    invalid_state("unknown phase")
                source_offset = require_int(cursor_state, "source_offset")
                named_offset = require_int(cursor_state, "named_offset")
                checkpoint_id = cursor_state.get("checkpoint_id")
                if (not isinstance(checkpoint_id, str)
                        or _CHECKPOINT_ID_RE.fullmatch(checkpoint_id) is None):
                    invalid_state("checkpoint_id has invalid format")
                checkpoint = _get_numeric_all_checkpoint(cursor)
                if checkpoint is None:
                    invalid_state(
                        "unknown or expired numeric all cursor checkpoint")
                if (checkpoint["offset"] != offset
                        or checkpoint["state"] != cursor_state):
                    invalid_state("cursor does not match its issued checkpoint")
                if checkpoint["candidate_digest"] != numeric_all_digest:
                    invalid_state(
                        "named candidate view changed since cursor issuance")
                numeric_all_progress = checkpoint["progress"]

            if set(numeric_all_progress) != {
                    "before_returned", "immediate_returned",
                    "after_returned"}:
                invalid_state("checkpoint progress has invalid fields")
            for progress_name in numeric_all_progress:
                require_int(numeric_all_progress, progress_name)
            before_returned = numeric_all_progress["before_returned"]
            immediate_returned = numeric_all_progress["immediate_returned"]
            after_returned = numeric_all_progress["after_returned"]
            if before_returned + immediate_returned + after_returned != offset:
                invalid_state("checkpoint progress does not match public offset")
            if cursor is None:
                pass
            elif phase == "before":
                if (source_offset != 0 or immediate_returned != 0
                        or after_returned != 0
                        or named_offset != before_returned
                        or before_returned >= len(before)):
                    invalid_state("unreachable before phase progress")
            elif phase == "immediate":
                if (named_offset != 0 or before_returned != len(before)
                        or after_returned != 0
                        or immediate_returned > source_offset):
                    invalid_state("unreachable immediate phase progress")
            elif (before_returned != len(before)
                  or immediate_returned > source_offset
                  or after_returned > named_offset):
                invalid_state("unreachable after phase progress")

            remaining = limit
            if phase == "before":
                if source_offset != 0 or named_offset > len(before):
                    invalid_state("before phase offsets are out of range")
                take = min(remaining, len(before) - named_offset)
                top.extend(before[named_offset:named_offset + take])
                named_offset += take
                numeric_all_progress["before_returned"] += take
                remaining -= take
                if named_offset == len(before):
                    phase = "immediate"
                    named_offset = 0

            if phase == "immediate" and remaining:
                page = immediate_page(source_offset, _SEARCH_SOURCE_LIMIT)
                consumed = 0
                for hit in page["items"]:
                    consumed += 1
                    existing = by_ea.get(hit["ea"])
                    if (existing is not None
                            and _SEARCH_TYPE_PRIORITY[existing["type"]]
                            < _SEARCH_TYPE_PRIORITY["immediate"]):
                        continue
                    top.append({
                        "_rank": 0, "type": "immediate", "value": parsed,
                        "ea": hit["ea"],
                    })
                    numeric_all_progress["immediate_returned"] += 1
                    remaining -= 1
                    if not remaining:
                        break
                source_offset += consumed
                if consumed == len(page["items"]) and page["complete"]:
                    phase = "after"
                    named_offset = 0

            if phase == "after" and remaining:
                if named_offset > len(after):
                    invalid_state("after phase offset is out of range")
                scan = after[
                    named_offset:named_offset + _SEARCH_SOURCE_LIMIT]
                lower_eas = [
                    item["ea"] for item in scan
                    if _SEARCH_TYPE_PRIORITY[item["type"]]
                    > _SEARCH_TYPE_PRIORITY["immediate"]
                ]
                filtered = api.filter_immediate_eas(parsed, lower_eas)
                if (not isinstance(filtered, list)
                        or any(isinstance(ea, bool) or not isinstance(ea, int)
                               for ea in filtered)):
                    raise IDAError(
                        "INTERNAL", "invalid immediate filter contract")
                replaced = set(filtered)
                if not replaced.issubset(set(lower_eas)):
                    raise IDAError(
                        "INTERNAL", "immediate filter returned an unknown EA")
                consumed = 0
                for item in scan:
                    consumed += 1
                    if (_SEARCH_TYPE_PRIORITY[item["type"]]
                            > _SEARCH_TYPE_PRIORITY["immediate"]
                            and item["ea"] in replaced):
                        continue
                    top.append(item)
                    numeric_all_progress["after_returned"] += 1
                    remaining -= 1
                    if not remaining:
                        break
                named_offset += consumed

            page_end = offset + len(top)
            if sum(numeric_all_progress.values()) != page_end:
                raise IDAError(
                    "INTERNAL", "numeric all progress lost public results")
            has_more = phase != "after" or named_offset < len(after)
            if not has_more:
                total = page_end
            next_state = {
                "phase": phase,
                "source_offset": source_offset,
                "named_offset": named_offset,
            }
        else:
            if cursor_state is not None:
                invalid_state("state is not allowed for this query")
            total = len(named)
            if offset > total:
                raise IDAError(
                    "INVALID_PARAM",
                    f"cursor offset {offset} exceeds current result total {total}",
                )
            page_end = min(offset + limit, total)
            top = named[offset:page_end]
            has_more = page_end < total

        next_cursor = None
        if has_more:
            try:
                if numeric_all_progress is not None:
                    next_cursor = _issue_numeric_all_cursor(
                        target_fingerprint, query, type, page_end, next_state,
                        numeric_all_digest, numeric_all_progress)
                else:
                    next_cursor = encode_search_cursor(
                        "search", target_fingerprint, query, type, page_end,
                        state=next_state)
            except CursorError as e:
                raise IDAError("INVALID_PARAM", f"invalid cursor: {e}") from e

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

        summary = {
            "total": total,
            "categories": sorted(categories),
            "truncated": has_more,
            "offset": offset,
            "returned": len(out_results),
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
        if note:
            summary["note"] = note
        return format_output({"query": query, "type": type,
                              "summary": summary, "results": out_results})
    except IDAError as e:
        return error_result(e)


@mcp.tool(annotations=READ_ONLY_TOOL)
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
            if "from_func_ea" in xref:
                func_ea = xref["from_func_ea"]
                function_name = xref.get("from_func_name")
            else:
                cf = _containing_function(from_ea)
                func_ea = _try_parse_int(cf["ea"]) if cf else None
                function_name = cf["name"] if cf else None
            key = func_ea if func_ea is not None else ea_to_hex(from_ea)
            if key not in grouped:
                grouped[key] = {
                    "function": function_name,
                    "function_ea": func_ea,
                    "sites": [],
                }
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
                func_start = g["function_ea"]
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


@mcp.tool(annotations=READ_ONLY_TOOL)
def cross_references(identifier: str, scope: XrefScope = "auto",
                     limit: ResultLimit = DEFAULT_XREF_LIGHT_LIMIT,
                     cursor: Optional[str] = None,
                     f: str = None) -> str:
    """Get incoming and outgoing cross-references for a function or address.
    Lighter than trace_data — returns reference lists without code context
    snippets. Use when you need the reference graph structure, not the code at
    each site."""
    r = _route_if_remote(
        f, "cross_references", identifier=identifier, scope=scope,
        limit=limit, cursor=cursor)
    if r: return r
    try:
        limit = _validate_positive_int(limit, "limit", 500)
        if (not isinstance(scope, str)
                or scope not in {"auto", "address", "function"}):
            raise IDAError(
                "INVALID_PARAM",
                "scope must be one of ['address', 'auto', 'function']")
        if cursor is not None and not isinstance(cursor, str):
            raise IDAError("INVALID_PARAM", "cursor must be a string or null")

        requested_ea = resolve_identifier(identifier)
        target_ea = requested_ea
        resolved_scope = "address"
        func_info = None
        if scope == "function":
            func_info = api.get_func_info(requested_ea)
            target_ea = func_info["ea"]
            resolved_scope = "function"
        elif scope == "auto":
            try:
                candidate = api.get_func_info(requested_ea)
            except IDAError as e:
                if e.code != "NO_FUNCTION":
                    raise
            else:
                if candidate["ea"] == requested_ea:
                    func_info = candidate
                    resolved_scope = "function"

        if func_info is not None:
            name = func_info["name"]
        else:
            try:
                name = api.get_name(target_ea)["name"]
            except IDAError:
                name = ""

        target_fingerprint = api.get_database_fingerprint()
        if cursor is None:
            from_offset = 0
            to_offset = 0
        else:
            try:
                cursor_state = decode_xref_cursor(
                    cursor, target_fingerprint, target_ea, resolved_scope)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e
            from_offset = cursor_state["from_offset"]
            to_offset = cursor_state["to_offset"]

        if func_info is not None:
            from_xrefs = api.get_func_callers(target_ea)
            to_xrefs = api.get_func_callsites(target_ea)
        else:
            from_xrefs = api.get_xrefs_to(target_ea)
            to_xrefs = api.get_xrefs_from(target_ea)

        from_entries = []
        for xref in from_xrefs:
            from_ea = xref["from_ea"]
            if resolved_scope == "function":
                function_name = xref.get("from_func_name", "")
            else:
                cf = _containing_function(from_ea)
                function_name = cf["name"] if cf else None
            entry = {
                "function": function_name or None,
                "ea": from_ea,
                "callsite_ea": from_ea,
                "xref_type": xref.get("type", ""),
            }
            entry["_sort"] = (
                from_ea, xref.get("from_func_ea", BADADDR),
                entry["xref_type"], entry["function"] or "")
            from_entries.append(entry)

        to_entries = []
        for xref in to_xrefs:
            to_ea = xref["to_ea"]
            if resolved_scope == "function":
                function_name = xref.get("to_func_name", "")
                callsite_ea = xref["from_ea"]
            else:
                try:
                    function_name = api.get_name(to_ea)["name"]
                except IDAError:
                    function_name = ""
                callsite_ea = target_ea
            entry = {
                "function": function_name,
                "ea": to_ea,
                "callsite_ea": callsite_ea,
                "xref_type": xref.get("type", ""),
            }
            direct_target_ea = xref.get("direct_target_ea")
            if direct_target_ea is not None:
                entry["direct_target_ea"] = direct_target_ea
            entry["_sort"] = (
                callsite_ea,
                direct_target_ea if direct_target_ea is not None else to_ea,
                to_ea, entry["xref_type"], function_name)
            to_entries.append(entry)

        from_entries.sort(key=lambda item: item["_sort"])
        to_entries.sort(key=lambda item: item["_sort"])
        from_total = len(from_entries)
        to_total = len(to_entries)
        if from_offset > from_total or to_offset > to_total:
            raise IDAError(
                "INVALID_PARAM",
                "cursor direction offset exceeds the current xref total")
        from_end = min(from_offset + limit, from_total)
        to_end = min(to_offset + limit, to_total)
        from_page = from_entries[from_offset:from_end]
        to_page = to_entries[to_offset:to_end]

        def attach_instruction(entry):
            try:
                d = api.get_disasm(entry["callsite_ea"], 1)
                instruction = d[0]["disasm"] if d else ""
            except IDAError:
                instruction = ""
            entry["instruction"] = instruction
            entry.pop("_sort", None)
            return entry

        from_list = [attach_instruction(entry) for entry in from_page]
        to_list = [attach_instruction(entry) for entry in to_page]
        from_has_more = from_end < from_total
        to_has_more = to_end < to_total
        has_more = from_has_more or to_has_more
        next_cursor = None
        if has_more:
            try:
                next_cursor = encode_xref_cursor(
                    target_fingerprint, target_ea, resolved_scope,
                    from_end, to_end)
            except CursorError as e:
                raise IDAError(
                    "INVALID_PARAM", f"invalid cursor: {e}") from e

        return format_output({
            "target": {"name": name, "ea": target_ea},
            "scope": resolved_scope,
            "from": from_list,
            "from_total": from_total,
            "from_truncated": from_total > limit,
            "to": to_list,
            "to_total": to_total,
            "to_truncated": to_total > limit,
            "summary": {
                "offset": from_end + to_end,
                "from": {
                    "offset": from_offset,
                    "returned": len(from_list),
                    "total": from_total,
                    "has_more": from_has_more,
                },
                "to": {
                    "offset": to_offset,
                    "returned": len(to_list),
                    "total": to_total,
                    "has_more": to_has_more,
                },
                "has_more": has_more,
                "next_cursor": next_cursor,
            },
        })
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "search": search,
    "trace_data": trace_data,
    "cross_references": cross_references,
})
