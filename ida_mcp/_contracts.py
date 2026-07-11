"""Pure helpers for correctness contracts shared by the IDA API layer."""

import base64
import binascii
import hashlib
import hmac
import json
import re


_CURSOR_VERSION = 4
_XREF_CURSOR_ORDERING_VERSION = 1
_DATA_CURSOR_ORDERING_VERSION = 1
_TYPE_CURSOR_ORDERING_VERSION = 1
_CURSOR_FIELDS = {
    "v", "tool", "target", "binding", "offset", "state", "checksum",
}
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CursorError(ValueError):
    """Raised when an opaque continuation cursor violates its contract."""


def _canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _search_binding_hash(query, search_type):
    if not isinstance(query, str) or not isinstance(search_type, str):
        raise CursorError("cursor query and type bindings must be strings")
    payload = _canonical_json({"query": query, "type": search_type})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cursor_checksum(payload):
    return hashlib.sha256(
        _canonical_json(payload).encode("utf-8")).hexdigest()


def encode_search_cursor(tool, target_fingerprint, query, search_type,
                         next_offset, state=None):
    """Encode a versioned, target- and query-bound search cursor."""
    if not isinstance(tool, str) or not tool:
        raise CursorError("cursor tool binding must be a non-empty string")
    if (not isinstance(target_fingerprint, str)
            or _SHA256_RE.fullmatch(target_fingerprint) is None):
        raise CursorError("cursor target binding must be a SHA-256 fingerprint")
    if (isinstance(next_offset, bool) or not isinstance(next_offset, int)
            or next_offset < 0):
        raise CursorError("cursor offset must be a non-negative integer")
    if state is not None and not isinstance(state, dict):
        raise CursorError("cursor state must be an object or null")

    payload = {
        "v": _CURSOR_VERSION,
        "tool": tool,
        "target": target_fingerprint,
        "binding": _search_binding_hash(query, search_type),
        "offset": next_offset,
        "state": state,
    }
    payload["checksum"] = _cursor_checksum(payload)
    raw = _canonical_json(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CursorError("cursor payload contains duplicate fields")
        result[key] = value
    return result


def decode_search_cursor(cursor, tool, target_fingerprint, query,
                         search_type, include_state=False):
    """Validate a search cursor and return its continuation offset."""
    if (not isinstance(cursor, str) or not cursor
            or _BASE64URL_RE.fullmatch(cursor) is None):
        raise CursorError("cursor must be a non-empty base64url string")
    padding = "=" * (-len(cursor) % 4)
    try:
        raw = base64.b64decode(
            cursor + padding, altchars=b"-_", validate=True)
        canonical_cursor = base64.urlsafe_b64encode(
            raw).rstrip(b"=").decode("ascii")
        if cursor != canonical_cursor:
            raise CursorError("cursor is not canonical base64url")
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except CursorError:
        raise
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise CursorError("cursor payload is not valid base64url JSON") from e

    if not isinstance(payload, dict) or set(payload) != _CURSOR_FIELDS:
        raise CursorError("cursor payload has invalid fields")
    if raw != _canonical_json(payload).encode("utf-8"):
        raise CursorError("cursor payload is not canonical JSON")
    if isinstance(payload["v"], bool) or not isinstance(payload["v"], int):
        raise CursorError("cursor version must be an integer")
    if payload["v"] != _CURSOR_VERSION:
        raise CursorError(f"unsupported cursor version: {payload['v']}")
    if not isinstance(payload["tool"], str) or not payload["tool"]:
        raise CursorError("cursor tool binding has invalid format")
    if (not isinstance(payload["target"], str)
            or _SHA256_RE.fullmatch(payload["target"]) is None):
        raise CursorError("cursor target binding has invalid format")
    if (not isinstance(payload["binding"], str)
            or _SHA256_RE.fullmatch(payload["binding"]) is None):
        raise CursorError("cursor query binding has invalid format")
    if (not isinstance(payload["checksum"], str)
            or _SHA256_RE.fullmatch(payload["checksum"]) is None):
        raise CursorError("cursor checksum has invalid format")

    signed = {key: value for key, value in payload.items()
              if key != "checksum"}
    if not hmac.compare_digest(payload["checksum"],
                               _cursor_checksum(signed)):
        raise CursorError("cursor checksum mismatch")
    if payload["tool"] != tool:
        raise CursorError("cursor does not match this tool")
    if payload["target"] != target_fingerprint:
        raise CursorError("cursor does not match the current target")
    if payload["binding"] != _search_binding_hash(query, search_type):
        raise CursorError("cursor does not match the current query or type")
    offset = payload["offset"]
    if (isinstance(offset, bool) or not isinstance(offset, int)
            or offset < 0):
        raise CursorError("cursor offset must be a non-negative integer")
    state = payload["state"]
    if state is not None and not isinstance(state, dict):
        raise CursorError("cursor state must be an object or null")
    if include_state:
        return {"offset": offset, "state": state}
    return offset


def _xref_cursor_binding(target_ea, scope, ordering_version):
    if (isinstance(target_ea, bool) or not isinstance(target_ea, int)
            or target_ea < 0):
        raise CursorError("xref cursor target must be a non-negative address")
    if scope not in {"address", "function"}:
        raise CursorError("xref cursor scope must be address or function")
    if (isinstance(ordering_version, bool)
            or not isinstance(ordering_version, int)
            or ordering_version < 1):
        raise CursorError("xref cursor ordering version must be positive")
    return hex(target_ea), f"{scope}:ordering-v{ordering_version}"


def encode_xref_cursor(target_fingerprint, target_ea, scope,
                       from_offset, to_offset, ordering_version=None):
    """Encode one continuation cursor with independent xref directions."""
    if ordering_version is None:
        ordering_version = _XREF_CURSOR_ORDERING_VERSION
    query, binding = _xref_cursor_binding(
        target_ea, scope, ordering_version)
    for name, value in (("from_offset", from_offset),
                        ("to_offset", to_offset)):
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 0):
            raise CursorError(
                f"xref cursor {name} must be a non-negative integer")
    state = {"from_offset": from_offset, "to_offset": to_offset}
    return encode_search_cursor(
        "cross_references", target_fingerprint, query, binding,
        from_offset + to_offset, state=state)


def decode_xref_cursor(cursor, target_fingerprint, target_ea, scope,
                       ordering_version=None):
    """Validate an xref cursor and return both direction offsets."""
    if ordering_version is None:
        ordering_version = _XREF_CURSOR_ORDERING_VERSION
    query, binding = _xref_cursor_binding(
        target_ea, scope, ordering_version)
    decoded = decode_search_cursor(
        cursor, "cross_references", target_fingerprint, query, binding,
        include_state=True)
    state = decoded["state"]
    if not isinstance(state, dict) or set(state) != {
            "from_offset", "to_offset"}:
        raise CursorError("xref cursor state has invalid fields")
    for name in ("from_offset", "to_offset"):
        value = state[name]
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 0):
            raise CursorError(
                f"xref cursor {name} must be a non-negative integer")
    if decoded["offset"] != state["from_offset"] + state["to_offset"]:
        raise CursorError("xref cursor offset does not match direction state")
    return state


def _data_cursor_binding(target_ea, read_offset, read_size,
                         dereference_depth, ordering_version):
    values = (
        ("target", target_ea, 0, None),
        ("read_offset", read_offset, 0, 1048576),
        ("read_size", read_size, 1, 4096),
        ("dereference_depth", dereference_depth, 0, 4),
        ("ordering_version", ordering_version, 1, None),
    )
    for name, value, minimum, maximum in values:
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < minimum
                or (maximum is not None and value > maximum)):
            if maximum is None:
                expected = f"at least {minimum}"
            else:
                expected = f"between {minimum} and {maximum}"
            raise CursorError(f"data cursor {name} must be {expected}")
    binding = _canonical_json({
        "read_offset": read_offset,
        "read_size": read_size,
        "dereference_depth": dereference_depth,
        "ordering_version": ordering_version,
    })
    return hex(target_ea), binding


_DATA_CURSOR_OFFSET_FIELDS = (
    "read_by_offset",
    "written_by_offset",
    "address_taken_by_offset",
    "other_refs_offset",
)


def encode_data_cursor(target_fingerprint, target_ea, read_offset, read_size,
                       dereference_depth, read_by_offset,
                       written_by_offset, address_taken_by_offset,
                       other_refs_offset, ordering_version=None):
    """Encode independent continuation offsets for all data-reference roles."""
    if ordering_version is None:
        ordering_version = _DATA_CURSOR_ORDERING_VERSION
    query, binding = _data_cursor_binding(
        target_ea, read_offset, read_size, dereference_depth,
        ordering_version)
    state = {
        "read_by_offset": read_by_offset,
        "written_by_offset": written_by_offset,
        "address_taken_by_offset": address_taken_by_offset,
        "other_refs_offset": other_refs_offset,
    }
    for name in _DATA_CURSOR_OFFSET_FIELDS:
        value = state[name]
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 0):
            raise CursorError(
                f"data cursor {name} must be a non-negative integer")
    return encode_search_cursor(
        "explore_data", target_fingerprint, query, binding,
        sum(state.values()), state=state)


def decode_data_cursor(cursor, target_fingerprint, target_ea, read_offset,
                       read_size, dereference_depth, ordering_version=None):
    """Validate a data-reference cursor and return all four role offsets."""
    if ordering_version is None:
        ordering_version = _DATA_CURSOR_ORDERING_VERSION
    query, binding = _data_cursor_binding(
        target_ea, read_offset, read_size, dereference_depth,
        ordering_version)
    decoded = decode_search_cursor(
        cursor, "explore_data", target_fingerprint, query, binding,
        include_state=True)
    state = decoded["state"]
    if (not isinstance(state, dict)
            or set(state) != set(_DATA_CURSOR_OFFSET_FIELDS)):
        raise CursorError("data cursor state has invalid fields")
    for name in _DATA_CURSOR_OFFSET_FIELDS:
        value = state[name]
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 0):
            raise CursorError(
                f"data cursor {name} must be a non-negative integer")
    if decoded["offset"] != sum(state.values()):
        raise CursorError(
            "data cursor offset does not match reference role state")
    return state


def _type_cursor_binding(tool, name_or_filter, ordering_version):
    if tool not in {"list_types", "get_type"}:
        raise CursorError("type cursor tool must be list_types or get_type")
    if not isinstance(name_or_filter, str):
        raise CursorError("type cursor name binding must be a string")
    if (isinstance(ordering_version, bool)
            or not isinstance(ordering_version, int)
            or ordering_version < 1):
        raise CursorError("type cursor ordering version must be positive")
    if tool == "list_types":
        canonical = name_or_filter.casefold()
        ordering = f"ordinal:ordering-v{ordering_version}"
    else:
        canonical = name_or_filter
        ordering = f"declaration:ordering-v{ordering_version}"
    return canonical, ordering


def encode_type_cursor(tool, target_fingerprint, name_or_filter, next_offset,
                       ordering_version=None):
    """Encode a local-type or member continuation cursor."""
    if ordering_version is None:
        ordering_version = _TYPE_CURSOR_ORDERING_VERSION
    query, binding = _type_cursor_binding(
        tool, name_or_filter, ordering_version)
    return encode_search_cursor(
        tool, target_fingerprint, query, binding, next_offset, state=None)


def decode_type_cursor(cursor, tool, target_fingerprint, name_or_filter,
                       ordering_version=None):
    """Validate a type cursor and return its collection offset."""
    if ordering_version is None:
        ordering_version = _TYPE_CURSOR_ORDERING_VERSION
    query, binding = _type_cursor_binding(
        tool, name_or_filter, ordering_version)
    decoded = decode_search_cursor(
        cursor, tool, target_fingerprint, query, binding,
        include_state=True)
    if decoded["state"] is not None:
        raise CursorError("type cursor state must be null")
    return decoded["offset"]


def is_valid_ea(ea, badaddr):
    """Return whether *ea* represents a usable IDA address."""
    return ea is not None and ea != badaddr


def classify_pseudocode_addresses(candidates, function_start, function_end,
                                   badaddr):
    """Classify best-effort pseudocode line addresses by their role.

    Candidate roles must come from Hex-Rays ctree evidence. Address range alone
    never turns an object/callee or otherwise ambiguous candidate into a
    statement. Every external candidate remains a referenced target.
    """
    valid = []
    statement_candidates = []
    referenced_targets = []
    seen_statements = set()
    seen_references = set()
    has_in_function_candidate = False
    for candidate in candidates:
        if isinstance(candidate, dict):
            ea = candidate.get("ea")
            role = candidate.get("role", "unknown")
        else:
            ea = candidate
            role = "unknown"
        if not is_valid_ea(ea, badaddr):
            continue
        valid.append(ea)
        in_function = function_start <= ea < function_end
        has_in_function_candidate = has_in_function_candidate or in_function
        if not in_function or role == "reference":
            if ea not in seen_references:
                seen_references.add(ea)
                referenced_targets.append(ea)
        elif role == "statement" and ea not in seen_statements:
            seen_statements.add(ea)
            statement_candidates.append(ea)

    statement_ea = (
        statement_candidates[0] if statement_candidates else None)

    if statement_ea is not None:
        mapping_reason = None
    elif not valid:
        mapping_reason = "no_address_candidates"
    elif not has_in_function_candidate:
        mapping_reason = "no_in_function_candidate"
    else:
        mapping_reason = "no_statement_candidate"

    return {
        "statement_ea": statement_ea,
        "referenced_targets": referenced_targets,
        "mapping_reason": mapping_reason,
    }


def bitfield_byte_envelope(bit_offset, bit_width):
    """Return the byte offset/size covering a bit-addressed member."""
    if bit_offset < 0 or bit_width < 0:
        raise ValueError("bit offset and width must be non-negative")
    byte_offset = bit_offset // 8
    if bit_width == 0:
        return byte_offset, 0
    byte_end = (bit_offset + bit_width + 7) // 8
    return byte_offset, byte_end - byte_offset


def read_bitfield_marker(udm):
    """Return IDA's exact UDM bitfield marker, or None when unavailable."""
    try:
        marker = udm.is_bitfield
        value = marker() if callable(marker) else marker
        return None if value is None else bool(value)
    except Exception:  # noqa: BLE001
        return None
