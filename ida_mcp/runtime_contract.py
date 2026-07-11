"""Side-effect-free runtime contract shared by Server, Worker, and plugin.

This module deliberately imports neither IDA nor FastMCP.  Internal protocol
peers can therefore validate authorization and compatibility before loading
either runtime.
"""

import hashlib
import json
import os
import re


SERVICE_NAME = "ida-mcp"
PROTOCOL_VERSION = 1
IMPLEMENTATION_VERSION = "1.0.0"
WRITE_ENABLE_ENV = "IDA_MCP_ALLOW_WRITE"

READ_TOOL_NAMES = frozenset({
    "analysis_status",
    "analyze_function",
    "binary_info",
    "binary_overview",
    "call_graph",
    "check_connection",
    "cross_references",
    "decompile",
    "decompile_with_addresses",
    "disassemble",
    "explore_data",
    "explore_function",
    "function_reachability",
    "get_comment",
    "get_function_prototype",
    "get_stack_frame",
    "get_switch",
    "get_type",
    "list_files",
    "list_local_variables",
    "list_types",
    "review_string_usage",
    "search",
    "survey_capabilities",
    "trace_data",
})

WRITE_TOOL_NAMES = frozenset({
    "apply_type",
    "create_type",
    "delete_type",
    "make_code",
    "make_data",
    "make_string",
    "patch_bytes",
    "rename",
    "rename_local_variable",
    "set_comment",
    "set_function_prototype",
    "set_local_variable_type",
    "undefine",
})

ALL_TOOL_NAMES = READ_TOOL_NAMES | WRITE_TOOL_NAMES
EXPECTED_TOOL_COUNT = 38

# Generated from FastMCP 1.27.1's complete public Tool records.  The value is
# replaced only together with a reviewed public-tool surface change.
TOOL_MANIFEST_SHA256 = "ba8e33e286928f1bb077b609d1ac12719590b42b80f4d998aef5b5927d962d61"

PUBLIC_TOOL_FIELDS = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "icons",
    "_meta",
    "execution",
)

CAPABILITY_FIELDS = frozenset({
    "read", "write", "hexrays", "worker_write_gate",
})
REQUIRED_CAPABILITIES = {
    "read": True,
    "worker_write_gate": True,
}

REGISTER_FIELDS = frozenset({
    "t",
    "fid",
    "name",
    "arch",
    "bits",
    "path",
    "pid",
    "call_port",
    "protocol_version",
    "implementation_version",
    "tool_manifest_sha256",
    "read_only",
    "capabilities",
})

REGISTER_MESSAGE_TYPE = "R"
ACK_MESSAGE_TYPE = "A"
ACK_COMMON_FIELDS = frozenset({
    "t",
    "ok",
    "service",
    "state",
    "protocol_version",
    "implementation_version",
    "tool_manifest_sha256",
    "required_capabilities",
})

INVALID_REGISTRATION = "INVALID_REGISTRATION"
PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"
IMPLEMENTATION_MISMATCH = "IMPLEMENTATION_MISMATCH"
TOOL_MANIFEST_MISMATCH = "TOOL_MANIFEST_MISMATCH"
CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
SERVER_STOPPING = "SERVER_STOPPING"

INCOMPATIBILITY_CODES = frozenset({
    INVALID_REGISTRATION,
    PROTOCOL_MISMATCH,
    IMPLEMENTATION_MISMATCH,
    TOOL_MANIFEST_MISMATCH,
    CAPABILITY_MISMATCH,
})

READ_ONLY_GUIDANCE = (
    "This IDA Worker is read-only. Explicitly enable writes on that Worker "
    "before retrying."
)
UNKNOWN_TOOL_GUIDANCE = (
    "The requested tool is not part of this IDA-MCP build. Refresh the "
    "available tool list before retrying."
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """Typed compatibility failure safe to place in an internal ACK."""

    def __init__(self, code, message):
        self.code = code
        self.message = str(message)
        super().__init__(self.message)

    def payload(self):
        return {"code": self.code, "message": self.message}


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def public_tool_record(tool):
    """Return exactly the reviewed public MCP Tool fields."""
    if hasattr(tool, "model_dump"):
        dumped = tool.model_dump(by_alias=True)
    elif isinstance(tool, dict):
        dumped = tool
    else:
        raise TypeError("tool must be a mapping or expose model_dump()")
    missing = [field for field in PUBLIC_TOOL_FIELDS if field not in dumped]
    if missing:
        raise ValueError(
            "public tool record is missing fields: " + ", ".join(missing))
    record = {field: dumped[field] for field in PUBLIC_TOOL_FIELDS}
    if not isinstance(record["name"], str) or not record["name"]:
        raise ValueError("public tool name must be a non-empty string")
    return record


def canonical_tool_manifest(tools):
    """Build canonical JSON for the full, sorted public Tool manifest."""
    records = [public_tool_record(tool) for tool in tools]
    records.sort(key=lambda item: item["name"])
    names = [item["name"] for item in records]
    if len(names) != len(set(names)):
        raise ValueError("public tool manifest contains duplicate names")
    return canonical_json(records)


def tool_manifest_sha256(tools):
    canonical = canonical_tool_manifest(tools).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def classify_tool_access(tools):
    """Classify actual annotations; reject anything except reviewed shapes."""
    read_names = set()
    write_names = set()
    for tool in tools:
        record = public_tool_record(tool)
        annotations = record["annotations"]
        if not isinstance(annotations, dict):
            raise ValueError(
                f"tool {record['name']!r} has no annotation object")
        hints = tuple(annotations.get(name) for name in (
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ))
        if any(type(value) is not bool for value in hints):
            raise ValueError(
                f"tool {record['name']!r} has non-boolean annotations")
        if hints == (True, False, True, False):
            read_names.add(record["name"])
        elif hints == (False, True, False, False):
            write_names.add(record["name"])
        else:
            raise ValueError(
                f"tool {record['name']!r} has unsupported annotations")
    return frozenset(read_names), frozenset(write_names)


def read_only_from_environment():
    """Read the one production write opt-in; every other value fails closed."""
    value = os.environ.get(WRITE_ENABLE_ENV)
    if value == "1":
        return False
    if value not in (None, "", "0"):
        print(
            f"[ida-mcp] Ignoring invalid {WRITE_ENABLE_ENV}={value!r}; "
            "Worker remains read-only")
    return True


def worker_capabilities(read_only, hexrays):
    if type(read_only) is not bool:
        raise ValueError("read_only must be a boolean")
    if type(hexrays) is not bool:
        raise ValueError("hexrays must be a boolean")
    return {
        "read": True,
        "write": not read_only,
        "hexrays": hexrays,
        "worker_write_gate": True,
    }


def read_only_error(tool):
    return {"error": {
        "code": "READ_ONLY",
        "message": (
            f"Tool {tool!r} is disabled because this IDA Worker is read-only.")
    }}


def unknown_tool_error(tool):
    return {"error": {
        "code": "UNKNOWN_TOOL",
        "message": (
            f"Tool {tool!r} is not in the reviewed IDA-MCP tool allowlist.")
    }}


def _invalid(message):
    raise ContractError(INVALID_REGISTRATION, message)


def _validate_exact_int(value, field, *, allowed=None, minimum=None,
                        maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        _invalid(f"{field} must be an integer")
    if allowed is not None and value not in allowed:
        _invalid(f"{field} has an unsupported value")
    if minimum is not None and value < minimum:
        _invalid(f"{field} is below its minimum")
    if maximum is not None and value > maximum:
        _invalid(f"{field} is above its maximum")


def _validate_contract_values(message):
    protocol_version = message.get("protocol_version")
    if isinstance(protocol_version, bool) or not isinstance(
            protocol_version, int):
        _invalid("protocol_version must be an integer")
    if protocol_version != PROTOCOL_VERSION:
        raise ContractError(
            PROTOCOL_MISMATCH,
            f"protocol version {protocol_version!r} is incompatible; "
            f"expected {PROTOCOL_VERSION}",
        )

    implementation_version = message.get("implementation_version")
    if (not isinstance(implementation_version, str)
            or not implementation_version):
        _invalid("implementation_version must be a non-empty string")
    if implementation_version != IMPLEMENTATION_VERSION:
        raise ContractError(
            IMPLEMENTATION_MISMATCH,
            f"implementation version {implementation_version!r} is "
            f"incompatible; expected {IMPLEMENTATION_VERSION!r}",
        )

    manifest = message.get("tool_manifest_sha256")
    if not isinstance(manifest, str) or _SHA256_RE.fullmatch(manifest) is None:
        _invalid("tool_manifest_sha256 must be 64 lowercase hex characters")
    if manifest != TOOL_MANIFEST_SHA256:
        raise ContractError(
            TOOL_MANIFEST_MISMATCH,
            "tool manifest is incompatible with this IDA-MCP build",
        )


def validate_worker_capabilities(read_only, capabilities):
    if type(read_only) is not bool:
        _invalid("read_only must be a boolean")
    if not isinstance(capabilities, dict):
        _invalid("capabilities must be an object")
    if set(capabilities) != CAPABILITY_FIELDS:
        _invalid("capabilities must contain exactly read/write/hexrays/"
                 "worker_write_gate")
    if any(type(value) is not bool for value in capabilities.values()):
        _invalid("capability values must be booleans")
    if (capabilities["read"] is not True
            or capabilities["worker_write_gate"] is not True
            or capabilities["write"] is not (not read_only)):
        raise ContractError(
            CAPABILITY_MISMATCH,
            "capabilities do not match the Worker authorization state",
        )
    return dict(capabilities)


def validate_registration(message):
    """Validate a closed REGISTER and return copied accepted metadata."""
    if not isinstance(message, dict):
        _invalid("registration must be an object")
    if set(message) != REGISTER_FIELDS:
        _invalid("registration fields do not match the protocol contract")
    if message["t"] != REGISTER_MESSAGE_TYPE:
        _invalid("registration message type is invalid")
    for field in ("fid", "name", "arch", "path"):
        if not isinstance(message[field], str) or not message[field]:
            _invalid(f"{field} must be a non-empty string")
    _validate_exact_int(message["bits"], "bits", allowed=(16, 32, 64))
    _validate_exact_int(message["pid"], "pid", minimum=0)
    _validate_exact_int(
        message["call_port"], "call_port", minimum=1, maximum=65535)
    _validate_contract_values(message)
    capabilities = validate_worker_capabilities(
        message["read_only"], message["capabilities"])
    return {
        "protocol_version": message["protocol_version"],
        "implementation_version": message["implementation_version"],
        "tool_manifest_sha256": message["tool_manifest_sha256"],
        "read_only": message["read_only"],
        "capabilities": capabilities,
    }


def ack_envelope(ok, *, code=None, message=None, state="running"):
    """Build one exact registration/probe ACK envelope."""
    if type(ok) is not bool:
        raise ValueError("ok must be a boolean")
    if state not in ("running", "stopping"):
        raise ValueError("state must be running or stopping")
    payload = {
        "t": ACK_MESSAGE_TYPE,
        "ok": ok,
        "service": SERVICE_NAME,
        "state": state,
        "protocol_version": PROTOCOL_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "tool_manifest_sha256": TOOL_MANIFEST_SHA256,
        "required_capabilities": dict(REQUIRED_CAPABILITIES),
    }
    if ok:
        if state != "running" or code is not None or message is not None:
            raise ValueError("positive ACK must be running without an error")
        return payload
    allowed = {SERVER_STOPPING} if state == "stopping" else INCOMPATIBILITY_CODES
    if code not in allowed or not isinstance(message, str) or not message:
        raise ValueError("negative ACK requires a valid code and message")
    payload["error"] = {"code": code, "message": message}
    return payload


def _validate_required_capabilities(value):
    if not isinstance(value, dict) or set(value) != set(REQUIRED_CAPABILITIES):
        _invalid("required_capabilities has invalid fields")
    if any(type(item) is not bool for item in value.values()):
        _invalid("required_capabilities values must be booleans")
    if value != REQUIRED_CAPABILITIES:
        raise ContractError(
            CAPABILITY_MISMATCH,
            "Server does not require the expected Worker capabilities",
        )


def inspect_server_ack(message):
    """Return (compatible|incompatible|stopping, structured diagnostic)."""
    try:
        if not isinstance(message, dict):
            _invalid("ACK must be an object")
        if type(message.get("ok")) is not bool:
            _invalid("ACK ok must be a boolean")
        expected_fields = ACK_COMMON_FIELDS | (
            frozenset() if message["ok"] else frozenset({"error"}))
        if set(message) != expected_fields:
            _invalid("ACK fields do not match the protocol contract")
        if message["t"] != ACK_MESSAGE_TYPE:
            _invalid("ACK message type is invalid")
        if message["service"] != SERVICE_NAME:
            _invalid("ACK service is invalid")
        if message["state"] not in ("running", "stopping"):
            _invalid("ACK state is invalid")
        _validate_contract_values(message)
        _validate_required_capabilities(message["required_capabilities"])

        if message["ok"]:
            if message["state"] != "running":
                _invalid("positive ACK must be in running state")
            return "compatible", None

        error = message["error"]
        if not isinstance(error, dict) or set(error) != {"code", "message"}:
            _invalid("negative ACK error has invalid fields")
        code = error["code"]
        text = error["message"]
        if type(code) is not str or not code:
            _invalid("negative ACK error code must be a non-empty string")
        if type(text) is not str or not text:
            _invalid("negative ACK error message must be non-empty")
        if message["state"] == "stopping":
            if code != SERVER_STOPPING:
                _invalid("stopping ACK must use SERVER_STOPPING")
            return "stopping", dict(error)
        if code not in INCOMPATIBILITY_CODES:
            _invalid("negative ACK error code is invalid")
        return "incompatible", dict(error)
    except ContractError as ex:
        return "incompatible", ex.payload()


def validate_positive_ack(message):
    status, diagnostic = inspect_server_ack(message)
    if status != "compatible":
        raise ContractError(
            diagnostic["code"], diagnostic["message"])
    return True


if len(READ_TOOL_NAMES) != 25 or len(WRITE_TOOL_NAMES) != 13:
    raise RuntimeError("central tool access manifest has invalid cardinality")
if len(ALL_TOOL_NAMES) != EXPECTED_TOOL_COUNT:
    raise RuntimeError("central tool access manifest has invalid total")
if READ_TOOL_NAMES & WRITE_TOOL_NAMES:
    raise RuntimeError("central tool access manifest overlaps")
