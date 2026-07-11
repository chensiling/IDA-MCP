"""Layer 3 MCP Server 入口。

mcp 实例与共享基础在 _base；工具按域分布在 tools/ 包。导入 tools 触发全部
@mcp.tool 注册。对外暴露 mcp / HTTP_HOST / HTTP_PORT / execute_tool。
"""
import json

from mcp.types import Tool as MCPTool

from ._base import (  # noqa: F401
    mcp, HTTP_HOST, HTTP_PORT,
    EXPECTED_TOOL_COUNT, _ALL_TOOLS, MCPToolError, tool_error_payload,
)

from . import tools  # noqa: F401  # 导入即注册全部工具
from .runtime_contract import (
    ALL_TOOL_NAMES,
    READ_TOOL_NAMES,
    TOOL_MANIFEST_SHA256,
    WRITE_TOOL_NAMES,
    classify_tool_access,
    tool_manifest_sha256,
)


PINNED_MCP_VERSION = "1.27.1"


def _sync_public_tools(mcp_instance):
    """Mirror FastMCP 1.27.1's public list_tools conversion synchronously."""
    manager = getattr(mcp_instance, "_tool_manager", None)
    list_tools = getattr(manager, "list_tools", None)
    if manager is None or not callable(list_tools):
        raise RuntimeError(
            "FastMCP 1.27.1 synchronous tool registry adapter is unavailable")
    try:
        registered = list_tools()
        return [
            MCPTool(
                name=info.name,
                title=info.title,
                description=info.description,
                inputSchema=info.parameters,
                outputSchema=info.output_schema,
                annotations=info.annotations,
                icons=info.icons,
                _meta=info.meta,
                execution=getattr(info, "execution", None),
            )
            for info in registered
        ]
    except (AttributeError, TypeError, ValueError) as ex:
        raise RuntimeError(
            "FastMCP 1.27.1 synchronous tool registry shape changed") from ex


def require_registered_tools(*, mcp_instance=None, tool_functions=None,
                             expected_manifest_sha256=None):
    """Fail fast unless the complete reviewed tool surface is registered."""
    if mcp_instance is None:
        mcp_instance = mcp
    if tool_functions is None:
        tool_functions = _ALL_TOOLS
    if expected_manifest_sha256 is None:
        expected_manifest_sha256 = TOOL_MANIFEST_SHA256

    if len(tool_functions) != EXPECTED_TOOL_COUNT:
        raise RuntimeError(
            f"IDA-MCP expected {EXPECTED_TOOL_COUNT} registered tools, "
            f"but found {len(tool_functions)}")
    function_names = frozenset(tool_functions)
    if function_names != ALL_TOOL_NAMES:
        raise RuntimeError(
            f"IDA-MCP local handler names differ from the reviewed "
            f"{EXPECTED_TOOL_COUNT}-tool access manifest")

    public_tools = _sync_public_tools(mcp_instance)
    public_names = [tool.name for tool in public_tools]
    if len(public_names) != EXPECTED_TOOL_COUNT:
        raise RuntimeError(
            f"IDA-MCP expected {EXPECTED_TOOL_COUNT} registered tools, "
            f"but found {len(public_names)}")
    if frozenset(public_names) != ALL_TOOL_NAMES:
        raise RuntimeError(
            "FastMCP registered tool names differ from the reviewed access "
            "manifest")
    try:
        actual_read, actual_write = classify_tool_access(public_tools)
    except (TypeError, ValueError) as ex:
        raise RuntimeError(f"FastMCP tool annotation contract failed: {ex}") from ex
    if actual_read != READ_TOOL_NAMES or actual_write != WRITE_TOOL_NAMES:
        raise RuntimeError(
            "FastMCP read/write annotations differ from the reviewed access "
            "manifest")

    try:
        actual_hash = tool_manifest_sha256(public_tools)
    except (TypeError, ValueError) as ex:
        raise RuntimeError(f"FastMCP public tool manifest is invalid: {ex}") from ex
    if actual_hash != expected_manifest_sha256:
        raise RuntimeError(
            "FastMCP public tool manifest hash mismatch: "
            f"expected {expected_manifest_sha256}, found {actual_hash}")
    return len(public_tools)


REGISTERED_TOOL_COUNT = require_registered_tools()


def execute_tool(name, kwargs):
    func = _ALL_TOOLS.get(name)
    if func is None:
        return tool_error_payload({"error": {
            "code": "INTERNAL", "message": f"Unknown tool: {name}"}})
    try:
        result = func(**kwargs)
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return {"text": str(result)}
    except MCPToolError as e:
        return e.payload
    except Exception as e:
        return tool_error_payload(e)
