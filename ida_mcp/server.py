"""Layer 3 MCP Server 入口。

mcp 实例与共享基础在 _base；工具按域分布在 tools/ 包。导入 tools 触发全部
@mcp.tool 注册。对外暴露 mcp / HTTP_HOST / HTTP_PORT / execute_tool。
"""
import json

from ._base import (  # noqa: F401
    mcp, HTTP_HOST, HTTP_PORT,
    _ALL_TOOLS, format_output,
)

from . import tools  # noqa: F401  # 导入即注册全部工具


def execute_tool(name, kwargs):
    func = _ALL_TOOLS.get(name)
    if func is None:
        return {"error": {"code": "INTERNAL",
                          "message": f"Unknown tool: {name}"}}
    try:
        result = func(**kwargs)
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return {"text": str(result)}
    except Exception as e:
        code = getattr(e, 'code', 'INTERNAL')
        return {"error": {"code": code, "message": str(e)}}
