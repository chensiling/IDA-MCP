"""Layer 3 MCP Server 入口。

mcp 实例与共享基础在 _base；工具按域分布在 tools/ 包。导入 tools 触发全部
@mcp.tool 注册。对外仍暴露 mcp / HTTP_HOST / HTTP_PORT，供插件入口启动。
"""

from ._base import mcp, HTTP_HOST, HTTP_PORT  # noqa: F401
from . import tools  # noqa: F401  导入即注册全部工具
