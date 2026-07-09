"""IDA-MCP 插件包：在 IDA 内嵌 Python 中运行的单进程 MCP Server。

架构（单进程）：
    opencode  ──HTTP──▶  ida_mcp.py (IDA 插件)
                          └─ FastMCP(streamable-http) 后台线程
                             └─ 工具经 execute_sync 直调 IDA API

不再需要 TCP bridge / ida_client / 外部 Python。所有原子操作在 ida_api.py，
工具组装在 server.py。
"""
