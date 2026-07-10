"""IDA-MCP 插件包：独立 MCP Server + 多 IDA Worker。

架构：
    MCP client ──HTTP──▶ ida_mcp_standalone.py
                              └─ TCP registry/router
                                  ├─ IDA Worker #1
                                  └─ IDA Worker #2

Server 由首个 IDA 使用 IDA 的 Python 解释器拉起。工具组合在 tools/，
原子操作在 ida_api/，Worker 通过 execute_sync 在 IDA 主线程执行原子。
"""
