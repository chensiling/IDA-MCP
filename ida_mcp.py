"""IDA-MCP 插件入口（单进程架构）。

在 IDA 内嵌 Python 中，用后台线程启动一个 HTTP MCP Server（FastMCP streamable-http）。
opencode 以 remote URL 连接：http://127.0.0.1:8765/mcp

部署：把本文件 ida_mcp.py 与同名文件夹 ida_mcp/ 一起复制到 IDA 的 plugins 目录：
    plugins/
    ├── ida_mcp.py      ← 本文件
    └── ida_mcp/        ← 包（server.py / _base.py / ida_api/ / tools/ / categories.py）

IDA 启动时自动加载 PLUGIN_ENTRY，无需外部进程或 MCP 客户端启动任何脚本。
"""

import os
import sys
import threading

import idaapi

# 确保能 import 同目录下的 ida_mcp 包（plugins 目录未必在 sys.path）
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)


class _ServerThread(threading.Thread):
    """后台线程运行 uvicorn，托管 FastMCP 的 streamable-http ASGI app。"""

    def __init__(self):
        super().__init__(daemon=True)
        self._server = None

    def run(self):
        try:
            import logging
            import uvicorn
            from ida_mcp.server import mcp, HTTP_HOST, HTTP_PORT

            # 抑制 mcp / uvicorn / starlette 的 INFO 日志，只保留 WARNING 及以上，
            # 避免在 IDA Output 窗口刷屏（如 "Created new transport" /
            # "Processing request of type" 等）。
            for _name in ("mcp", "uvicorn", "uvicorn.error", "uvicorn.access",
                          "starlette", "sse_starlette"):
                logging.getLogger(_name).setLevel(logging.WARNING)

            app = mcp.streamable_http_app()
            config = uvicorn.Config(
                app,
                host=HTTP_HOST,
                port=HTTP_PORT,
                log_level="warning",
                # 后台线程中运行，禁用信号处理（仅主线程可注册信号）
                lifespan="on",
            )
            self._server = uvicorn.Server(config)
            self._server.install_signal_handlers = lambda: None
            print(f"[ida-mcp] MCP server starting on "
                  f"http://{HTTP_HOST}:{HTTP_PORT}/mcp")
            self._server.run()
            print("[ida-mcp] MCP server stopped")
        except Exception as e:  # noqa: BLE001
            print(f"[ida-mcp] MCP server error: {e}")

    def stop(self):
        if self._server is not None:
            # uvicorn 优雅停止：置标志位，其事件循环会退出
            self._server.should_exit = True


class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IDA MCP"
    comment = "In-process MCP server for AI-assisted reverse engineering"
    wanted_hotkey = ""
    help = ""

    def init(self):
        self.server_thread = _ServerThread()
        self.server_thread.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if getattr(self, "server_thread", None) is not None:
            self.server_thread.stop()
            print("[ida-mcp] MCP server shutdown requested")


def PLUGIN_ENTRY():
    return IDAMCPPlugin()
