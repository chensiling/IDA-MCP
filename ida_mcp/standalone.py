"""Standalone MCP server process — runs outside IDA.

This is the central hub:
- HTTP MCP server on :8765 for AI clients
- Internal TCP server on :8766 for IDA Worker registrations
- Routes tool calls to the correct Worker
- Auto-exits after IDLE_TIMEOUT seconds with no Workers connected
"""
import logging
import threading
import time

from . import _base
from ._base import (
    mcp, HTTP_HOST, HTTP_PORT, format_output,
    INTERNAL_PORT,
)
from .registry import Registry
from .router import Router
from .multi import InternalServer

IDLE_TIMEOUT = 30
STARTUP_GRACE = 60


class StandaloneServer:
    def __init__(self):
        self.registry = Registry()
        self.router = Router(self.registry, self._local_handler)
        self._internal = InternalServer(self.registry)
        self._running = False
        self._idle_thread = None
        self._had_connections = False

    def _local_handler(self, tool, args):
        return {'error': {'code': 'NO_LOCAL', 'message':
                'No local file loaded. Use list_files to find a Worker.'}}

    def start(self):
        self._running = True
        _base._MULTI_ROUTER = self.router

        self._internal.start()
        self._idle_thread = threading.Thread(target=self._idle_monitor,
                                             daemon=True)
        self._idle_thread.start()

        for _name in ("mcp", "uvicorn", "uvicorn.error", "uvicorn.access",
                       "starlette", "sse_starlette"):
            logging.getLogger(_name).setLevel(logging.WARNING)

        import uvicorn
        app = mcp.streamable_http_app()
        config = uvicorn.Config(app, host=HTTP_HOST, port=HTTP_PORT,
                                log_level="warning", lifespan="on")
        srv = uvicorn.Server(config)
        srv.install_signal_handlers = lambda: None

        print(f"[ida-mcp-server] Listening on http://{HTTP_HOST}:{HTTP_PORT}/mcp")
        try:
            srv.run()
        finally:
            self.stop()

    def stop(self):
        self._running = False
        self._internal.stop()

    def _idle_monitor(self):
        deadline = time.time() + STARTUP_GRACE
        while self._running:
            time.sleep(5)
            count = self.registry.count()
            if count > 0:
                self._had_connections = True
            if self._had_connections and count == 0:
                remaining = IDLE_TIMEOUT
                while remaining > 0 and self._running:
                    time.sleep(5)
                    remaining -= 5
                    if self.registry.count() > 0:
                        break
                else:
                    print("[ida-mcp-server] No Workers connected, shutting down")
                    self._running = False
                    return
            if time.time() > deadline and count == 0:
                print("[ida-mcp-server] No Workers connected within "
                      f"{STARTUP_GRACE}s, shutting down")
                self._running = False
                return


def main():
    StandaloneServer().start()


if __name__ == '__main__':
    main()
