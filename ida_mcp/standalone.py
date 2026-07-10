"""Standalone MCP server process — runs outside IDA.

This is the central hub:
- HTTP MCP server on :8765 for AI clients
- Internal TCP server on :8766 for IDA Worker registrations
- Routes tool calls to the correct Worker
- Starts a cancelable shutdown after 3 seconds with no Workers connected
"""
import logging
import threading
import time

from . import _base
from .server import (
    HTTP_HOST, HTTP_PORT, mcp, require_registered_tools,
)
from .registry import Registry
from .router import Router
from .multi import InternalServer

SHUTDOWN_DEBOUNCE = 3.0
STARTUP_GRACE = 60

STATE_STARTING = "STARTING"
STATE_ACTIVE = "ACTIVE"
STATE_DRAINING = "DRAINING"
STATE_STOPPING = "STOPPING"


class StandaloneServer:
    def __init__(self):
        self.registry = Registry()
        self.router = Router(self.registry, self._local_handler)
        self._internal = InternalServer(self.registry)
        self._running = False
        self._stop_event = threading.Event()
        self._idle_thread = None
        self._uvicorn_server = None
        self._state_lock = threading.Lock()
        self._state = STATE_STARTING

    def _local_handler(self, tool, args):
        return {'error': {'code': 'NO_LOCAL', 'message':
                'No local file loaded. Use list_files to find a Worker.'}}

    def start(self):
        tool_count = require_registered_tools()
        self._running = True
        self._stop_event.clear()
        self._set_state(STATE_STARTING)
        _base._MULTI_ROUTER = self.router

        try:
            self._internal.start()
            self._idle_thread = threading.Thread(
                target=self._idle_monitor, daemon=True)
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
            self._uvicorn_server = srv
            if self._stop_event.is_set():
                srv.should_exit = True

            print(f"[ida-mcp-server] Listening on "
                  f"http://{HTTP_HOST}:{HTTP_PORT}/mcp "
                  f"({tool_count} tools)")
            srv.run()
        finally:
            self.stop()

    def stop(self):
        self._request_shutdown()
        self._internal.stop()
        idle_thread = self._idle_thread
        if (idle_thread is not None
                and idle_thread is not threading.current_thread()):
            idle_thread.join(timeout=2.0)
        self._idle_thread = None
        self._uvicorn_server = None
        if _base._MULTI_ROUTER is self.router:
            _base._MULTI_ROUTER = None

    def _request_shutdown(self):
        self.registry.stop_accepting()
        self._signal_shutdown()

    def _signal_shutdown(self):
        self._running = False
        self._set_state(STATE_STOPPING)
        self._stop_event.set()
        srv = self._uvicorn_server
        if srv is not None:
            srv.should_exit = True

    def _idle_monitor(self):
        startup_deadline = time.monotonic() + STARTUP_GRACE
        had_connections = False
        while not self._stop_event.is_set():
            count, generation, accepting = self.registry.snapshot()
            if not accepting:
                return

            if count > 0:
                had_connections = True
                self._set_state(STATE_ACTIVE)
                self.registry.wait_for_change(generation)
                continue

            now = time.monotonic()
            if had_connections:
                self._set_state(STATE_DRAINING)
                _, changed_generation, _ = self.registry.wait_for_change(
                    generation, SHUTDOWN_DEBOUNCE)
                if changed_generation != generation:
                    continue
                if self.registry.begin_shutdown_if_empty(generation):
                    print("[ida-mcp-server] No Workers connected for "
                          f"{SHUTDOWN_DEBOUNCE:g}s, shutting down")
                    self._signal_shutdown()
                    return
                continue

            remaining = startup_deadline - now
            if remaining <= 0:
                if not self.registry.begin_shutdown_if_empty(generation):
                    continue
                print("[ida-mcp-server] No Workers connected within "
                      f"{STARTUP_GRACE}s, shutting down")
                self._signal_shutdown()
                return
            self.registry.wait_for_change(generation, remaining)

    @property
    def state(self):
        with self._state_lock:
            return self._state

    def _set_state(self, state):
        with self._state_lock:
            self._state = state


def main():
    StandaloneServer().start()


if __name__ == '__main__':
    main()
