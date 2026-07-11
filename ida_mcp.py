"""IDA-MCP 插件入口（独立 Server + Worker 架构）。

在 IDA 内嵌 Python 中启动 Worker，注册到独立的 MCP Server。
- 第一个 IDA 实例启动时，自动拉起独立 MCP Server 进程。
- 所有 IDA 实例平等——全部作为 Worker 连接。
- MCP Server 在最后一个 Worker 断连并连续空闲 3s 后发起退出。

部署：把 ida_mcp.py / ida_mcp_standalone.py / ida_mcp/ 一起复制到 plugins 目录。
"""

import os
import sys
import socket
import subprocess
import threading
import time

import idaapi
import ida_hexrays
import ida_ida
import ida_nalt

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

MCP_HTTP_PORT = 8765
MCP_INTERNAL_PORT = 8766
SERVER_LAUNCH_COOLDOWN = 3.0

_server_launch_lock = threading.Lock()
_last_server_launch = 0.0


def _probe_server():
    from ida_mcp import protocol
    from ida_mcp.runtime_contract import (
        INVALID_REGISTRATION,
        inspect_server_ack,
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    try:
        s.settimeout(0.5)
        s.connect(('127.0.0.1', MCP_INTERNAL_PORT))
        connected = True
        protocol.send_msg(s, {'t': protocol.MSG_PROBE})
        response = protocol.recv_msg(s)
        return inspect_server_ack(response)
    except (ConnectionRefusedError, OSError, TimeoutError) as ex:
        if not connected:
            return 'unreachable', {
                'code': 'SERVER_UNREACHABLE',
                'message': str(ex) or 'Server is unreachable',
            }
        return 'incompatible', {
            'code': INVALID_REGISTRATION,
            'message': f'Server probe failed after connection: {ex}',
        }
    except Exception as ex:
        return 'incompatible', {
            'code': INVALID_REGISTRATION,
            'message': f'Server probe returned an invalid response: {ex}',
        }
    finally:
        try:
            s.close()
        except Exception:
            pass


def _server_running():
    status, _ = _probe_server()
    return status == 'compatible'


def _launch_server():
    from ida_mcp.launcher import find_python_executable

    script = os.path.join(_PLUGIN_DIR, 'ida_mcp_standalone.py')
    try:
        python_executable = find_python_executable()
        subprocess.Popen(
            [python_executable, script],
            cwd=_PLUGIN_DIR,
            creationflags=subprocess.CREATE_NO_WINDOW
            if sys.platform == 'win32' else 0,
        )
        print(f"[ida-mcp] Launching server with {python_executable}")
    except Exception as e:
        print(f"[ida-mcp] Failed to launch server: {e}")
        return False
    return True


def _wait_for_server(timeout=30, return_on_unreachable=False):
    deadline = time.time() + timeout
    last = ('unreachable', {
        'code': 'SERVER_UNREACHABLE',
        'message': 'Server is unreachable',
    })
    while time.time() < deadline:
        last = _probe_server()
        if (last[0] in ('compatible', 'incompatible')
                or (return_on_unreachable and last[0] == 'unreachable')):
            return last
        time.sleep(0.5)
    return last


def _ensure_server_available():
    """Relaunch a missing Server, rate-limited within this IDA process."""
    global _last_server_launch

    status, diagnostic = _probe_server()
    if status == 'compatible':
        return True
    if status == 'incompatible':
        print(f"[ida-mcp] Incompatible Server: "
              f"{diagnostic['code']}: {diagnostic['message']}")
        return False
    if status == 'stopping':
        print("[ida-mcp] Server is stopping; waiting before reconnect")
        return False
    with _server_launch_lock:
        status, diagnostic = _probe_server()
        if status == 'compatible':
            return True
        if status != 'unreachable':
            if status == 'incompatible':
                print(f"[ida-mcp] Incompatible Server: "
                      f"{diagnostic['code']}: {diagnostic['message']}")
            return False
        now = time.monotonic()
        if now - _last_server_launch < SERVER_LAUNCH_COOLDOWN:
            return False
        _last_server_launch = now
        print("[ida-mcp] Server unavailable, relaunching...")
        return _launch_server()


def _collect_file_info():
    from ida_mcp._base import get_file_id
    path = ida_nalt.get_input_file_path()
    if not path:
        return None
    try:
        hexrays = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays = False
    return {
        'fid': get_file_id(path),
        'name': os.path.basename(path),
        'arch': ida_ida.inf_get_procname().strip(),
        'bits': 64 if ida_ida.inf_is_64bit() else 32,
        'path': path,
        'hexrays': hexrays,
    }


def _collect_on_main():
    box = {}
    def _do():
        try:
            box['value'] = _collect_file_info()
        except Exception as e:
            box['error'] = e
        return 1
    status = idaapi.execute_sync(_do, idaapi.MFF_READ)
    if status == -1 or ("value" not in box and "error" not in box):
        raise RuntimeError("failed to collect file information on IDA main thread")
    if 'error' in box:
        raise box['error']
    return box.get('value')


class _WorkerThread(threading.Thread):

    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()
        self._worker = None

    def run(self):
        worker = None
        try:
            file_info = None
            while file_info is None:
                if self._stop_event.is_set():
                    return
                file_info = _collect_on_main()
                if file_info is None and self._stop_event.wait(1.0):
                    return

            from ida_mcp.server import execute_tool
            from ida_mcp.multi import Worker

            worker = Worker(
                file_info,
                execute_tool,
                ensure_server=_ensure_server_available,
            )
            with self._state_lock:
                if self._stop_event.is_set():
                    return
                self._worker = worker
                worker.start()
            print(f"[ida-mcp] Worker | {file_info['name']} "
                  f"({file_info['fid']})")

            self._stop_event.wait()
        except Exception as e:
            import traceback
            print(f"[ida-mcp] Worker error: {e}")
            traceback.print_exc()
        finally:
            cleanup = None
            with self._state_lock:
                if self._worker is worker:
                    cleanup = self._worker
                    self._worker = None
            if cleanup is not None:
                try:
                    cleanup.stop()
                except Exception:
                    pass

    def stop(self):
        self._stop_event.set()
        with self._state_lock:
            worker = self._worker
            self._worker = None
        if worker is not None:
            try:
                worker.stop()
            except Exception:
                pass
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=5.0)


class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IDA MCP"
    comment = "Worker for the standalone IDA-MCP server"
    wanted_hotkey = ""
    help = ""

    def init(self):
        status, diagnostic = _probe_server()
        if status == 'stopping':
            print("[ida-mcp] Existing Server is stopping; waiting...")
            status, diagnostic = _wait_for_server(return_on_unreachable=True)
        if status == 'stopping':
            print("[ida-mcp] Server is still stopping; Worker startup deferred")
            return idaapi.PLUGIN_KEEP
        if status == 'incompatible':
            print(f"[ida-mcp] Incompatible Server: "
                  f"{diagnostic['code']}: {diagnostic['message']}")
            return idaapi.PLUGIN_KEEP
        if status == 'unreachable':
            print("[ida-mcp] No server found, launching...")
            if not _launch_server():
                print("[ida-mcp] Failed to launch server")
                return idaapi.PLUGIN_KEEP
            status, diagnostic = _wait_for_server()
            if status != 'compatible':
                print(f"[ida-mcp] Server did not become compatible: "
                      f"{diagnostic['code']}: {diagnostic['message']}")
                return idaapi.PLUGIN_KEEP
            print("[ida-mcp] Server started")

        self.worker_thread = _WorkerThread()
        self.worker_thread.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        worker_thread = getattr(self, "worker_thread", None)
        self.worker_thread = None
        if worker_thread is not None:
            worker_thread.stop()
            print("[ida-mcp] Worker shutdown requested")


def PLUGIN_ENTRY():
    return IDAMCPPlugin()
