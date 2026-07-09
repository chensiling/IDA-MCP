"""IDA-MCP 插件入口（独立 Server + Worker 架构）。

在 IDA 内嵌 Python 中启动 Worker，注册到独立的 MCP Server。
- 第一个 IDA 实例启动时，自动拉起独立 MCP Server 进程。
- 所有 IDA 实例平等——全部作为 Worker 连接。
- MCP Server 在最后一个 Worker 断连 30s 后自动退出。

部署：把 ida_mcp.py / ida_mcp_standalone.py / ida_mcp/ 一起复制到 plugins 目录。
"""

import os
import sys
import socket
import subprocess
import threading
import time

import idaapi
import ida_ida
import ida_nalt
import ida_kernwin

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

MCP_HTTP_PORT = 8765
MCP_INTERNAL_PORT = 8766


def _server_running():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.5)
        s.connect(('127.0.0.1', MCP_INTERNAL_PORT))
        return True
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _launch_server():
    script = os.path.join(_PLUGIN_DIR, 'ida_mcp_standalone.py')
    try:
        subprocess.Popen(
            [sys.executable, script],
            creationflags=subprocess.CREATE_NO_WINDOW
            if sys.platform == 'win32' else 0,
        )
    except Exception as e:
        print(f"[ida-mcp] Failed to launch server: {e}")
        return False
    return True


def _wait_for_server(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _server_running():
            return True
        time.sleep(0.5)
    return False


def _collect_file_info():
    from ida_mcp._base import get_file_id
    path = ida_nalt.get_input_file_path()
    if not path:
        return None
    return {
        'fid': get_file_id(path),
        'name': os.path.basename(path),
        'arch': ida_ida.inf_get_procname().strip(),
        'bits': 64 if ida_ida.inf_is_64bit() else 32,
        'path': path,
    }


def _collect_on_main():
    box = {}
    def _do():
        try:
            box['value'] = _collect_file_info()
        except Exception as e:
            box['error'] = e
        return 1
    idaapi.execute_sync(_do, idaapi.MFF_READ)
    if 'error' in box:
        raise box['error']
    return box.get('value')


class _WorkerThread(threading.Thread):

    def __init__(self, dialog_suppressor):
        super().__init__(daemon=True)
        self._dialog_suppressor = dialog_suppressor
        self._worker = None

    def run(self):
        try:
            file_info = None
            for _ in range(30):
                file_info = _collect_on_main()
                if file_info is not None:
                    break
                time.sleep(1)
            if file_info is None:
                print("[ida-mcp] Timed out waiting for file to load")
                return

            from ida_mcp.server import execute_tool
            from ida_mcp.multi import Worker

            self._worker = Worker(file_info, execute_tool)
            self._worker.start()
            print(f"[ida-mcp] Worker | {file_info['name']} "
                  f"({file_info['fid']})")

            while self._worker._running:
                time.sleep(1)
        except Exception as e:
            import traceback
            print(f"[ida-mcp] Worker error: {e}")
            traceback.print_exc()

    def stop(self):
        if self._worker:
            try:
                self._worker.stop()
            except Exception:
                pass
            self._worker = None


class _SuppressDialogs(ida_kernwin.UI_Hooks):
    def ask_yn(self, deflt, fmt):
        return 1
    def ask_buttons(self, yes_text, no_text, cancel_text, deflt, fmt):
        return 1


_dialog_suppressor = None


class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IDA MCP"
    comment = "In-process MCP server for AI-assisted reverse engineering"
    wanted_hotkey = ""
    help = ""

    def init(self):
        global _dialog_suppressor
        if _dialog_suppressor is None:
            _dialog_suppressor = _SuppressDialogs()
            _dialog_suppressor.hook()

        if not _server_running():
            print("[ida-mcp] No server found, launching...")
            if not _launch_server():
                print("[ida-mcp] Failed to launch server")
                return idaapi.PLUGIN_KEEP
            if not _wait_for_server():
                print("[ida-mcp] Server did not start in time")
                return idaapi.PLUGIN_KEEP
            print("[ida-mcp] Server started")

        self.worker_thread = _WorkerThread(_dialog_suppressor)
        self.worker_thread.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if getattr(self, "worker_thread", None) is not None:
            self.worker_thread.stop()
            print("[ida-mcp] Worker shutdown requested")


def PLUGIN_ENTRY():
    return IDAMCPPlugin()
