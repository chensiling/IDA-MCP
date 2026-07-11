"""Multi-instance support: internal server and Worker. No election logic.
"""
import os
import socket
import threading
import time

from . import protocol
from .registry import FileEntry
from .runtime_contract import (
    ALL_TOOL_NAMES,
    IMPLEMENTATION_VERSION,
    INVALID_REGISTRATION,
    PROTOCOL_VERSION,
    READ_TOOL_NAMES,
    SERVER_STOPPING,
    TOOL_MANIFEST_SHA256,
    ContractError,
    ack_envelope,
    inspect_server_ack,
    read_only_error,
    read_only_from_environment,
    unknown_tool_error,
    validate_registration,
    worker_capabilities,
)

INTERNAL_PORT = 8766
FIRST_FRAME_TIMEOUT = 5.0
CONTROL_IDLE_TIMEOUT = 15.0
MAX_WORKER_CONNECTIONS = 64
MAX_CALL_CONNECTIONS = 16
ENSURE_SERVER_FAILURE_THRESHOLD = 3
ENSURE_SERVER_COOLDOWN = 5.0
WORKER_FILE_INFO_FIELDS = frozenset({
    'fid', 'name', 'arch', 'bits', 'path', 'hexrays',
})


class IncompatibleServerError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class ServerStoppingError(RuntimeError):
    def __init__(self, message):
        self.code = SERVER_STOPPING
        self.message = message
        super().__init__(f"{SERVER_STOPPING}: {message}")


class InternalServer:
    """Accepts Worker registrations over TCP."""

    def __init__(self, registry):
        self.registry = registry
        self._running = False
        self._sock = None
        self._thread = None
        self._connections = set()
        self._connections_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_WORKER_CONNECTIONS)

    def start(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', INTERNAL_PORT))
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        self._thread = threading.Thread(target=self._accept_workers, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        sock = self._sock
        self._sock = None
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        with self._connections_lock:
            connections = list(self._connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        thread = self._thread
        self._thread = None
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def _accept_workers(self):
        listen_sock = self._sock
        while self._running:
            try:
                conn, _ = listen_sock.accept()
                conn.settimeout(FIRST_FRAME_TIMEOUT)
                if not self._slots.acquire(blocking=False):
                    conn.close()
                    continue
                with self._connections_lock:
                    self._connections.add(conn)
                try:
                    t = threading.Thread(
                        target=self._handle_worker, args=(conn,), daemon=True)
                    t.start()
                except Exception:
                    with self._connections_lock:
                        self._connections.discard(conn)
                    self._slots.release()
                    conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_worker(self, conn):
        try:
            msg = protocol.recv_msg(conn)
            if isinstance(msg, dict) and msg.get('t') == protocol.MSG_PROBE:
                if set(msg) != {'t'}:
                    self._send_contract_ack(
                        conn, False, INVALID_REGISTRATION,
                        'probe fields do not match the protocol contract')
                    return
                if self.registry.is_accepting():
                    self._send_contract_ack(conn, True)
                else:
                    self._send_contract_ack(
                        conn, False, SERVER_STOPPING,
                        'server is stopping', state='stopping')
                return
            if not isinstance(msg, dict) or msg.get('t') != protocol.MSG_REGISTER:
                self._send_contract_ack(
                    conn, False, INVALID_REGISTRATION,
                    'first message must be register')
                return
            try:
                entry = self._entry_from_register(msg, conn)
            except ContractError as ex:
                self._send_contract_ack(
                    conn, False, ex.code, ex.message)
                return
            if not self.registry.register(entry):
                self._send_contract_ack(
                    conn, False, SERVER_STOPPING,
                    'server is stopping', state='stopping')
                return
            self._send_contract_ack(conn, True)
            conn.settimeout(CONTROL_IDLE_TIMEOUT)

            while self._running:
                msg = protocol.recv_msg(conn)
                if msg is None:
                    break
                if not isinstance(msg, dict):
                    break
                mt = msg.get('t')
                if mt == protocol.MSG_UNREGISTER:
                    removed = self.registry.unregister(
                        msg.get('fid'), conn=conn)
                    self._send_ack(conn, removed is not None,
                                   None if removed is not None
                                   else 'registration is not owned by connection')
                    break
                elif mt == protocol.MSG_HEARTBEAT:
                    protocol.send_msg(conn, {'t': protocol.MSG_HEARTBEAT})
                else:
                    break
        except Exception:
            pass
        finally:
            self.registry.unregister_conn(conn)
            with self._connections_lock:
                self._connections.discard(conn)
            try:
                conn.close()
            except Exception:
                pass
            self._slots.release()

    @staticmethod
    def _send_ack(conn, ok, error=None):
        payload = {'t': protocol.MSG_ACK, 'ok': ok}
        if error:
            payload['error'] = error
        try:
            protocol.send_msg(conn, payload)
        except Exception:
            pass

    @staticmethod
    def _send_contract_ack(conn, ok, code=None, message=None,
                           state='running'):
        try:
            protocol.send_msg(conn, ack_envelope(
                ok, code=code, message=message, state=state))
        except Exception:
            pass

    @staticmethod
    def _entry_from_register(msg, conn):
        metadata = validate_registration(msg)
        return FileEntry(
            fid=msg['fid'], name=msg['name'], arch=msg['arch'],
            bits=msg['bits'], path=msg['path'], pid=msg['pid'], conn=conn,
            local=False, call_port=msg['call_port'], **metadata)


class Worker:
    """Connects to the MCP server as a Worker node."""

    def __init__(self, file_info, local_handler, ensure_server=None):
        if not isinstance(file_info, dict) or set(file_info) != WORKER_FILE_INFO_FIELDS:
            raise ValueError(
                'file_info must contain exactly fid/name/arch/bits/path/hexrays')
        if type(file_info['hexrays']) is not bool:
            raise ValueError('file_info hexrays must be a boolean')
        self.file_info = dict(file_info)
        self.local_handler = local_handler
        self.ensure_server = ensure_server
        self._read_only = read_only_from_environment()
        self._capabilities = worker_capabilities(
            self._read_only, self.file_info['hexrays'])
        self._conn = None
        self._conn_lock = threading.Lock()
        self._running = False
        self._thread = None
        self._call_port = 0
        self._call_sock = None
        self._call_thread = None
        self._call_connections = set()
        self._call_connections_lock = threading.Lock()
        self._call_slots = threading.BoundedSemaphore(MAX_CALL_CONNECTIONS)
        self._connection_failures = 0
        self._last_ensure_attempt = 0.0
        self._terminal_error = None

    @property
    def read_only(self):
        return self._read_only

    @property
    def capabilities(self):
        return dict(self._capabilities)

    @property
    def terminal_error(self):
        return self._terminal_error

    def start(self):
        from .server import require_registered_tools
        require_registered_tools()
        with self._conn_lock:
            self._running = True
        self._start_call_server()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        with self._conn_lock:
            self._running = False
            conn = self._conn
            self._conn = None
        if conn:
            try:
                protocol.send_msg(conn, {
                    't': protocol.MSG_UNREGISTER,
                    'fid': self.file_info['fid']
                })
            except Exception:
                pass
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        self._close_call_server()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        if (self._call_thread
                and self._call_thread is not threading.current_thread()):
            self._call_thread.join(timeout=2.0)

    def _close_call_server(self):
        call_sock = self._call_sock
        self._call_sock = None
        if call_sock:
            try:
                call_sock.close()
            except Exception:
                pass
        with self._call_connections_lock:
            call_connections = list(self._call_connections)
        for call_conn in call_connections:
            try:
                call_conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                call_conn.close()
            except Exception:
                pass

    def _start_call_server(self):
        self._call_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._call_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._call_sock.bind(('127.0.0.1', 0))
        self._call_port = self._call_sock.getsockname()[1]
        self._call_sock.listen(16)
        self._call_sock.settimeout(1.0)
        self._call_thread = threading.Thread(target=self._accept_calls,
                                             daemon=True)
        self._call_thread.start()

    def _accept_calls(self):
        listen_sock = self._call_sock
        while self._running:
            try:
                conn, _ = listen_sock.accept()
                conn.settimeout(FIRST_FRAME_TIMEOUT)
                if not self._call_slots.acquire(blocking=False):
                    conn.close()
                    continue
                with self._call_connections_lock:
                    self._call_connections.add(conn)
                try:
                    t = threading.Thread(target=self._handle_call_conn,
                                         args=(conn,), daemon=True)
                    t.start()
                except Exception:
                    with self._call_connections_lock:
                        self._call_connections.discard(conn)
                    self._call_slots.release()
                    conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_call_conn(self, conn):
        try:
            msg = protocol.recv_msg(conn)
            if isinstance(msg, dict) and msg.get('t') == protocol.MSG_CALL:
                result = self._handle_call(msg)
                protocol.send_msg(conn, {'t': protocol.MSG_RESULT, 'r': result})
        except Exception:
            pass
        finally:
            with self._call_connections_lock:
                self._call_connections.discard(conn)
            try:
                conn.close()
            except Exception:
                pass
            self._call_slots.release()

    def _run(self):
        while self._running:
            conn = None
            retry_delay = 1.0
            count_failure = True
            terminal = False
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(2.0)
                with self._conn_lock:
                    if not self._running:
                        return
                    self._conn = conn
                conn.connect(('127.0.0.1', INTERNAL_PORT))
                conn.settimeout(1.0)
                self._register()
                self._connection_failures = 0
                self._loop()
            except ServerStoppingError as ex:
                if not self._running:
                    break
                self._connection_failures = 0
                count_failure = False
                retry_delay = 1.0
                print(f"[ida-mcp] {ex}; waiting for Server replacement")
            except IncompatibleServerError as ex:
                self._terminal_error = {
                    'code': ex.code,
                    'message': ex.message,
                }
                count_failure = False
                terminal = True
                with self._conn_lock:
                    self._running = False
                self._close_call_server()
                print(f"[ida-mcp] Incompatible Server: {ex}")
            except (ConnectionRefusedError, OSError, TimeoutError):
                if not self._running:
                    break
                retry_delay = 1.0
            except Exception:
                if not self._running:
                    break
                retry_delay = 2.0
            finally:
                with self._conn_lock:
                    if self._conn is conn:
                        self._conn = None
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
            if not self._running:
                break
            if terminal:
                break
            if count_failure:
                self._connection_failures += 1
                self._maybe_ensure_server()
            time.sleep(retry_delay)

    def _maybe_ensure_server(self):
        if (self.ensure_server is None
                or self._connection_failures < ENSURE_SERVER_FAILURE_THRESHOLD):
            return
        now = time.monotonic()
        if now - self._last_ensure_attempt < ENSURE_SERVER_COOLDOWN:
            return
        self._last_ensure_attempt = now
        self._connection_failures = 0
        try:
            self.ensure_server()
        except Exception:
            pass

    def _register(self):
        protocol.send_msg(self._conn, {
            't': protocol.MSG_REGISTER,
            'fid': self.file_info['fid'],
            'name': self.file_info['name'],
            'arch': self.file_info['arch'],
            'bits': self.file_info['bits'],
            'path': self.file_info['path'],
            'pid': os.getpid(),
            'call_port': self._call_port,
            'protocol_version': PROTOCOL_VERSION,
            'implementation_version': IMPLEMENTATION_VERSION,
            'tool_manifest_sha256': TOOL_MANIFEST_SHA256,
            'read_only': self._read_only,
            'capabilities': dict(self._capabilities),
        })
        ack = protocol.recv_msg(self._conn)
        status, error = inspect_server_ack(ack)
        if status == 'compatible':
            return
        if status == 'stopping':
            raise ServerStoppingError(error['message'])
        raise IncompatibleServerError(error['code'], error['message'])

    def _loop(self):
        while self._running:
            try:
                msg = protocol.recv_msg(self._conn)
            except socket.timeout:
                if not self._heartbeat():
                    break
                continue
            except OSError:
                msg = None
            if msg is None:
                break
            mt = msg.get('t')
            if mt == protocol.MSG_HEARTBEAT:
                try:
                    protocol.send_msg(self._conn, {'t': protocol.MSG_HEARTBEAT})
                except Exception:
                    break

    def _handle_call(self, msg):
        tool = msg.get('tool', '')
        args = msg.get('args', {})
        if not isinstance(tool, str) or tool not in ALL_TOOL_NAMES:
            return unknown_tool_error(tool)
        if self._read_only and tool not in READ_TOOL_NAMES:
            return read_only_error(tool)
        try:
            return self.local_handler(tool, args)
        except Exception as ex:
            return {'error': {'code': 'WORKER_ERROR', 'message': str(ex)}}

    def _heartbeat(self):
        try:
            protocol.send_msg(self._conn, {'t': protocol.MSG_HEARTBEAT})
            resp = protocol.recv_msg(self._conn)
            return bool(resp and resp.get('t') == protocol.MSG_HEARTBEAT)
        except Exception:
            return False
