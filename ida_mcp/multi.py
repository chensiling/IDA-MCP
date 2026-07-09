"""Multi-instance support: internal server and Worker. No election logic.
"""
import os
import socket
import threading
import time

from . import protocol
from .registry import Registry, FileEntry

INTERNAL_PORT = 8766


class InternalServer:
    """Accepts Worker registrations over TCP."""

    def __init__(self, registry):
        self.registry = registry
        self._running = False
        self._sock = None
        self._thread = None

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
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def _accept_workers(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(target=self._handle_worker, args=(conn,),
                                     daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_worker(self, conn):
        try:
            while self._running:
                msg = protocol.recv_msg(conn)
                if msg is None:
                    break
                mt = msg.get('t')
                if mt == protocol.MSG_REGISTER:
                    entry = FileEntry(
                        fid=msg['fid'],
                        name=msg['name'],
                        arch=msg['arch'],
                        bits=msg['bits'],
                        path=msg['path'],
                        pid=msg['pid'],
                        conn=conn,
                        local=False,
                        call_port=msg.get('call_port', 0)
                    )
                    self.registry.register(entry)
                    protocol.send_msg(conn, {'t': protocol.MSG_ACK, 'ok': True})
                elif mt == protocol.MSG_UNREGISTER:
                    self.registry.unregister(msg['fid'])
                    protocol.send_msg(conn, {'t': protocol.MSG_ACK, 'ok': True})
                elif mt == protocol.MSG_HEARTBEAT:
                    protocol.send_msg(conn, {'t': protocol.MSG_HEARTBEAT})
        except Exception:
            pass
        finally:
            self.registry.unregister_conn(conn)
            try:
                conn.close()
            except Exception:
                pass


class Worker:
    """Connects to the MCP server as a Worker node."""

    def __init__(self, file_info, local_handler):
        self.file_info = file_info
        self.local_handler = local_handler
        self._conn = None
        self._running = False
        self._thread = None
        self._call_port = 0
        self._call_sock = None
        self._call_thread = None

    def start(self):
        self._running = True
        self._start_call_server()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._conn:
            try:
                protocol.send_msg(self._conn, {
                    't': protocol.MSG_UNREGISTER,
                    'fid': self.file_info['fid']
                })
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass
        if self._call_sock:
            try:
                self._call_sock.close()
            except Exception:
                pass
            self._call_sock = None
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._call_thread:
            self._call_thread.join(timeout=2.0)

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
        while self._running:
            try:
                conn, addr = self._call_sock.accept()
                t = threading.Thread(target=self._handle_call_conn,
                                     args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_call_conn(self, conn):
        try:
            msg = protocol.recv_msg(conn)
            if msg and msg.get('t') == protocol.MSG_CALL:
                result = self._handle_call(msg)
                protocol.send_msg(conn, {'t': protocol.MSG_RESULT, 'r': result})
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _run(self):
        while self._running:
            try:
                self._conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._conn.settimeout(2.0)
                self._conn.connect(('127.0.0.1', INTERNAL_PORT))
                self._conn.settimeout(1.0)
                self._register()
                self._loop()
            except (ConnectionRefusedError, OSError, TimeoutError):
                if not self._running:
                    break
                time.sleep(1.0)
            except Exception:
                if not self._running:
                    break
                time.sleep(2.0)

    def _register(self):
        protocol.send_msg(self._conn, {
            't': protocol.MSG_REGISTER,
            'fid': self.file_info['fid'],
            'name': self.file_info['name'],
            'arch': self.file_info['arch'],
            'bits': self.file_info['bits'],
            'path': self.file_info['path'],
            'pid': os.getpid(),
            'call_port': self._call_port
        })
        ack = protocol.recv_msg(self._conn)
        if not ack or not ack.get('ok'):
            raise RuntimeError('register failed')

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
