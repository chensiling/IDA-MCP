"""Request router - dispatches tool calls to the correct IDA instance."""
import socket

from . import protocol
from .registry import FileEntry

_NO_FILE_TOOLS = frozenset()
WORKER_CONNECT_TIMEOUT = 5.0
WORKER_RESPONSE_TIMEOUT = 300.0


class Router:
    def __init__(self, registry, local_handler):
        self.registry = registry
        self.local_handler = local_handler

    def dispatch(self, tool, fid, args):
        if tool == 'list_files':
            return self._list_files()

        if not fid:
            entries = self.registry.list_all()
            if len(entries) == 1:
                fid = entries[0].fid
            else:
                return {'error': {
                    'code': 'MULTI_FILE',
                    'message': "Multiple IDA instances are connected. "
                               "Use list_files to see available files, "
                               "then specify the 'f' parameter."}}

        entry = self.registry.get(fid)
        if not entry:
            return {'error': {
                'code': 'UNKNOWN_FILE',
                'message': f"Unknown file_id '{fid}'. "
                           f"Use list_files to see available files."}}

        if entry.local:
            return self.local_handler(tool, args)
        else:
            return self._call_remote(entry, tool, args)

    def _list_files(self):
        entries = self.registry.list_all()
        return [
            {'fid': e.fid, 'name': e.name, 'arch': e.arch,
             'bits': e.bits, 'path': e.path}
            for e in entries
        ]

    def _call_remote(self, entry, tool, args):
        worker_port = entry.call_port
        if not worker_port:
            return {'error': {'code': 'WORKER_ERROR',
                              'message': 'worker has no call port'}}
        request_started = False
        try:
            with socket.create_connection(
                    ('127.0.0.1', worker_port),
                    timeout=WORKER_CONNECT_TIMEOUT) as sock:
                sock.settimeout(WORKER_RESPONSE_TIMEOUT)
                request_started = True
                protocol.send_msg(sock, {
                    't': protocol.MSG_CALL,
                    'tool': tool,
                    'args': args
                })
                resp = protocol.recv_msg(sock)
            if resp is None:
                return {'error': {'code': 'WORKER_ERROR',
                                  'message': 'worker no response'}}
            if not isinstance(resp, dict) or resp.get('t') != protocol.MSG_RESULT:
                return {'error': {'code': 'WORKER_ERROR',
                                  'message': 'invalid worker response'}}
            return resp.get('r', {'error': {'code': 'WORKER_ERROR',
                                            'message': 'no result'}})
        except TimeoutError:
            if request_started:
                return {'error': {
                    'code': 'RESULT_UNKNOWN',
                    'message': 'Worker response timed out after the request '
                               'started. The operation may have completed; '
                               'verify state before retrying.'}}
            return {'error': {'code': 'WORKER_TIMEOUT',
                              'message': 'Timed out connecting to worker.'}}
        except Exception as ex:
            return {'error': {'code': 'WORKER_ERROR', 'message': str(ex)}}
