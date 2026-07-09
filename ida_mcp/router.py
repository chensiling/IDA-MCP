"""Request router - dispatches tool calls to the correct IDA instance."""
import socket

from . import protocol
from .registry import FileEntry

_NO_FILE_TOOLS = frozenset()


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
        return [[e.fid, e.name, e.arch, e.bits, e.path] for e in entries]

    def _call_remote(self, entry, tool, args):
        worker_port = entry.call_port
        if not worker_port:
            return {'error': {'code': 'WORKER_ERROR',
                              'message': 'worker has no call port'}}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60.0)
            sock.connect(('127.0.0.1', worker_port))
            protocol.send_msg(sock, {
                't': protocol.MSG_CALL,
                'tool': tool,
                'args': args
            })
            resp = protocol.recv_msg(sock)
            sock.close()
            if resp is None:
                return {'error': {'code': 'WORKER_ERROR',
                                  'message': 'worker no response'}}
            return resp.get('r', {'error': {'code': 'WORKER_ERROR',
                                            'message': 'no result'}})
        except Exception as ex:
            return {'error': {'code': 'WORKER_ERROR', 'message': str(ex)}}
