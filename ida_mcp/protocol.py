"""Internal TCP protocol for Master <-> Worker communication.
Wire format: [4-byte big-endian length][JSON payload]
"""
import json
import struct

HEADER_SIZE = 4


def send_msg(sock, obj):
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    sock.sendall(struct.pack('>I', len(data)) + data)


def recv_msg(sock):
    hdr = _recv_exact(sock, HEADER_SIZE)
    if not hdr:
        return None
    length = struct.unpack('>I', hdr)[0]
    if length == 0:
        return {}
    data = _recv_exact(sock, length)
    if not data:
        return None
    return json.loads(data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


MSG_REGISTER = 'R'
MSG_UNREGISTER = 'U'
MSG_CALL = 'C'
MSG_RESULT = 'S'
MSG_PROMOTE = 'P'
MSG_PROMOTED = 'D'
MSG_HEARTBEAT = 'H'
MSG_ACK = 'A'
