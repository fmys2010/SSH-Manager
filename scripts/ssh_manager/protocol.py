# -*- coding: utf-8 -*-
"""Length-prefixed JSON framing shared by the daemon and its clients."""

import json
import socket
import struct

from .config import MAX_FRAME_BYTES

_HEADER = struct.Struct(">I")


class ProtocolError(Exception):
    """Raised for malformed, oversized or undeserializable frames."""


def recv_exact(sock, n):
    """Read exactly ``n`` bytes.

    Returns ``None`` on EOF or connection error. ``socket.timeout`` is
    re-raised so callers can distinguish "no data yet" from "peer is gone".
    """
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def send_frame(sock, obj):
    """Serialize ``obj`` as one length-prefixed JSON frame and send it."""
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    sock.sendall(_HEADER.pack(len(body)) + body)


def recv_frame(sock, max_bytes=MAX_FRAME_BYTES):
    """Read one frame and return the decoded object, or None on EOF.

    Raises ProtocolError when the frame is oversized or not valid JSON.
    """
    header = recv_exact(sock, _HEADER.size)
    if header is None:
        return None
    (length,) = _HEADER.unpack(header)
    if length > max_bytes:
        raise ProtocolError("frame too large: %d bytes (limit %d)" % (length, max_bytes))
    body = recv_exact(sock, length)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("malformed frame: %s" % exc)
