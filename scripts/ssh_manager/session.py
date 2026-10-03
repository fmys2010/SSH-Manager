# -*- coding: utf-8 -*-
"""In-daemon record of a single SSH connection."""

import threading
import time

import paramiko

from .config import format_timestamp
from .encoding import AdaptiveDecoder


class Session(object):
    """Holds a connected paramiko.SSHClient plus its metadata."""

    def __init__(self, conn_id, client, host, port, username, connected_at,
                 decoder, key_path=None, auth_mode="password"):
        self.id = conn_id
        self.client = client
        self.host = host
        self.port = port
        self.username = username
        self.connected_at = connected_at
        self.last_activity = connected_at
        # One decoder per stream: stdout and stderr are independent byte
        # streams, so sharing a decoder lets a multi-byte character split
        # across them corrupt the output.
        self.decoder = decoder
        self.stderr_decoder = AdaptiveDecoder(encoding=getattr(decoder, "encoding", None))
        self.key_path = key_path
        self.auth_mode = auth_mode
        self.lock = threading.Lock()   # serializes execs on this connection
        self.busy = False              # True while an exec is in flight

    def idle_seconds(self, now=None):
        now = now if now is not None else time.time()
        return int(now - self.last_activity)

    def describe(self):
        """Readable "user@host:port" for logs (never contains secrets)."""
        return "%s@%s:%s" % (self.username, self.host, self.port)

    def decoder_for(self, stream):
        """Decoder for a protocol stream name ("stdout" / "stderr")."""
        return self.stderr_decoder if stream == "stderr" else self.decoder

    def reset_decoders(self):
        """Start a fresh encoding decision for both streams."""
        self.decoder.reset()
        self.stderr_decoder.reset()

    def flush_decoders(self):
        """Finalize both streams; returns [(stream, text), ...] for non-empty tails."""
        tails = []
        for stream, decoder in (("stdout", self.decoder), ("stderr", self.stderr_decoder)):
            text = decoder.flush()
            if text:
                tails.append((stream, text))
        return tails

    def to_info(self, now=None):
        """Metadata for the ``list`` command; timestamps are ISO-8601 local."""
        return {
            "id": self.id,
            "user": self.username,
            "host": self.host,
            "port": self.port,
            "connected_at": format_timestamp(self.connected_at),
            "idle_seconds": self.idle_seconds(now),
            "auth_mode": self.auth_mode,
        }

    def close(self):
        """Close the underlying paramiko client (idempotent, never raises)."""
        try:
            self.client.close()
        except (OSError, paramiko.SSHException):
            pass
