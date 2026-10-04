# -*- coding: utf-8 -*-
"""In-daemon record of a single SSH connection."""

import threading
import time

import paramiko

from .config import format_timestamp


class Session(object):
    """Holds a connected paramiko.SSHClient plus its metadata.

    Concurrency: each command takes one slot from ``channels`` (a semaphore) and
    opens its own SSH channel; paramiko serialises the transport internally, so
    several commands can run on one connection at once. ``active_channels``
    lets the reaper avoid reaping a connection that is doing work.
    """

    def __init__(self, conn_id, client, host, port, username, connected_at,
                 encoding=None, key_path=None, auth_mode="password",
                 name=None, max_channels=10):
        self.id = conn_id
        self.client = client
        self.host = host
        self.port = port
        self.username = username
        self.name = name
        self.connected_at = connected_at
        self.last_activity = connected_at
        self.encoding = encoding          # None = auto-detect, else forced
        self.key_path = key_path
        self.auth_mode = auth_mode
        self.channels = threading.Semaphore(max_channels)
        self._count_lock = threading.Lock()
        self._active_channels = 0

    # -- lifecycle ---------------------------------------------------------

    def acquire_channel(self, timeout=None):
        return self.channels.acquire(timeout=timeout)

    def release_channel(self):
        self.channels.release()

    def enter_channel(self):
        with self._count_lock:
            self._active_channels += 1

    def leave_channel(self):
        with self._count_lock:
            self._active_channels = max(0, self._active_channels - 1)

    @property
    def busy(self):
        with self._count_lock:
            return self._active_channels > 0

    def idle_seconds(self, now=None):
        now = now if now is not None else time.time()
        return int(now - self.last_activity)

    def describe(self):
        """Readable "user@host:port" for logs (never contains secrets)."""
        return "%s@%s:%s" % (self.username, self.host, self.port)

    def transport_alive(self):
        """True while the underlying SSH transport is usable."""
        try:
            transport = self.client.get_transport()
            return transport is not None and transport.is_active()
        except (OSError, paramiko.SSHException):
            return False

    # -- reporting ---------------------------------------------------------

    def to_info(self, now=None):
        """Metadata for the ``list`` command; timestamps are ISO-8601 local."""
        return {
            "id": self.id,
            "name": self.name,
            "user": self.username,
            "host": self.host,
            "port": self.port,
            "connected_at": format_timestamp(self.connected_at),
            "idle_seconds": self.idle_seconds(now),
            "auth_mode": self.auth_mode,
            "state": "alive" if self.transport_alive() else "dead",
            "active_channels": self._active_channels,
        }

    def close(self):
        """Close the underlying paramiko client (idempotent, never raises)."""
        try:
            self.client.close()
        except (OSError, paramiko.SSHException):
            pass
