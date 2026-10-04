# -*- coding: utf-8 -*-
"""Exceptions shared by the CLI, the client and the daemon."""


class SSHConnectError(Exception):
    """Raised on SSH connect/auth/network failures.

    Messages are bilingual (readable Chinese + English) so both human users
    and logs get an actionable description.
    """


class ConnectError(SSHConnectError):
    """Connect failure carrying a machine-readable code and details.

    ``code`` is one of ``unknown_host``, ``host_key_mismatch``, ``duplicate_name``,
    ``bad_name`` or None. ``details`` may carry ``fingerprint``/``key_type``.
    """

    def __init__(self, message, code=None, details=None):
        SSHConnectError.__init__(self, message)
        self.code = code
        self.details = details or {}


class SessionError(Exception):
    """Raised for bad or unknown connection ids."""
