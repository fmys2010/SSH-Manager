# -*- coding: utf-8 -*-
"""Exceptions shared by the CLI, the client and the daemon."""


class SSHConnectError(Exception):
    """Raised on SSH connect/auth/network failures.

    Messages are bilingual (readable Chinese + English) so both human users
    and logs get an actionable description.
    """


class SessionError(Exception):
    """Raised for bad or unknown connection ids."""
