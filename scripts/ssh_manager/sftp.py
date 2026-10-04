# -*- coding: utf-8 -*-
"""SFTP operations: upload, download and basic remote file management.

Each operation opens a short-lived SFTP channel on the session's transport and
closes it afterwards, so SFTP can run alongside exec channels on the same
connection.
"""

import os
import stat as stat_module

from .config import format_timestamp


class SFTPError(Exception):
    """Raised when an SFTP operation fails."""


def _open(session):
    transport = session.client.get_transport()
    if transport is None or not transport.is_active():
        raise SFTPError("connection closed: %s" % session.describe())
    try:
        return transport.open_sftp_client()
    except Exception as exc:
        raise SFTPError("cannot open sftp channel: %s" % exc)


def _entry(attrs, name=None):
    mode = attrs.st_mode or 0
    return {
        "name": name,
        "size": attrs.st_size or 0,
        "mode": oct(mode & 0o777),
        "is_dir": stat_module.S_ISDIR(mode),
        "mtime": format_timestamp(attrs.st_mtime) if attrs.st_mtime else None,
    }


def put(session, local_path, remote_path):
    if not os.path.isfile(local_path):
        raise SFTPError("local file not found: %s" % local_path)
    sftp = _open(session)
    try:
        sftp.put(local_path, remote_path)
        size = os.path.getsize(local_path)
    except Exception as exc:
        raise SFTPError("put failed: %s" % exc)
    finally:
        sftp.close()
    return {"operation": "put", "local": local_path, "remote": remote_path, "bytes": size}


def get(session, remote_path, local_path):
    sftp = _open(session)
    try:
        sftp.get(remote_path, local_path)
        size = os.path.getsize(local_path)
    except Exception as exc:
        raise SFTPError("get failed: %s" % exc)
    finally:
        sftp.close()
    return {"operation": "get", "remote": remote_path, "local": local_path, "bytes": size}


def ls(session, path="."):
    sftp = _open(session)
    try:
        entries = sftp.listdir_attr(path)
    except Exception as exc:
        raise SFTPError("ls failed: %s" % exc)
    finally:
        sftp.close()
    return {"operation": "ls", "path": path,
            "entries": [_entry(attrs, attrs.filename) for attrs in entries]}


def stat(session, path):
    sftp = _open(session)
    try:
        attrs = sftp.stat(path)
    except Exception as exc:
        raise SFTPError("stat failed: %s" % exc)
    finally:
        sftp.close()
    info = _entry(attrs, os.path.basename(path.rstrip("/")) or path)
    info["operation"] = "stat"
    info["path"] = path
    return info


def mkdir(session, path):
    sftp = _open(session)
    try:
        sftp.mkdir(path)
    except Exception as exc:
        raise SFTPError("mkdir failed: %s" % exc)
    finally:
        sftp.close()
    return {"operation": "mkdir", "path": path}


def rm(session, path):
    sftp = _open(session)
    try:
        attrs = sftp.stat(path)
        if stat_module.S_ISDIR(attrs.st_mode or 0):
            sftp.rmdir(path)
        else:
            sftp.remove(path)
    except Exception as exc:
        raise SFTPError("rm failed: %s" % exc)
    finally:
        sftp.close()
    return {"operation": "rm", "path": path}


OPERATIONS = {"put": put, "get": get, "ls": ls, "stat": stat, "mkdir": mkdir, "rm": rm}


def dispatch(session, operation, **kwargs):
    """Run one SFTP operation by name; raises SFTPError for unknown operations."""
    handler = OPERATIONS.get(operation)
    if handler is None:
        raise SFTPError("unknown sftp operation: %s" % operation)
    return handler(session, **kwargs)
