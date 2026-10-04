# -*- coding: utf-8 -*-
"""Configuration: constants, environment handling, state-dir paths and I/O helpers."""

import json
import os
import time

VERSION = "2.1.0"

# -- environment variable names ------------------------------------------------
STATE_DIR_ENV = "SSH_MANAGER_STATE_DIR"
IDLE_TIMEOUT_ENV = "SSH_MANAGER_IDLE_TIMEOUT"
PASSWORD_ENV = "SSH_MANAGER_PASSWORD"
KEY_PASSPHRASE_ENV = "SSH_MANAGER_KEY_PASSPHRASE"
KEEPALIVE_ENV = "SSH_MANAGER_KEEPALIVE_INTERVAL"
MAX_CHANNELS_ENV = "SSH_MANAGER_MAX_CHANNELS"
JOB_BUFFER_ENV = "SSH_MANAGER_JOB_BUFFER_KB"
LOG_MAX_KB_ENV = "SSH_MANAGER_LOG_MAX_KB"

# -- file names ----------------------------------------------------------------
STATE_DIR_DEFAULT = os.path.join(os.path.expanduser("~"), ".ssh-manager")
DAEMON_FILE = "daemon.json"
DAEMON_LOG = "daemon.log"
LOCK_FILE = "daemon.lock"

# -- tunables ------------------------------------------------------------------
DEFAULT_IDLE_TIMEOUT = 1800          # seconds before an idle session is reaped
DEFAULT_KEEPALIVE_INTERVAL = 30.0    # seconds between exec keepalive frames
AUTO_START_WAIT = 8.0                # max seconds to wait for a daemon spawn
CONNECT_TIMEOUT = 15                 # seconds, SSH connect/banner timeout
KEEPALIVE_SECONDS = 30               # seconds, SSH transport keepalive
DRAIN_TIMEOUT = 0.3                  # seconds, select() wait in the exec drain loop
STREAM_READ_TIMEOUT_FACTOR = 3.0     # client read timeout = factor * keepalive interval
MAX_FRAME_BYTES = 16 * 1024 * 1024   # protocol frame cap (guards against bad clients)
STALE_LOCK_SECONDS = 30.0            # a start lock older than this is considered stale
DEFAULT_MAX_CHANNELS = 10            # concurrent channels per SSH connection
DEFAULT_JOB_BUFFER_KB = 256          # per background job output budget
DEFAULT_LOG_MAX_KB = 1024            # rotate daemon.log at this size
LOG_BACKUPS = 3                      # daemon.log.1 .. daemon.log.3
MAX_JOBS_PER_SESSION = 50            # finished background jobs kept per session

# Windows subprocess flags (no-ops elsewhere)
DETACHED_PROCESS = getattr(__import__("subprocess"), "DETACHED_PROCESS", 0x00000008)
CREATE_NEW_PROCESS_GROUP = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0x00000200)
CREATE_NO_WINDOW = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0x08000000)

IS_POSIX = os.name == "posix"


def get_state_dir():
    """Effective state directory (environment override or default)."""
    return os.environ.get(STATE_DIR_ENV) or STATE_DIR_DEFAULT


def get_idle_timeout():
    """Effective idle timeout in seconds (environment override or default)."""
    return _env_int(IDLE_TIMEOUT_ENV, DEFAULT_IDLE_TIMEOUT, minimum=1)


def get_keepalive_interval():
    """Effective exec keepalive interval in seconds (environment override or default)."""
    raw = os.environ.get(KEEPALIVE_ENV)
    if raw:
        try:
            return max(0.2, float(raw))
        except ValueError:
            pass
    return DEFAULT_KEEPALIVE_INTERVAL


def get_max_channels():
    """Concurrent channel cap per SSH connection."""
    return _env_int(MAX_CHANNELS_ENV, DEFAULT_MAX_CHANNELS, minimum=1)


def get_job_buffer_bytes():
    """Per background job output budget, in bytes."""
    return _env_int(JOB_BUFFER_ENV, DEFAULT_JOB_BUFFER_KB, minimum=1) * 1024


def get_log_max_bytes():
    """daemon.log rotation threshold, in bytes."""
    return _env_int(LOG_MAX_KB_ENV, DEFAULT_LOG_MAX_KB, minimum=1) * 1024


def _env_int(name, default, minimum=None):
    raw = os.environ.get(name)
    if raw:
        try:
            value = int(raw)
        except ValueError:
            return default
        if minimum is not None:
            value = max(minimum, value)
        return value
    return default


# -- paths ---------------------------------------------------------------------

def state_path(state_dir=None):
    return os.path.join(state_dir or get_state_dir(), DAEMON_FILE)


def log_path(state_dir=None):
    return os.path.join(state_dir or get_state_dir(), DAEMON_LOG)


def lock_path(state_dir=None):
    return os.path.join(state_dir or get_state_dir(), LOCK_FILE)


# -- helpers -------------------------------------------------------------------

def ensure_state_dir(state_dir=None):
    """Create the state directory (0700 on POSIX) and return its path."""
    path = state_dir or get_state_dir()
    os.makedirs(path, exist_ok=True)
    if IS_POSIX:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def secure_file(path, mode=0o600):
    """Best-effort tightening of a file's permissions (POSIX only)."""
    if not IS_POSIX:
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_json_atomic(path, obj, mode=0o600):
    """Write JSON via a temporary file + os.replace so readers never see a torn file."""
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    secure_file(tmp, mode)
    os.replace(tmp, path)


def rotate_log(path, max_bytes):
    """Shift daemon.log -> .1 -> .2 -> .3 once it exceeds ``max_bytes``."""
    try:
        if os.path.getsize(path) < max_bytes:
            return False
    except OSError:
        return False
    for index in range(LOG_BACKUPS - 1, 0, -1):
        source = "%s.%d" % (path, index)
        if os.path.exists(source):
            try:
                os.replace(source, "%s.%d" % (path, index + 1))
            except OSError:
                pass
    try:
        os.replace(path, path + ".1")
        return True
    except OSError:
        return False


def log(message, state_dir=None):
    """Append one line to daemon.log (rotating it when needed). Never raises."""
    try:
        directory = ensure_state_dir(state_dir)
        path = os.path.join(directory, DAEMON_LOG)
        rotate_log(path, get_log_max_bytes())
        with open(path, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
        secure_file(path, 0o600)
    except OSError:
        pass


def read_log_tail(path, lines=None):
    """Return the last ``lines`` lines of a log file (all of it when None)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return ""
    if lines is None or lines <= 0:
        return content
    return "".join(content.splitlines(True)[-lines:])


def format_timestamp(epoch_seconds):
    """Local ISO-8601 timestamp (second resolution) for a POSIX timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch_seconds))
