# -*- coding: utf-8 -*-
"""Client side of the daemon protocol, including daemon auto-start."""

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

from .config import (
    AUTO_START_WAIT,
    KEY_PASSPHRASE_ENV,
    PASSWORD_ENV,
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW,
    DETACHED_PROCESS,
    STALE_LOCK_SECONDS,
    STREAM_READ_TIMEOUT_FACTOR,
    ensure_state_dir,
    get_keepalive_interval,
    get_state_dir,
    lock_path,
    log_path,
    secure_file,
    state_path,
)
from .errors import ConnectError, SSHConnectError, SessionError
from .protocol import ProtocolError, recv_frame, send_frame

_CONNECT_TIMEOUT = 60.0


class DaemonClient(object):
    """Speaks the length-prefixed JSON protocol to the manager daemon."""

    def __init__(self, state_dir=None):
        self.state_dir = state_dir or get_state_dir()
        self._child = None   # Popen handle of a daemon we spawned, if any

    # -- state / spawn --------------------------------------------------------

    def _read_state(self):
        try:
            with open(state_path(self.state_dir), "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _daemon_alive(self):
        state = self._read_state()
        if state is None:
            return False
        try:
            sock = socket.create_connection(("127.0.0.1", state["port"]), timeout=2.0)
            sock.close()
            return True
        except (OSError, KeyError, TypeError):
            return False

    def _spawn_daemon(self):
        """Launch ``ssh_manager.py daemon`` detached (Windows) / sessioned (POSIX)."""
        ensure_state_dir(self.state_dir)
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "ssh_manager.py")
        env = dict(os.environ)
        env.setdefault("SSH_MANAGER_STATE_DIR", self.state_dir)
        # The daemon never needs the user's credentials: do not leak them into
        # a long-lived detached process environment.
        env.pop(PASSWORD_ENV, None)
        env.pop(KEY_PASSPHRASE_ENV, None)
        with open(log_path(self.state_dir), "a", encoding="utf-8") as logfile:
            if os.name == "nt":
                flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
                self._child = subprocess.Popen(
                    [sys.executable, script, "daemon"],
                    stdout=logfile, stderr=logfile,
                    creationflags=flags,
                    cwd=os.path.dirname(script),
                    env=env, close_fds=True,
                )
            else:
                self._child = subprocess.Popen(
                    [sys.executable, script, "daemon"],
                    stdout=logfile, stderr=logfile,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=os.path.dirname(script),
                    env=env, close_fds=True,
                )

    def _acquire_start_lock(self):
        """Serialize concurrent cold starts. Returns True when this process owns it."""
        ensure_state_dir(self.state_dir)
        path = lock_path(self.state_dir)
        for attempt in (0, 1):
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                if attempt == 0 and self._lock_is_stale(path):
                    self._remove_lock(path)
                    continue
                return False
            except OSError:
                return False
            try:
                os.write(fd, ("%d %f" % (os.getpid(), time.time())).encode("ascii"))
            finally:
                os.close(fd)
            secure_file(path, 0o600)
            return True
        return False

    def _lock_is_stale(self, path):
        try:
            age = time.time() - os.path.getmtime(path)
        except OSError:
            return False
        return age > STALE_LOCK_SECONDS and not self._daemon_alive()

    def _remove_lock(self, path):
        try:
            os.remove(path)
        except OSError:
            pass

    def _wait_for_daemon(self):
        deadline = time.time() + AUTO_START_WAIT
        last_error = None
        while time.time() < deadline:
            state = self._read_state()
            if state:
                try:
                    sock = socket.create_connection(("127.0.0.1", state["port"]), timeout=1.0)
                    sock.close()
                    return
                except OSError as exc:
                    last_error = exc
            time.sleep(0.2)
        raise SSHConnectError(
            "无法启动守护进程/Failed to start daemon: %s" % (last_error or "timeout"))

    def ensure_daemon(self):
        """Ensure a daemon is running; start one if needed. May raise SSHConnectError."""
        if self._daemon_alive():
            return
        owned = self._acquire_start_lock()
        try:
            if self._daemon_alive():
                return
            if owned:
                self._spawn_daemon()
            self._wait_for_daemon()
        finally:
            if owned:
                self._remove_lock(lock_path(self.state_dir))

    # -- protocol -------------------------------------------------------------

    def _send_and_recv(self, obj):
        """Send one request and return the single response frame."""
        state = self._read_state()
        if state is None:
            raise SSHConnectError("守护进程未运行/Daemon not running (state file missing)")
        obj = dict(obj)
        obj.setdefault("token", state.get("token"))
        try:
            sock = socket.create_connection(("127.0.0.1", state["port"]), timeout=_CONNECT_TIMEOUT)
        except (OSError, KeyError, TypeError) as exc:
            raise SSHConnectError("无法连接守护进程/Cannot reach daemon: %s" % exc)
        try:
            send_frame(sock, obj)
            try:
                return recv_frame(sock)
            except ProtocolError as exc:
                raise SSHConnectError("守护进程协议错误/protocol error: %s" % exc)
        except OSError as exc:
            raise SSHConnectError("与守护进程通信失败/daemon I/O error: %s" % exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _send_and_get_sock(self, obj):
        """Send one request and return the connected socket for streaming reads."""
        state = self._read_state()
        if state is None:
            raise SSHConnectError("守护进程未运行/Daemon not running (state file missing)")
        obj = dict(obj)
        obj.setdefault("token", state.get("token"))
        try:
            sock = socket.create_connection(("127.0.0.1", state["port"]), timeout=_CONNECT_TIMEOUT)
        except (OSError, KeyError, TypeError) as exc:
            raise SSHConnectError("无法连接守护进程/Cannot reach daemon: %s" % exc)
        try:
            send_frame(sock, obj)
        except OSError as exc:
            sock.close()
            raise SSHConnectError("发送请求失败/Failed to send request: %s" % exc)
        return sock

    # -- high-level ops -------------------------------------------------------

    def connect(self, host, port, user, password, encoding=None, key_path=None,
                key_passphrase=None, use_agent=False, known_hosts=None,
                no_host_key_check=False, name=None, accept_host_key=False):
        req = {"op": "connect", "host": host, "port": port,
               "user": user, "password": password}
        if encoding:
            req["encoding"] = encoding
        if key_path:
            req["key_path"] = key_path
        if key_passphrase:
            req["key_passphrase"] = key_passphrase
        if use_agent:
            req["use_agent"] = True
        if known_hosts:
            req["known_hosts"] = known_hosts
        if no_host_key_check:
            req["no_host_key_check"] = True
        if name:
            req["name"] = name
        if accept_host_key:
            req["accept_host_key"] = True
        resp = self._send_and_recv(req)
        if resp is None:
            raise SSHConnectError("守护进程无响应/Daemon returned no response")
        if not resp.get("ok"):
            details = dict((k, resp[k]) for k in ("fingerprint", "key_type", "host", "port")
                           if k in resp)
            raise ConnectError(resp.get("error", "connect failed"),
                               code=resp.get("error_code"), details=details)
        return {"id": resp["id"], "name": resp.get("name")}

    @staticmethod
    def _pump_stdin(sock, source):
        """Copy a local binary stream to the daemon as base64 stdin frames."""
        try:
            while True:
                chunk = source.read(32768)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                send_frame(sock, {"type": "stdin",
                                  "data_b64": base64.b64encode(chunk).decode("ascii")})
        except (OSError, ValueError):
            pass
        finally:
            try:
                send_frame(sock, {"type": "stdin_eof"})
            except OSError:
                pass

    def exec_stream(self, conn_id, command, timeout=None, pty=None, stdin_source=None):
        """Yield ("OUT: "/"ERR: ", text) frames, then ("RETURN", exit_status).

        The socket keeps a generous read timeout so a wedged daemon is detected,
        while the daemon emits keepalive frames during silent stretches so a
        long-running command is never mistaken for a dead connection.
        """
        request = {"op": "exec", "id": conn_id, "command": command, "timeout": timeout}
        if pty:
            request["pty"] = pty
        if stdin_source is not None:
            request["stdin"] = True
        sock = self._send_and_get_sock(request)
        if stdin_source is not None:
            threading.Thread(target=self._pump_stdin, args=(sock, stdin_source),
                             daemon=True).start()
        state = self._read_state() or {}
        interval = state.get("keepalive_interval") or get_keepalive_interval()
        try:
            read_timeout = max(2.0, float(interval) * STREAM_READ_TIMEOUT_FACTOR)
        except (TypeError, ValueError):
            read_timeout = max(2.0, get_keepalive_interval() * STREAM_READ_TIMEOUT_FACTOR)
        sock.settimeout(read_timeout)
        try:
            while True:
                try:
                    frame = recv_frame(sock)
                except socket.timeout:
                    raise SSHConnectError(
                        "守护进程无响应/daemon unresponsive (no data for %.0fs)" % read_timeout)
                except ProtocolError as exc:
                    raise SSHConnectError("守护进程协议错误/protocol error: %s" % exc)
                if frame is None:
                    raise SSHConnectError("守护进程连接中断/daemon connection lost")
                ftype = frame.get("type")
                if ftype == "keepalive":
                    continue
                if ftype == "error":
                    raise SessionError(frame.get("message", "exec error"))
                if ftype == "done":
                    yield ("RETURN", frame.get("exit_status"))
                    return
                if ftype == "data":
                    tag = "OUT: " if frame.get("stream") == "stdout" else "ERR: "
                    yield (tag, frame.get("text", ""))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def exec_background(self, conn_id, command, timeout=None, pty=None):
        """Start a background job; returns its job id."""
        request = {"op": "exec", "id": conn_id, "command": command,
                   "timeout": timeout, "background": True}
        if pty:
            request["pty"] = pty
        resp = self._send_and_recv(request)
        if resp is None or not resp.get("ok"):
            raise SessionError((resp or {}).get("error", "background exec failed"))
        return resp["job_id"]

    def jobs(self):
        resp = self._send_and_recv({"op": "jobs"})
        if resp is None or not resp.get("ok"):
            raise SSHConnectError((resp or {}).get("error", "jobs failed"))
        return resp.get("jobs", [])

    def job_logs(self, job_id, follow=False, since=0):
        """Yield buffered job output. Returns (frames, next_seq, job_info).

        With ``follow`` it is a generator yielding ("OUT: "/"ERR: ", text) and
        finally ("RETURN", exit_status); without it returns a snapshot tuple.
        """
        if follow:
            return self._job_logs_follow(job_id, since)
        resp = self._send_and_recv({"op": "job_logs", "job_id": job_id,
                                    "since": since, "follow": False})
        if resp is None or not resp.get("ok"):
            raise SessionError((resp or {}).get("error", "unknown job"))
        frames = [("OUT: " if stream == "stdout" else "ERR: ", text)
                  for _seq, stream, text in resp.get("chunks", [])]
        return frames, resp.get("next_seq", 0), resp.get("job", {})

    def _job_logs_follow(self, job_id, since=0):
        sock = self._send_and_get_sock({"op": "job_logs", "job_id": job_id,
                                        "since": since, "follow": True})
        state = self._read_state() or {}
        interval = state.get("keepalive_interval") or get_keepalive_interval()
        try:
            read_timeout = max(2.0, float(interval) * STREAM_READ_TIMEOUT_FACTOR)
        except (TypeError, ValueError):
            read_timeout = max(2.0, get_keepalive_interval() * STREAM_READ_TIMEOUT_FACTOR)
        sock.settimeout(read_timeout)
        try:
            while True:
                try:
                    frame = recv_frame(sock)
                except socket.timeout:
                    raise SSHConnectError(
                        "守护进程无响应/daemon unresponsive (no data for %.0fs)" % read_timeout)
                if frame is None:
                    raise SSHConnectError("守护进程连接中断/daemon connection lost")
                ftype = frame.get("type")
                if ftype == "keepalive":
                    continue
                if ftype == "error":
                    raise SessionError(frame.get("message", "job logs error"))
                if ftype == "done":
                    yield ("RETURN", frame.get("exit_status"))
                    return
                if ftype == "data":
                    tag = "OUT: " if frame.get("stream") == "stdout" else "ERR: "
                    yield (tag, frame.get("text", ""))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def job_kill(self, job_id):
        resp = self._send_and_recv({"op": "job_kill", "job_id": job_id})
        if resp is None or not resp.get("ok"):
            raise SessionError((resp or {}).get("error", "kill failed"))
        return resp.get("job", {})

    def sftp(self, operation, conn_id, **kwargs):
        resp = self._send_and_recv({"op": "sftp", "sftp_op": operation,
                                    "id": conn_id, "args": kwargs})
        if resp is None or not resp.get("ok"):
            raise ConnectError((resp or {}).get("error", "sftp failed"),
                               code=(resp or {}).get("error_code"))
        return resp.get("result", {})

    def close(self, conn_id):
        resp = self._send_and_recv({"op": "close", "id": conn_id})
        if resp is None or not resp.get("ok"):
            raise SessionError((resp or {}).get("error", "close failed"))

    def list(self):
        resp = self._send_and_recv({"op": "list"})
        if resp is None or not resp.get("ok"):
            raise SSHConnectError((resp or {}).get("error", "list failed"))
        return resp.get("sessions", [])

    def ping(self):
        resp = self._send_and_recv({"op": "ping"})
        return resp is not None and resp.get("ok") is True

    def stop(self):
        resp = self._send_and_recv({"op": "stop"})
        return resp is not None and resp.get("ok") is True
