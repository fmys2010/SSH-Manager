# -*- coding: utf-8 -*-
"""The localhost daemon that owns the SSH connections."""

import base64
import hashlib
import os
import re
import select
import socket
import threading
import time
import uuid

import paramiko

from . import auth, sftp
from .config import (
    CONNECT_TIMEOUT,
    DRAIN_TIMEOUT,
    KEEPALIVE_SECONDS,
    MAX_JOBS_PER_SESSION,
    VERSION,
    ensure_state_dir,
    get_idle_timeout,
    get_job_buffer_bytes,
    get_keepalive_interval,
    get_max_channels,
    get_state_dir,
    log,
    state_path,
    write_json_atomic,
)
from .encoding import make_stream_decoders
from .errors import ConnectError, SSHConnectError
from .jobs import JobRegistry
from .protocol import ProtocolError, recv_frame, send_frame
from .session import Session

NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class Daemon(object):
    """Localhost TCP daemon managing SSH sessions.

    Binds 127.0.0.1:0 (OS-assigned port), publishes port/pid/token in
    daemon.json, authenticates every request with the token, and reaps idle or
    dead sessions in the background. A session that is running commands is
    never reaped, and several commands may run on one connection at once.
    """

    def __init__(self, state_dir=None, idle_timeout=None, keepalive_interval=None,
                 max_channels=None, job_buffer_bytes=None):
        self.state_dir = state_dir or get_state_dir()
        self.idle_timeout = idle_timeout if idle_timeout is not None else get_idle_timeout()
        self.keepalive_interval = (
            keepalive_interval if keepalive_interval is not None else get_keepalive_interval())
        self.max_channels = max_channels if max_channels is not None else get_max_channels()
        self.jobs = JobRegistry(
            job_buffer_bytes if job_buffer_bytes is not None else get_job_buffer_bytes(),
            max_finished=MAX_JOBS_PER_SESSION)
        self.token = os.urandom(16).hex()
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self._pending_names = set()
        self._listener = None
        self._stop_event = threading.Event()
        self._handler_threads = []
        self._reaper = None
        # Cap at 30s so a dead transport is noticed promptly even when the
        # idle timeout is long.
        self._reaper_interval = max(0.5, min(30.0, self.idle_timeout / 2.0))

    # -- listener / lifecycle ------------------------------------------------

    def start(self):
        """Bind the listener and publish the state file. Returns the port."""
        ensure_state_dir(self.state_dir)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        port = self._listener.getsockname()[1]
        self._write_state_file(port)
        self._reaper = threading.Thread(target=self._reaper_loop, args=(), daemon=True)
        self._reaper.start()
        log("daemon started on 127.0.0.1:%d pid=%d version=%s idle_timeout=%ds "
            "keepalive=%.1fs max_channels=%d" % (
                port, os.getpid(), VERSION, self.idle_timeout, self.keepalive_interval,
                self.max_channels), self.state_dir)
        return port

    def _write_state_file(self, port):
        write_json_atomic(state_path(self.state_dir), {
            "port": port,
            "pid": os.getpid(),
            "token": self.token,
            "version": VERSION,
            "keepalive_interval": self.keepalive_interval,
            "max_channels": self.max_channels,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

    def serve_forever(self):
        """Accept and handle client connections until stopped."""
        self.start()
        try:
            while not self._stop_event.is_set():
                try:
                    conn, _ = self._listener.accept()
                except OSError:
                    break  # listener closed by stop()
                thread = threading.Thread(target=self.handle_connection, args=(conn,), daemon=True)
                thread.start()
                self._handler_threads = [t for t in self._handler_threads if t.is_alive()]
                self._handler_threads.append(thread)
        finally:
            try:
                self._listener.close()
            except OSError:
                pass

    def stop(self):
        """Gracefully close all sessions and stop the daemon."""
        self._stop_event.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self.sessions_lock:
            ids = list(self.sessions)
        for conn_id in ids:
            self.close_session(conn_id, "daemon stop")
        for thread in list(self._handler_threads):
            if thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=2.0)
        log("daemon stopped", self.state_dir)

    def close_session(self, conn_id, reason):
        """Remove a session, kill its background jobs and close its SSH client."""
        with self.sessions_lock:
            session = self.sessions.pop(conn_id, None)
        if session is not None:
            self.jobs.prune_session(conn_id)
            log("closing session %s (%s) reason=%s" % (
                conn_id, session.describe(), reason), self.state_dir)
            session.close()
        return session is not None

    def _resolve_session(self, key):
        """Look a session up by UUID or by name."""
        if not key:
            return None
        with self.sessions_lock:
            session = self.sessions.get(key)
            if session is not None:
                return session
            for candidate in self.sessions.values():
                if candidate.name and candidate.name == key:
                    return candidate
        return None

    # -- reaper --------------------------------------------------------------

    def _reaper_loop(self):
        while not self._stop_event.is_set():
            time.sleep(self._reaper_interval)
            now = time.time()
            with self.sessions_lock:
                snapshot = list(self.sessions.items())
            for conn_id, session in snapshot:
                if session.busy:
                    continue
                if not session.transport_alive():
                    self.close_session(conn_id, "connection dead")
                    log("session %s removed (transport inactive)" % conn_id, self.state_dir)
                    continue
                if session.idle_seconds(now) > self.idle_timeout:
                    self.close_session(conn_id, "idle timeout")
                    log("session %s reaped (idle > %ds)" % (
                        conn_id, self.idle_timeout), self.state_dir)

    # -- SSH session setup ----------------------------------------------------

    def open_session(self, host, port, username, password, encoding=None,
                     key_path=None, key_passphrase=None, use_agent=False,
                     known_hosts=None, no_host_key_check=False,
                     accept_host_key=False, name=None):
        """Create a paramiko connection and register it. Raises on failure."""
        client = paramiko.SSHClient()
        pkey = None
        policy = None
        key_name = host if port == 22 else "[%s]:%d" % (host, port)
        try:
            policy = auth.configure_host_keys(
                client, known_hosts=known_hosts, no_host_key_check=no_host_key_check,
                accept_host_key=accept_host_key)
            was_known = client.get_host_keys().lookup(key_name) is not None
            if key_path:
                pkey = auth.load_private_key(key_path, key_passphrase)  # raises AuthError
            allow_agent = bool(key_path) or bool(use_agent)
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password or None,
                pkey=pkey,
                timeout=CONNECT_TIMEOUT,
                allow_agent=allow_agent,
                look_for_keys=False,
                banner_timeout=CONNECT_TIMEOUT,
            )
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(KEEPALIVE_SECONDS)
            if accept_host_key and not was_known and transport is not None:
                remote_key = transport.get_remote_server_key()
                auth.append_known_hosts(
                    auth.known_hosts_path(known_hosts), host, port, remote_key)
                log("saved host key for %s:%s (%s)" % (
                    host, port, auth.fingerprint_sha256(remote_key)), self.state_dir)
        except auth.AuthError:
            raise
        except paramiko.BadHostKeyException as exc:
            raise ConnectError(
                "host key mismatch for %s:%s (expected %s, got %s)" % (
                    host, port, exc.expected_key.get_name(), exc.key.get_name()),
                code="host_key_mismatch")
        except paramiko.AuthenticationException as exc:
            raise SSHConnectError(
                "认证失败/Authentication failed for %s@%s:%s: %s" % (
                    username, host, port, exc))
        except (paramiko.SSHException, socket.error, OSError) as exc:
            if policy is not None and policy.key is not None:
                raise ConnectError(
                    auth.unknown_host_hint(host, port),
                    code="unknown_host",
                    details={
                        "host": host,
                        "port": port,
                        "key_type": policy.key.get_name(),
                        "fingerprint": auth.fingerprint_sha256(policy.key),
                    })
            if known_hosts and not no_host_key_check and not accept_host_key:
                if isinstance(exc, FileNotFoundError) or "known_hosts" in str(exc):
                    raise SSHConnectError("known_hosts file not readable: %s" % known_hosts)
            raise SSHConnectError(
                "连接失败/Connection failed for %s@%s:%s: %s" % (username, host, port, exc))

        conn_id = str(uuid.uuid4())
        now = time.time()
        session = Session(
            conn_id, client, host, port, username, now,
            encoding=encoding,
            key_path=key_path,
            auth_mode="key" if (key_path or use_agent) else "password",
            name=name,
            max_channels=self.max_channels,
        )
        with self.sessions_lock:
            self.sessions[conn_id] = session
        log("session %s opened (%s%s, auth=%s)" % (
            conn_id, session.describe(),
            ", name=%s" % name if name else "", session.auth_mode), self.state_dir)
        return session

    # -- socket handling ------------------------------------------------------

    def handle_connection(self, conn):
        """Read length-prefixed JSON frames from one client socket."""
        try:
            while not self._stop_event.is_set():
                try:
                    req = recv_frame(conn)
                except ProtocolError as exc:
                    self._safe_send(conn, {"type": "error", "message": str(exc)})
                    return
                if req is None:
                    return
                try:
                    self._dispatch(conn, req)
                except Exception as exc:  # malformed request must not wedge the client
                    self._safe_send(conn, {"type": "error",
                                           "message": "internal error: %s" % exc,
                                           "error_code": "bad_request"})
                    log("handler error: %s" % exc, self.state_dir)
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, conn, req):
        if not isinstance(req, dict) or req.get("token") != self.token:
            self._safe_send(conn, {"type": "error", "message": "invalid token",
                                   "error_code": "bad_token"})
            return
        op = req.get("op")
        if op == "ping":
            self._safe_send(conn, {"ok": True, "version": VERSION})
        elif op == "connect":
            self._handle_connect(conn, req)
        elif op == "exec":
            self._handle_exec(conn, req)
        elif op == "close":
            self._handle_close(conn, req)
        elif op == "list":
            self._handle_list(conn)
        elif op == "jobs":
            self._handle_jobs(conn)
        elif op == "job_logs":
            self._handle_job_logs(conn, req)
        elif op == "job_kill":
            self._handle_job_kill(conn, req)
        elif op == "sftp":
            self._handle_sftp(conn, req)
        elif op == "stop":
            self._safe_send(conn, {"ok": True})
            threading.Thread(target=self.stop, daemon=True).start()
        else:
            self._safe_send(conn, {"type": "error", "message": "unknown op: %s" % op,
                                   "error_code": "bad_request"})

    def _safe_send(self, conn, obj):
        """Send a frame; returns False when the client is gone."""
        try:
            send_frame(conn, obj)
            return True
        except OSError:
            return False

    def _handle_connect(self, conn, req):
        host = req.get("host")
        user = req.get("user")
        password = req.get("password") or ""
        encoding = req.get("encoding")
        name = req.get("name")
        if not (host and user):
            self._safe_send(conn, {"ok": False, "error": "host and user required",
                                   "error_code": "bad_request"})
            return
        try:
            port = int(req.get("port") or 22)
        except (TypeError, ValueError):
            self._safe_send(conn, {"ok": False, "error": "invalid port",
                                   "error_code": "bad_request"})
            return
        if name is not None and not NAME_PATTERN.match(name):
            self._safe_send(conn, {
                "ok": False, "error_code": "bad_name",
                "error": "invalid session name %r (allowed: letters, digits, . _ -, 1-64 chars)"
                         % name})
            return
        if name:
            with self.sessions_lock:
                taken = (name in self._pending_names
                         or any(s.name == name for s in self.sessions.values()))
                if not taken:
                    self._pending_names.add(name)
            if taken:
                self._safe_send(conn, {"ok": False, "error_code": "duplicate_name",
                                       "error": "session name already in use: %s" % name})
                return
        try:
            session = self.open_session(
                host, port, user, password,
                encoding=encoding if encoding and encoding != "auto" else None,
                key_path=req.get("key_path"),
                key_passphrase=req.get("key_passphrase"),
                use_agent=bool(req.get("use_agent")),
                known_hosts=req.get("known_hosts"),
                no_host_key_check=bool(req.get("no_host_key_check")),
                accept_host_key=bool(req.get("accept_host_key")),
                name=name,
            )
        except (SSHConnectError, auth.AuthError) as exc:
            payload = {"ok": False, "error": str(exc)}
            code = getattr(exc, "code", None)
            if code:
                payload["error_code"] = code
            details = getattr(exc, "details", None)
            if details:
                payload.update(details)
            self._safe_send(conn, payload)
            return
        finally:
            if name:
                with self.sessions_lock:
                    self._pending_names.discard(name)
        self._safe_send(conn, {"ok": True, "id": session.id, "name": session.name})

    def _handle_close(self, conn, req):
        session = self._resolve_session(req.get("id"))
        if session is None:
            self._safe_send(conn, {"ok": False, "error_code": "unknown_session",
                                   "error": "unknown connection id: %s" % req.get("id")})
            return
        self.close_session(session.id, "client close")
        self._safe_send(conn, {"ok": True})

    def _handle_list(self, conn):
        now = time.time()
        with self.sessions_lock:
            items = [session.to_info(now) for session in self.sessions.values()]
        self._safe_send(conn, {"ok": True, "sessions": items})

    # -- background jobs ------------------------------------------------------

    def _handle_jobs(self, conn):
        self._safe_send(conn, {"ok": True,
                               "jobs": [job.info() for job in self.jobs.list()]})

    def _handle_job_logs(self, conn, req):
        job = self.jobs.get(req.get("job_id"))
        if job is None:
            self._safe_send(conn, {"type": "error", "error_code": "unknown_job",
                                   "message": "unknown job: %s" % req.get("job_id")})
            return
        try:
            since = int(req.get("since") or 0)
        except (TypeError, ValueError):
            since = 0
        if not req.get("follow"):
            chunks, next_seq = job.snapshot(since)
            self._safe_send(conn, {"ok": True, "chunks": chunks,
                                   "next_seq": next_seq, "job": job.info()})
            return
        while True:
            chunks, next_seq, finished = job.wait_for_update(since, self.keepalive_interval)
            for _seq, stream, text in chunks:
                if not self._safe_send(conn, {"type": "data", "stream": stream, "text": text}):
                    return
            since = next_seq
            if finished:
                self._safe_send(conn, {"type": "done", "exit_status": job.exit_status,
                                       "status": job.status})
                return
            if not chunks:
                if not self._safe_send(conn, {"type": "keepalive"}):
                    return

    def _handle_job_kill(self, conn, req):
        job = self.jobs.get(req.get("job_id"))
        if job is None:
            self._safe_send(conn, {"type": "error", "error_code": "unknown_job",
                                   "message": "unknown job: %s" % req.get("job_id")})
            return
        job.kill()
        self._safe_send(conn, {"ok": True, "job": job.info()})

    # -- sftp -----------------------------------------------------------------

    def _handle_sftp(self, conn, req):
        session = self._resolve_session(req.get("id"))
        if session is None:
            self._safe_send(conn, {"ok": False, "error_code": "unknown_session",
                                   "error": "unknown connection id: %s" % req.get("id")})
            return
        if not session.transport_alive():
            self._safe_send(conn, {"ok": False, "error_code": "session_dead",
                                   "error": "connection closed: %s" % session.describe()})
            return
        session.last_activity = time.time()
        operation = req.get("sftp_op")
        kwargs = req.get("args") or {}
        try:
            result = sftp.dispatch(session, operation, **kwargs)
        except (sftp.SFTPError, TypeError) as exc:
            self._safe_send(conn, {"ok": False, "error_code": "sftp_error",
                                   "error": str(exc)})
            return
        session.last_activity = time.time()
        self._safe_send(conn, {"ok": True, "result": result})

    # -- exec -----------------------------------------------------------------

    def _handle_exec(self, conn, req):
        session = self._resolve_session(req.get("id"))
        if session is None:
            self._safe_send(conn, {"type": "error", "error_code": "unknown_session",
                                   "message": "unknown or expired connection id: %s"
                                              % req.get("id")})
            return
        if not session.transport_alive():
            self._safe_send(conn, {"type": "error", "error_code": "session_dead",
                                   "message": "connection closed: %s" % session.describe()})
            return
        command = req.get("command") or ""
        timeout = req.get("timeout")
        pty = req.get("pty")
        stdin_enabled = bool(req.get("stdin"))
        session.last_activity = time.time()
        if req.get("background"):
            job = self.jobs.create(session.id, command)
            self.jobs.prune_finished(session.id)
            self._safe_send(conn, {"ok": True, "job_id": job.id})
            threading.Thread(
                target=self._background_exec,
                args=(session, job, command, timeout, pty), daemon=True).start()
            return
        self._exec_foreground(conn, session, command, timeout, pty, stdin_enabled)

    def _acquire_slot(self, session, conn):
        """Take a channel slot, keeping a waiting client alive."""
        while True:
            if session.acquire_channel(timeout=self.keepalive_interval):
                return True
            if conn is not None and not self._safe_send(conn, {"type": "keepalive"}):
                return False

    def _exec_foreground(self, conn, session, command, timeout, pty, stdin_enabled):
        if not self._acquire_slot(session, conn):
            return
        session.enter_channel()
        channel = None
        try:
            decoders = make_stream_decoders(session.encoding)
            channel = self._open_channel(session, command, pty)
            emit = lambda stream, text: self._safe_send(
                conn, {"type": "data", "stream": stream, "text": text})
            status = self._run_channel(session, channel, decoders, emit, timeout,
                                       stdin_enabled, conn)
            self._safe_send(conn, {"type": "done", "exit_status": status})
            digest = hashlib.sha256(command.encode("utf-8")).hexdigest()[:12]
            log("exec id=%s cmd_len=%d cmd_sha=%s exit=%d" % (
                session.id, len(command), digest, status), self.state_dir)
        except ConnectionResetError:
            return  # client went away mid-stream
        except (OSError, socket.error, paramiko.SSHException) as exc:
            self._safe_send(conn, {"type": "error", "message": "exec error: %s" % exc,
                                   "error_code": "exec_error"})
        finally:
            session.leave_channel()
            session.release_channel()
            session.last_activity = time.time()
            if channel is not None:
                try:
                    channel.close()
                except (OSError, paramiko.SSHException):
                    pass

    def _background_exec(self, session, job, command, timeout, pty):
        if not self._acquire_slot(session, None):
            job.finish("failed", None, "connection closing")
            return
        session.enter_channel()
        channel = None
        try:
            decoders = make_stream_decoders(session.encoding)
            channel = self._open_channel(session, command, pty)
            job.channel = channel
            status = self._run_channel(session, channel, decoders, job.append, timeout,
                                       False, None)
            job.finish("killed" if job.killed else "done", status)
        except (OSError, socket.error, paramiko.SSHException) as exc:
            job.finish("failed", None, "exec error: %s" % exc)
        finally:
            session.leave_channel()
            session.release_channel()
            session.last_activity = time.time()
            if channel is not None:
                try:
                    channel.close()
                except (OSError, paramiko.SSHException):
                    pass
            digest = hashlib.sha256(command.encode("utf-8")).hexdigest()[:12]
            log("job id=%s session=%s cmd_sha=%s status=%s exit=%s" % (
                job.id, session.id, digest, job.status, job.exit_status), self.state_dir)

    def _open_channel(self, session, command, pty):
        transport = session.client.get_transport()
        if transport is None or not transport.is_active():
            raise SSHConnectError("connection closed: %s" % session.describe())
        channel = transport.open_session()
        if pty:
            channel.get_pty(
                term=pty.get("term") or "vt100",
                width=int(pty.get("width") or 80),
                height=int(pty.get("height") or 24),
            )
        channel.exec_command(command)
        return channel

    def _run_channel(self, session, channel, decoders, emit, timeout, stdin_enabled, conn):
        """Pump one channel to completion. Returns the remote exit status."""
        start = time.time()
        deadline = start + timeout if timeout is not None else None
        last_emit = start
        timed_out = False
        stdin_open = stdin_enabled and conn is not None
        while True:
            if self._drain(channel, decoders, emit):
                last_emit = time.time()
            if channel.exit_status_ready():
                break
            now = time.time()
            if now - last_emit >= self.keepalive_interval:
                if conn is not None and not self._safe_send(conn, {"type": "keepalive"}):
                    return 1
                last_emit = now
            watch = [channel]
            if stdin_open:
                watch.append(conn)
            try:
                ready, _, _ = select.select(watch, [], [], DRAIN_TIMEOUT)
            except (OSError, ValueError):
                if channel.exit_status_ready():
                    break
                raise
            if stdin_open and conn in ready:
                frame = recv_frame(conn)
                if frame is None:
                    stdin_open = False
                elif frame.get("type") == "stdin":
                    payload = base64.b64decode(frame.get("data_b64") or "")
                    if payload:
                        channel.sendall(payload)
                    last_emit = time.time()
                elif frame.get("type") == "stdin_eof":
                    try:
                        channel.shutdown_write()
                    except (OSError, paramiko.SSHException):
                        pass
                    stdin_open = False
            if deadline is not None and time.time() > deadline:
                timed_out = True
                emit("stderr", "[timeout after %ds]\n" % int(time.time() - start))
                try:
                    channel.close()
                except (OSError, paramiko.SSHException):
                    pass
                break
        if timed_out:
            return 124
        self._drain(channel, decoders, emit)
        for stream, tail in self._flush(decoders):
            emit(stream, tail)
        try:
            return channel.recv_exit_status()
        except (socket.timeout, OSError, paramiko.SSHException):
            return 1

    def _drain(self, channel, decoders, emit):
        """Forward ready stdout/stderr data. Returns True if anything was sent."""
        emitted = False
        while channel.recv_ready():
            raw = channel.recv(65536)
            if not raw:
                break
            text = decoders["stdout"].decode(raw)
            if text:
                emit("stdout", text)
            emitted = True
        while channel.recv_stderr_ready():
            raw = channel.recv_stderr(65536)
            if not raw:
                break
            text = decoders["stderr"].decode(raw)
            if text:
                emit("stderr", text)
            emitted = True
        return emitted

    @staticmethod
    def _flush(decoders):
        tails = []
        for stream in ("stdout", "stderr"):
            text = decoders[stream].flush()
            if text:
                tails.append((stream, text))
        return tails
