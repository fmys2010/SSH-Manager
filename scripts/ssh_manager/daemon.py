# -*- coding: utf-8 -*-
"""The localhost daemon that owns the SSH connections."""

import hashlib
import os
import select
import socket
import threading
import time
import uuid

import paramiko

from . import auth
from .config import (
    CONNECT_TIMEOUT,
    DRAIN_TIMEOUT,
    KEEPALIVE_SECONDS,
    VERSION,
    ensure_state_dir,
    get_idle_timeout,
    get_keepalive_interval,
    get_state_dir,
    log,
    state_path,
    write_json_atomic,
)
from .encoding import AdaptiveDecoder
from .errors import SSHConnectError
from .protocol import ProtocolError, recv_frame, send_frame
from .session import Session


class Daemon(object):
    """Localhost TCP daemon managing SSH sessions.

    Binds 127.0.0.1:0 (OS-assigned port), publishes port/pid/token in
    daemon.json, authenticates every request with the token, and reaps idle
    sessions in the background. Sessions with an in-flight command are never
    reaped.
    """

    def __init__(self, state_dir=None, idle_timeout=None, keepalive_interval=None):
        self.state_dir = state_dir or get_state_dir()
        self.idle_timeout = idle_timeout if idle_timeout is not None else get_idle_timeout()
        self.keepalive_interval = (
            keepalive_interval if keepalive_interval is not None else get_keepalive_interval())
        self.token = os.urandom(16).hex()
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self._listener = None
        self._stop_event = threading.Event()
        self._handler_threads = []
        self._reaper = None
        self._reaper_interval = max(0.5, min(60.0, self.idle_timeout / 2.0))

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
        log("daemon started on 127.0.0.1:%d pid=%d version=%s idle_timeout=%ds keepalive=%.1fs" % (
            port, os.getpid(), VERSION, self.idle_timeout, self.keepalive_interval),
            self.state_dir)
        return port

    def _write_state_file(self, port):
        write_json_atomic(state_path(self.state_dir), {
            "port": port,
            "pid": os.getpid(),
            "token": self.token,
            "version": VERSION,
            "keepalive_interval": self.keepalive_interval,
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
        """Remove a session from the registry and close its SSH client."""
        with self.sessions_lock:
            session = self.sessions.pop(conn_id, None)
        if session is not None:
            log("closing session %s (%s) reason=%s" % (
                conn_id, session.describe(), reason), self.state_dir)
            session.close()
        return session is not None

    # -- reaper --------------------------------------------------------------

    def _reaper_loop(self):
        while not self._stop_event.is_set():
            time.sleep(self._reaper_interval)
            now = time.time()
            with self.sessions_lock:
                stale = [cid for cid, session in self.sessions.items()
                         if not session.busy and session.idle_seconds(now) > self.idle_timeout]
            for cid in stale:
                self.close_session(cid, "idle timeout")
                log("session %s reaped (idle > %ds)" % (cid, self.idle_timeout), self.state_dir)

    # -- SSH session setup ----------------------------------------------------

    def open_session(self, host, port, username, password, decoder=None,
                     key_path=None, key_passphrase=None, use_agent=False,
                     known_hosts=None, no_host_key_check=False):
        """Create a paramiko connection and register it. Raises on failure."""
        client = paramiko.SSHClient()
        pkey = None
        try:
            # A bad --known-hosts path must surface as a connect error, not
            # kill the handler thread and leave the client waiting.
            auth.configure_host_keys(client, known_hosts=known_hosts,
                                     no_host_key_check=no_host_key_check)
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
        except auth.AuthError:
            raise
        except paramiko.BadHostKeyException as exc:
            raise SSHConnectError(
                "host key mismatch for %s:%s (expected %s, got %s)" % (
                    host, port, exc.expected_key.get_name(), exc.key.get_name()))
        except paramiko.AuthenticationException as exc:
            raise SSHConnectError(
                "认证失败/Authentication failed for %s@%s:%s: %s" % (
                    username, host, port, exc))
        except (paramiko.SSHException, socket.error, OSError) as exc:
            if "not found in known_hosts" in str(exc):
                raise SSHConnectError(auth.unknown_host_hint(host, port))
            if known_hosts and not no_host_key_check:
                hint = "known_hosts file not readable: %s" % known_hosts
                if isinstance(exc, FileNotFoundError) or "known_hosts" in str(exc):
                    raise SSHConnectError(hint)
            raise SSHConnectError(
                "连接失败/Connection failed for %s@%s:%s: %s" % (username, host, port, exc))

        conn_id = str(uuid.uuid4())
        now = time.time()
        session = Session(
            conn_id, client, host, port, username, now,
            decoder if decoder is not None else AdaptiveDecoder(),
            key_path=key_path,
            auth_mode="key" if (key_path or use_agent) else "password",
        )
        with self.sessions_lock:
            self.sessions[conn_id] = session
        log("session %s opened (%s, auth=%s)" % (
            conn_id, session.describe(), session.auth_mode), self.state_dir)
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
                                           "message": "internal error: %s" % exc})
                    log("handler error: %s" % exc, self.state_dir)
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, conn, req):
        if not isinstance(req, dict) or req.get("token") != self.token:
            self._safe_send(conn, {"type": "error", "message": "invalid token"})
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
        elif op == "stop":
            self._safe_send(conn, {"ok": True})
            threading.Thread(target=self.stop, daemon=True).start()
        else:
            self._safe_send(conn, {"type": "error", "message": "unknown op: %s" % op})

    def _safe_send(self, conn, obj):
        try:
            send_frame(conn, obj)
        except OSError:
            pass

    def _handle_connect(self, conn, req):
        host = req.get("host")
        port = int(req.get("port") or 22)
        user = req.get("user")
        password = req.get("password") or ""
        encoding = req.get("encoding")
        if not (host and user):
            self._safe_send(conn, {"ok": False, "error": "host and user required"})
            return
        decoder = None
        if encoding and encoding != "auto":
            decoder = AdaptiveDecoder(encoding=encoding)
        try:
            session = self.open_session(
                host, port, user, password, decoder=decoder,
                key_path=req.get("key_path"),
                key_passphrase=req.get("key_passphrase"),
                use_agent=bool(req.get("use_agent")),
                known_hosts=req.get("known_hosts"),
                no_host_key_check=bool(req.get("no_host_key_check")),
            )
        except (SSHConnectError, auth.AuthError) as exc:
            self._safe_send(conn, {"ok": False, "error": str(exc)})
            return
        self._safe_send(conn, {"ok": True, "id": session.id})

    def _handle_close(self, conn, req):
        conn_id = req.get("id")
        if conn_id not in self._session_ids():
            self._safe_send(conn, {"ok": False,
                                   "error": "unknown connection id: %s" % conn_id})
            return
        self.close_session(conn_id, "client close")
        self._safe_send(conn, {"ok": True})

    def _handle_list(self, conn):
        now = time.time()
        with self.sessions_lock:
            items = [session.to_info(now) for session in self.sessions.values()]
        self._safe_send(conn, {"ok": True, "sessions": items})

    def _session_ids(self):
        with self.sessions_lock:
            return set(self.sessions)

    # -- exec -----------------------------------------------------------------

    def _handle_exec(self, conn, req):
        conn_id = req.get("id")
        command = req.get("command")
        timeout = req.get("timeout")
        with self.sessions_lock:
            session = self.sessions.get(conn_id)
        if session is None:
            self._safe_send(conn, {"type": "error",
                                   "message": "unknown or expired connection id: %s" % conn_id})
            return
        session.last_activity = time.time()
        self._exec_channel(conn, session, command, timeout)

    def _exec_channel(self, conn, session, command, timeout):
        """Open a channel and stream output back on ``conn`` in real time."""
        chan = None
        status = 1
        # Commands on one connection are serialized, but a queued client must
        # not be left staring at a silent socket: keep it alive while we wait.
        while not session.lock.acquire(timeout=self.keepalive_interval):
            self._safe_send(conn, {"type": "keepalive"})
        try:
            session.busy = True
            try:
                session.reset_decoders()
                transport = session.client.get_transport()
                if transport is None or not transport.is_active():
                    self._safe_send(conn, {"type": "error",
                                           "message": "connection closed: %s" % session.describe()})
                    return
                chan = transport.open_session()
                chan.exec_command(command)
                start = time.time()
                deadline = start + timeout if timeout is not None else None
                last_emit = start
                timed_out = False
                while True:
                    if self._drain_available(conn, session, chan):
                        last_emit = time.time()
                    if chan.exit_status_ready():
                        break
                    now = time.time()
                    if now - last_emit >= self.keepalive_interval:
                        self._safe_send(conn, {"type": "keepalive"})
                        last_emit = now
                    try:
                        select.select([chan], [], [], DRAIN_TIMEOUT)
                    except (OSError, ValueError):
                        if chan.exit_status_ready():
                            break
                        return  # channel closed abnormally
                    if deadline is not None and time.time() > deadline:
                        timed_out = True
                        elapsed = int(time.time() - start)
                        self._emit_data(conn, session,
                                        b"[timeout after %ds]\n" % elapsed, "stderr")
                        try:
                            chan.close()
                        except (OSError, paramiko.SSHException):
                            pass
                        break
                if timed_out:
                    status = 124
                else:
                    self._drain_available(conn, session, chan)
                    for stream, tail in session.flush_decoders():
                        self._safe_send(conn, {"type": "data", "stream": stream,
                                               "text": tail})
                    try:
                        status = chan.recv_exit_status()
                    except (socket.timeout, OSError, paramiko.SSHException):
                        status = 1
                self._safe_send(conn, {"type": "done", "exit_status": status})
                # Log a digest, never the command text: commands often carry secrets.
                digest = hashlib.sha256((command or "").encode("utf-8")).hexdigest()[:12]
                log("exec id=%s cmd_len=%d cmd_sha=%s exit=%d" % (
                    session.id, len(command or ""), digest, status), self.state_dir)
            except ConnectionResetError:
                return  # client went away mid-stream
            except (OSError, socket.error, paramiko.SSHException) as exc:
                self._safe_send(conn, {"type": "error", "message": "exec error: %s" % exc})
            finally:
                session.busy = False
                session.last_activity = time.time()
                if chan is not None:
                    try:
                        chan.close()
                    except (OSError, paramiko.SSHException):
                        pass
        finally:
            session.lock.release()

    def _drain_available(self, conn, session, chan):
        """Forward any ready stdout/stderr data. Returns True if anything was sent."""
        emitted = False
        while chan.recv_ready():
            raw = chan.recv(65536)
            if not raw:
                break
            self._emit_data(conn, session, raw, "stdout")
            emitted = True
        while chan.recv_stderr_ready():
            raw = chan.recv_stderr(65536)
            if not raw:
                break
            self._emit_data(conn, session, raw, "stderr")
            emitted = True
        return emitted

    def _emit_data(self, conn, session, raw, stream):
        """Decode a raw chunk with the session decoder and forward it."""
        if not raw:
            return
        text = session.decoder_for(stream).decode(raw)
        if text:
            self._safe_send(conn, {"type": "data", "stream": stream, "text": text})
