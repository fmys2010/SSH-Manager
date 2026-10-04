# -*- coding: utf-8 -*-
"""
Test suite for the SSH Connection Manager.

Starts a fake paramiko SSH server (with PTY, stdin and SFTP support) so no real
SSH server or network is needed. Run with:

    python scripts/test_ssh_manager.py

For smoke-testing the real CLI (not run during unittest):

    python scripts/test_ssh_manager.py --smoke
"""

import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import paramiko

from ssh_manager import VERSION, auth, protocol
from ssh_manager.client import DaemonClient
from ssh_manager.config import STATE_DIR_ENV, log as write_log
from ssh_manager.daemon import Daemon
from ssh_manager.encoding import AdaptiveDecoder, make_stream_decoders
from ssh_manager.errors import ConnectError, SSHConnectError, SessionError
from ssh_manager.jobs import Job, JobRegistry

FAKE_USER = "testuser"
FAKE_PASS = "testpass"


# ---------------------------------------------------------------------------
# Fake SFTP server backed by a local directory
# ---------------------------------------------------------------------------

class _SFTPHandle(paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError:
            return paramiko.SFTP_FAILURE

    def chattr(self, attr):
        return paramiko.SFTP_OK


def _make_sftp_interface(root):
    class _LocalSFTPInterface(paramiko.SFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            paramiko.SFTPServerInterface.__init__(self, server, *args, **kwargs)
            self.root = root

        def _real(self, path):
            return os.path.join(self.root, self.canonicalize(path).lstrip("/"))

        def list_folder(self, path):
            real = self._real(path)
            try:
                names = os.listdir(real)
            except OSError:
                return paramiko.SFTP_NO_SUCH_FILE
            entries = []
            for name in names:
                attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(real, name)))
                attr.filename = name
                entries.append(attr)
            return entries

        def stat(self, path):
            try:
                return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
            except OSError:
                return paramiko.SFTP_NO_SUCH_FILE

        def lstat(self, path):
            return self.stat(path)

        def open(self, path, flags, attr):
            real = self._real(path)
            try:
                flags |= getattr(os, "O_BINARY", 0)
                mode = getattr(attr, "st_mode", None) or 0o666
                fd = os.open(real, flags, mode)
            except OSError:
                return paramiko.SFTP_FAILURE
            handle_mode = "rb"
            if flags & os.O_WRONLY:
                handle_mode = "wb"
            elif flags & os.O_RDWR:
                handle_mode = "r+b"
            fileobj = os.fdopen(fd, handle_mode)
            handle = _SFTPHandle()
            handle.readfile = fileobj
            handle.writefile = fileobj
            return handle

        def remove(self, path):
            try:
                os.remove(self._real(path))
                return paramiko.SFTP_OK
            except OSError:
                return paramiko.SFTP_FAILURE

        def mkdir(self, path, attr):
            try:
                os.mkdir(self._real(path), getattr(attr, "st_mode", None) or 0o777)
                return paramiko.SFTP_OK
            except OSError:
                return paramiko.SFTP_FAILURE

        def rmdir(self, path):
            try:
                os.rmdir(self._real(path))
                return paramiko.SFTP_OK
            except OSError:
                return paramiko.SFTP_FAILURE

    return _LocalSFTPInterface


# ---------------------------------------------------------------------------
# Fake SSH server
# ---------------------------------------------------------------------------

class FakeServerInterface(paramiko.ServerInterface):
    """Paramiko server interface supporting password/public-key auth, PTY and SFTP."""

    def __init__(self, authorized_key=None, sftp_root=None):
        self.authorized_key = authorized_key
        self.sftp_root = sftp_root

    def check_auth_password(self, username, password):
        if username == FAKE_USER and password == FAKE_PASS:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if (username == FAKE_USER and self.authorized_key is not None
                and key.get_base64() == self.authorized_key.get_base64()):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        if isinstance(term, bytes):
            term = term.decode("utf-8", "replace")
        channel._fake_pty = (term, width, height)
        return True

    def check_channel_subsystem_request(self, channel, name):
        if name == "sftp" and self.sftp_root is not None:
            channel.get_transport().set_subsystem_handler(
                "sftp", paramiko.SFTPServer, _make_sftp_interface(self.sftp_root))
            # The base implementation is what actually creates and starts the
            # handler; returning True without it leaves the client hanging.
            return paramiko.ServerInterface.check_channel_subsystem_request(
                self, channel, name)
        return False

    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode("utf-8", errors="replace")
        threading.Thread(target=self._run_command, args=(channel, cmd_str),
                         daemon=True).start()
        return True

    def _run_command(self, channel, command):
        time.sleep(0.05)  # let the exec ACK go out before any close
        try:
            if command == "echo hello":
                channel.send(b"hello\n")
                channel.send_exit_status(0)
            elif command == "chinese_utf8":
                channel.send("你好世界\n".encode("utf-8"))
                channel.send_exit_status(0)
            elif command == "chinese_gbk":
                channel.send("中文测试\n".encode("gbk"))
                channel.send_exit_status(0)
            elif command == "tty_info":
                pty = getattr(channel, "_fake_pty", None)
                if pty:
                    channel.send(("tty=%s %dx%d\n" % pty).encode("utf-8"))
                else:
                    channel.send(b"no-tty\n")
                channel.send_exit_status(0)
            elif command == "cat":
                deadline = time.time() + 15
                while time.time() < deadline:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if not data:
                            break
                        channel.send(data)
                    elif channel.eof_received:
                        break
                    else:
                        time.sleep(0.02)
                channel.send_exit_status(0)
            elif command == "big_output":
                data = b"abcde\n" * 33333  # ~200KB
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset + 65536]
                    sent = channel.send(chunk)
                    offset += sent if sent else len(chunk)
                channel.send_exit_status(0)
            elif command == "slow_stream":
                for _ in range(5):
                    time.sleep(0.15)
                    channel.send(b"tick\n")
                channel.send_exit_status(0)
            elif command == "stream_ticks":
                for index in range(5):
                    time.sleep(0.1)
                    channel.send(("tick%d\n" % index).encode("ascii"))
                channel.send_exit_status(0)
            elif command == "flood":
                for _ in range(200):
                    channel.send(b"x" * 1024)
                channel.send_exit_status(0)
            elif command == "stderr_and_stdout":
                channel.send_stderr(b"ERR from fake\n")
                channel.send(b"OUT from fake\n")
                channel.send_exit_status(0)
            elif command == "exit_42":
                channel.send_exit_status(42)
            elif command.startswith("sleep "):
                time.sleep(float(command.split(None, 1)[1]))
                channel.send_exit_status(0)
            elif command == "hang":
                time.sleep(3600)
                channel.send_exit_status(0)
            else:
                channel.send(b"unknown command: %s\n" % command.encode("utf-8"))
                channel.send_exit_status(1)
        except Exception:
            pass
        finally:
            try:
                channel.close()
            except Exception:
                pass


class FakeSSHServer(object):
    """Paramiko-based fake SSH server. The actual port is ``.port``."""

    def __init__(self, authorized_key=None, sftp_root=None):
        self.host_key = paramiko.RSAKey.generate(2048)
        self.authorized_key = authorized_key
        self.sftp_root = sftp_root
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._transports = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=FakeServerInterface(
                    authorized_key=self.authorized_key, sftp_root=self.sftp_root))
            except Exception:
                pass

    def stop(self):
        self._stop.set()
        for transport in self._transports:
            try:
                transport.close()
            except Exception:
                pass
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _temp_dir(prefix):
    return tempfile.mkdtemp(prefix="sshm_%s_" % prefix)


def _cleanup_dir(path):
    for _ in range(10):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path):
            return
        time.sleep(0.2)


def _write_known_hosts(path, host_key, port, hostname="127.0.0.1"):
    keys = paramiko.HostKeys()
    keys.add("[%s]:%d" % (hostname, port), host_key.get_name(), host_key)
    keys.save(path)
    return path


def _start_daemon(state_dir, **kwargs):
    daemon = Daemon(state_dir=state_dir, **kwargs)
    threading.Thread(target=daemon.serve_forever, daemon=True).start()
    time.sleep(0.3)
    client = DaemonClient(state_dir=state_dir)
    for _ in range(40):
        if client._daemon_alive():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("daemon failed to start")
    return daemon, client


def _connect(client, fake, **kwargs):
    kwargs.setdefault("no_host_key_check", True)
    return client.connect("127.0.0.1", fake.port, FAKE_USER, FAKE_PASS, **kwargs)["id"]


# ---------------------------------------------------------------------------
# AdaptiveDecoder / stream decoders
# ---------------------------------------------------------------------------

class TestAdaptiveDecoder(unittest.TestCase):

    def test_utf8_split_across_chunks(self):
        decoder = AdaptiveDecoder()
        first = decoder.decode(b"\xe4\xb8")
        second = decoder.decode(b"\xad")
        self.assertEqual(first + second, "中")
        self.assertEqual(decoder._locked, "utf-8")

    def test_gbk_content(self):
        decoder = AdaptiveDecoder()
        self.assertEqual(decoder.decode(b"\xd6\xd0\xce\xc4"), "中文")
        self.assertEqual(decoder._locked, "gbk")

    def test_ascii_then_gbk_locks_late(self):
        decoder = AdaptiveDecoder()
        self.assertEqual(decoder.decode(b"hello "), "hello ")
        self.assertIsNone(decoder._locked)
        self.assertEqual(decoder.decode(b"\xd6\xd0"), "中")
        self.assertEqual(decoder._locked, "gbk")

    def test_binary_junk_never_raises(self):
        decoder = AdaptiveDecoder()
        self.assertIsInstance(decoder.decode(b"\xff\xfe\x01\x80"), str)
        self.assertEqual(decoder._locked, "latin-1")

    def test_forced_encodings(self):
        self.assertEqual(AdaptiveDecoder(encoding="utf-8").decode("你好".encode("utf-8")), "你好")
        self.assertEqual(AdaptiveDecoder(encoding="gbk").decode("中文测试".encode("gbk")), "中文测试")
        self.assertEqual(AdaptiveDecoder(encoding="latin-1").decode(b"\xff\xfe\x01"), "\xff\xfe\x01")

    def test_reset_with_forced_encoding(self):
        decoder = AdaptiveDecoder(encoding="gbk")
        decoder.decode("中文".encode("gbk"))
        decoder.reset()
        self.assertEqual(decoder.decode("测试".encode("gbk")), "测试")

    def test_reset_unlocks_auto_detection(self):
        decoder = AdaptiveDecoder()
        decoder.decode(b"\xd6\xd0")
        self.assertEqual(decoder._locked, "gbk")
        decoder.reset()
        self.assertIsNone(decoder._locked)

    def test_flush_emits_pending_bytes(self):
        decoder = AdaptiveDecoder()
        decoder.decode(b"\xe4\xb8")
        self.assertIsInstance(decoder.flush(), str)


class TestStreamDecoders(unittest.TestCase):

    def test_stream_decoders_are_independent(self):
        decoders = make_stream_decoders()
        self.assertEqual(decoders["stdout"].decode(b"\xe4"), "")
        self.assertEqual(decoders["stderr"].decode(b"abc"), "abc")
        self.assertEqual(decoders["stdout"].decode(b"\xb8\xad"), "中")

    def test_forced_encoding_propagates(self):
        decoders = make_stream_decoders("gbk")
        self.assertEqual(decoders["stdout"].decode("中文".encode("gbk")), "中文")
        self.assertEqual(decoders["stderr"].decode("测试".encode("gbk")), "测试")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

class TestAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = _temp_dir("auth")
        cls.key = paramiko.RSAKey.generate(2048)
        cls.plain_path = os.path.join(cls.tmp, "id_rsa")
        cls.key.write_private_key_file(cls.plain_path)
        cls.enc_path = os.path.join(cls.tmp, "id_rsa_enc")
        cls.key.write_private_key_file(cls.enc_path, password="secret")

    @classmethod
    def tearDownClass(cls):
        _cleanup_dir(cls.tmp)

    def test_key_is_encrypted_detects_both_forms(self):
        self.assertFalse(auth.key_is_encrypted(self.plain_path))
        self.assertTrue(auth.key_is_encrypted(self.enc_path))

    def test_discovery_prefers_unencrypted_key(self):
        ssh_dir = _temp_dir("sshdir")
        try:
            shutil.copy(self.enc_path, os.path.join(ssh_dir, "id_ed25519"))
            shutil.copy(self.plain_path, os.path.join(ssh_dir, "id_rsa"))
            path, passphrase, notes = auth.resolve_private_key(
                auth.KEY_DISCOVER, prompt=None, ssh_dir=ssh_dir)
            self.assertEqual(os.path.basename(path), "id_rsa")
            self.assertIsNone(passphrase)
            self.assertTrue(any("passphrase required" in n for n in notes))
        finally:
            _cleanup_dir(ssh_dir)

    def test_encrypted_key_without_passphrase_is_an_error(self):
        with self.assertRaises(auth.AuthError):
            auth.resolve_private_key(self.enc_path, prompt=None)

    def test_encrypted_key_with_passphrase_loads(self):
        path, passphrase, notes = auth.resolve_private_key(
            self.enc_path, passphrase="secret", prompt=None)
        self.assertEqual(path, self.enc_path)
        self.assertEqual(passphrase, "secret")

    def test_missing_key_is_an_error(self):
        with self.assertRaises(auth.AuthError):
            auth.resolve_private_key(os.path.join(self.tmp, "nope"))

    def test_discovery_without_keys_falls_back_to_agent(self):
        ssh_dir = _temp_dir("empty_ssh")
        try:
            path, passphrase, notes = auth.resolve_private_key(
                auth.KEY_DISCOVER, ssh_dir=ssh_dir)
            self.assertIsNone(path)
            self.assertTrue(any("ssh-agent" in note for note in notes))
        finally:
            _cleanup_dir(ssh_dir)

    def test_fingerprint_is_openssh_style(self):
        fingerprint = auth.fingerprint_sha256(self.key)
        self.assertTrue(fingerprint.startswith("SHA256:"))
        self.assertNotIn("=", fingerprint)

    def test_append_known_hosts_uses_brackets_for_nonstandard_port(self):
        path = os.path.join(self.tmp, "known_hosts_append")
        auth.append_known_hosts(path, "127.0.0.1", 2222, self.key)
        auth.append_known_hosts(path, "example.com", 22, self.key)
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        self.assertTrue(lines[0].startswith("[127.0.0.1]:2222 ssh-rsa "))
        self.assertTrue(lines[1].startswith("example.com ssh-rsa "))


# ---------------------------------------------------------------------------
# Protocol / job buffer units
# ---------------------------------------------------------------------------

class TestProtocol(unittest.TestCase):

    def test_oversized_frame_is_rejected(self):
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack(">I", protocol.MAX_FRAME_BYTES + 1))
            with self.assertRaises(protocol.ProtocolError):
                protocol.recv_frame(right)
        finally:
            left.close()
            right.close()

    def test_round_trip(self):
        left, right = socket.socketpair()
        try:
            protocol.send_frame(left, {"op": "ping", "text": "中文"})
            self.assertEqual(protocol.recv_frame(right)["text"], "中文")
        finally:
            left.close()
            right.close()


class TestJobBuffer(unittest.TestCase):

    def test_ring_buffer_drops_oldest(self):
        job = Job("j1", "s1", "cmd", max_bytes=100)
        job.append("stdout", "a" * 60)
        job.append("stdout", "b" * 60)
        chunks, seq = job.snapshot()
        self.assertEqual(seq, 2)
        self.assertEqual(len(chunks), 1)
        self.assertTrue(chunks[0][2].startswith("b"))

    def test_single_oversized_chunk_is_truncated(self):
        """chan.recv can return one chunk larger than the whole budget."""
        job = Job("j1", "s1", "cmd", max_bytes=100)
        job.append("stdout", "x" * 500)
        chunks, seq = job.snapshot()
        self.assertEqual(len(chunks), 1)
        self.assertLessEqual(len(chunks[0][2].encode("utf-8")), 100)
        self.assertGreater(len(chunks[0][2]), 0)

    def test_truncation_keeps_multibyte_characters_valid(self):
        job = Job("j1", "s1", "cmd", max_bytes=64)
        job.append("stdout", "中" * 100)
        chunks, _seq = job.snapshot()
        text = chunks[0][2]
        self.assertLessEqual(len(text.encode("utf-8")), 64)
        self.assertTrue(text)

    def test_finish_wakes_followers(self):
        job = Job("j1", "s1", "cmd", max_bytes=1000)
        seen = []

        def follower():
            chunks, seq, finished = job.wait_for_update(0, timeout=5)
            seen.append((len(chunks), finished))

        thread = threading.Thread(target=follower)
        thread.start()
        time.sleep(0.1)
        job.append("stdout", "hello")
        thread.join(timeout=5)
        self.assertEqual(seen[0][0], 1)

    def test_registry_prune_session(self):
        registry = JobRegistry(max_bytes=1000)
        job = registry.create("s1", "cmd")
        registry.create("s2", "cmd")
        registry.prune_session("s1")
        self.assertIsNone(registry.get(job.id))
        self.assertEqual(len(registry.list()), 1)


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

class TestIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("state")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def setUp(self):
        self.conn_id = _connect(self.client, self.fake)

    def tearDown(self):
        try:
            self.client.close(self.conn_id)
        except Exception:
            pass

    def _exec_get_output(self, conn_id, command, timeout=None):
        stdout, stderr, status = [], [], 1
        for tag, text in self.client.exec_stream(conn_id, command, timeout=timeout):
            if tag == "RETURN":
                status = text
            elif tag == "OUT: ":
                stdout.append(text)
            elif tag == "ERR: ":
                stderr.append(text)
        return status, "".join(stdout), "".join(stderr)

    def test_connect_and_list(self):
        self.assertIn(self.conn_id, [s["id"] for s in self.client.list()])

    def test_list_timestamp_and_state(self):
        session = [s for s in self.client.list() if s["id"] == self.conn_id][0]
        self.assertRegex(session["connected_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
        self.assertEqual(session["state"], "alive")

    def test_connect_wrong_password(self):
        with self.assertRaises(SSHConnectError):
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, "wrongpass",
                                no_host_key_check=True)

    def test_exec_echo(self):
        status, out, err = self._exec_get_output(self.conn_id, "echo hello")
        self.assertEqual((status, out), (0, "hello\n"))

    def test_exec_chinese_utf8_and_gbk(self):
        self.assertEqual(self._exec_get_output(self.conn_id, "chinese_utf8")[1], "你好世界\n")
        self.assertEqual(self._exec_get_output(self.conn_id, "chinese_gbk")[1], "中文测试\n")

    def test_exec_big_output(self):
        collected = [text for tag, text in self.client.exec_stream(self.conn_id, "big_output")
                     if tag == "OUT: "]
        self.assertAlmostEqual(len("".join(collected)), 199998, delta=5)

    def test_exec_stderr_and_stdout(self):
        stdout, stderr = [], []
        for tag, text in self.client.exec_stream(self.conn_id, "stderr_and_stdout"):
            if tag == "OUT: ":
                stdout.append(text)
            elif tag == "ERR: ":
                stderr.append(text)
        self.assertEqual("".join(stdout), "OUT from fake\n")
        self.assertEqual("".join(stderr), "ERR from fake\n")

    def test_exec_exit_42(self):
        self.assertEqual(self._exec_get_output(self.conn_id, "exit_42")[0], 42)

    def test_exec_timeout_returns_124(self):
        status, out, err = self._exec_get_output(self.conn_id, "hang", timeout=1)
        self.assertEqual(status, 124)
        self.assertIn("timeout after", err)

    def test_exec_timeout_leaves_daemon_log_clean(self):
        self._exec_get_output(self.conn_id, "hang", timeout=1)
        time.sleep(0.3)
        with open(os.path.join(self.state_dir, "daemon.log"),
                  encoding="utf-8", errors="replace") as handle:
            contents = handle.read()
        self.assertNotIn("Traceback", contents)
        self.assertNotIn("UnboundLocalError", contents)

    def test_silent_command_survives_keepalive_window(self):
        self.assertEqual(self._exec_get_output(self.conn_id, "sleep 2")[0], 0)

    def test_close_by_id_and_unknown(self):
        self.client.close(self.conn_id)
        with self.assertRaises(SessionError):
            self._exec_get_output(self.conn_id, "echo hello")
        with self.assertRaises(SessionError):
            self.client.close("nonexistent-id")


class TestNaming(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("name_state")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def test_named_session_is_addressable_and_unique(self):
        conn_id = _connect(self.client, self.fake, name="prod-web")
        try:
            session = [s for s in self.client.list() if s["id"] == conn_id][0]
            self.assertEqual(session["name"], "prod-web")
            status = None
            for tag, text in self.client.exec_stream("prod-web", "echo hello"):
                if tag == "RETURN":
                    status = text
            self.assertEqual(status, 0)
            with self.assertRaises(ConnectError) as ctx:
                _connect(self.client, self.fake, name="prod-web")
            self.assertEqual(ctx.exception.code, "duplicate_name")
        finally:
            self.client.close("prod-web")
        self.assertEqual([s for s in self.client.list() if s.get("name") == "prod-web"], [])

    def test_invalid_name_is_rejected(self):
        with self.assertRaises(ConnectError) as ctx:
            _connect(self.client, self.fake, name="bad name!")
        self.assertEqual(ctx.exception.code, "bad_name")


class TestPtyAndStdin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("pty_state")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def setUp(self):
        self.conn_id = _connect(self.client, self.fake)

    def tearDown(self):
        try:
            self.client.close(self.conn_id)
        except Exception:
            pass

    def _collect(self, command, **kwargs):
        stdout, status = [], 1
        for tag, text in self.client.exec_stream(self.conn_id, command, **kwargs):
            if tag == "RETURN":
                status = text
            elif tag == "OUT: ":
                stdout.append(text)
        return status, "".join(stdout)

    def test_pty_is_allocated(self):
        status, out = self._collect("tty_info",
                                    pty={"term": "vt100", "width": 100, "height": 40})
        self.assertEqual(status, 0)
        self.assertIn("tty=vt100 100x40", out)

    def test_no_pty_by_default(self):
        status, out = self._collect("tty_info")
        self.assertEqual(out, "no-tty\n")

    def test_stdin_is_streamed(self):
        import io as _io
        payload = b"line one\nline two\n"
        status, out = self._collect("cat", stdin_source=_io.BytesIO(payload))
        self.assertEqual(status, 0)
        self.assertEqual(out.encode("utf-8"), payload)


class TestBackgroundJobs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("bg_state")
        cls.daemon, cls.client = _start_daemon(
            cls.state_dir, idle_timeout=600, job_buffer_bytes=4096)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def setUp(self):
        self.conn_id = _connect(self.client, self.fake)

    def tearDown(self):
        try:
            self.client.close(self.conn_id)
        except Exception:
            pass

    def test_background_job_returns_id_and_logs(self):
        job_id = self.client.exec_background(self.conn_id, "stream_ticks")
        self.assertTrue(job_id)
        time.sleep(1.5)
        frames, _seq, info = self.client.job_logs(job_id)
        self.assertEqual(info["status"], "done")
        self.assertEqual(info["exit_status"], 0)
        text = "".join(chunk for _tag, chunk in frames)
        self.assertIn("tick0", text)
        self.assertIn("tick4", text)

    def test_jobs_listing(self):
        job_id = self.client.exec_background(self.conn_id, "echo hello")
        time.sleep(0.8)
        jobs = {job["job_id"]: job for job in self.client.jobs()}
        self.assertIn(job_id, jobs)
        self.assertEqual(jobs[job_id]["status"], "done")

    def test_follow_streams_until_finished(self):
        job_id = self.client.exec_background(self.conn_id, "stream_ticks")
        chunks, status = [], None
        for tag, text in self.client.job_logs(job_id, follow=True):
            if tag == "RETURN":
                status = text
            else:
                chunks.append(text)
        self.assertEqual(status, 0)
        self.assertIn("tick4", "".join(chunks))

    def test_kill_background_job(self):
        job_id = self.client.exec_background(self.conn_id, "sleep 30")
        time.sleep(0.5)
        info = self.client.job_kill(job_id)
        self.assertEqual(info["job_id"], job_id)
        time.sleep(1.2)
        _frames, _seq, info = self.client.job_logs(job_id)
        self.assertEqual(info["status"], "killed")

    def test_output_buffer_is_bounded(self):
        job_id = self.client.exec_background(self.conn_id, "flood")
        deadline = time.time() + 20
        while time.time() < deadline:
            _frames, _seq, info = self.client.job_logs(job_id)
            if info.get("status") != "running":
                break
            time.sleep(0.3)
        frames, _seq, info = self.client.job_logs(job_id)
        text = "".join(chunk for _tag, chunk in frames)
        self.assertLessEqual(len(text.encode("utf-8")), 4096)
        self.assertGreater(len(text), 0)

    def test_unknown_job(self):
        with self.assertRaises(SessionError):
            self.client.job_logs("nonexistent-job")

    def test_jobs_removed_with_session(self):
        job_id = self.client.exec_background(self.conn_id, "sleep 5")
        self.client.close(self.conn_id)
        self.assertIsNone(self.daemon.jobs.get(job_id))


class TestSftp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.remote_root = _temp_dir("sftp_root")
        cls.fake = FakeSSHServer(sftp_root=cls.remote_root)
        cls.state_dir = _temp_dir("sftp_state")
        cls.local_root = _temp_dir("sftp_local")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)
        _cleanup_dir(cls.remote_root)
        _cleanup_dir(cls.local_root)

    def setUp(self):
        self.conn_id = _connect(self.client, self.fake)

    def tearDown(self):
        try:
            self.client.close(self.conn_id)
        except Exception:
            pass

    def test_put_get_ls_stat_mkdir_rm(self):
        local = os.path.join(self.local_root, "payload.txt")
        with open(local, "wb") as f:
            f.write(b"hello sftp\n")
        result = self.client.sftp("put", self.conn_id, local_path=local,
                                  remote_path="/payload.txt")
        self.assertEqual(result["bytes"], 11)

        listing = self.client.sftp("ls", self.conn_id, path="/")
        names = [entry["name"] for entry in listing["entries"]]
        self.assertIn("payload.txt", names)

        info = self.client.sftp("stat", self.conn_id, path="/payload.txt")
        self.assertFalse(info["is_dir"])
        self.assertEqual(info["size"], 11)

        self.client.sftp("mkdir", self.conn_id, path="/subdir")
        self.assertTrue(self.client.sftp("stat", self.conn_id, path="/subdir")["is_dir"])

        back = os.path.join(self.local_root, "back.txt")
        result = self.client.sftp("get", self.conn_id, remote_path="/payload.txt",
                                  local_path=back)
        self.assertEqual(result["bytes"], 11)
        with open(back, "rb") as handle:
            self.assertEqual(handle.read(), b"hello sftp\n")

        self.client.sftp("rm", self.conn_id, path="/payload.txt")
        with self.assertRaises(ConnectError) as ctx:
            self.client.sftp("stat", self.conn_id, path="/payload.txt")
        self.assertEqual(ctx.exception.code, "sftp_error")

    def test_put_missing_local_file_fails_cleanly(self):
        with self.assertRaises(ConnectError):
            self.client.sftp("put", self.conn_id,
                             local_path=os.path.join(self.local_root, "nope.bin"),
                             remote_path="/nope.bin")


class TestConcurrency(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("conc_state")
        cls.daemon, cls.client = _start_daemon(
            cls.state_dir, idle_timeout=600, max_channels=3)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def test_more_parallel_execs_than_channel_limit(self):
        conn_id = _connect(self.client, self.fake)
        results = {}

        def run(index):
            status = None
            for tag, text in self.client.exec_stream(conn_id, "sleep 1"):
                if tag == "RETURN":
                    status = text
            results[index] = status

        threads = [threading.Thread(target=run, args=(index,)) for index in range(9)]
        started = time.time()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=40)
        elapsed = time.time() - started
        self.assertEqual(len(results), 9)
        self.assertEqual(set(results.values()), {0})
        # 9 commands, 3 slots, 1s each -> at least 3 rounds, well under 9s serialised
        self.assertGreaterEqual(elapsed, 2.5)
        self.assertLess(elapsed, 8.0)


class TestHealthDetection(unittest.TestCase):

    def test_dead_transport_is_evicted(self):
        fake = FakeSSHServer()
        state_dir = _temp_dir("health_state")
        daemon, client = _start_daemon(state_dir, idle_timeout=2)
        try:
            conn_id = _connect(client, fake)
            fake.stop()
            deadline = time.time() + 15
            while time.time() < deadline:
                if conn_id not in [s["id"] for s in client.list()]:
                    break
                time.sleep(0.5)
            self.assertNotIn(conn_id, [s["id"] for s in client.list()])
            with self.assertRaises(SessionError):
                for _ in client.exec_stream(conn_id, "echo hello"):
                    pass
        finally:
            try:
                daemon.stop()
            except Exception:
                pass
            try:
                fake.stop()
            except Exception:
                pass
            _cleanup_dir(state_dir)


class TestHostKeyVerification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("hostkey_state")
        cls.tmp = _temp_dir("hostkey")
        cls.known_hosts = _write_known_hosts(
            os.path.join(cls.tmp, "known_hosts"), cls.fake.host_key, cls.fake.port)
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)
        _cleanup_dir(cls.tmp)

    def test_unknown_host_reports_fingerprint(self):
        with self.assertRaises(ConnectError) as ctx:
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS)
        self.assertEqual(ctx.exception.code, "unknown_host")
        self.assertTrue(ctx.exception.details["fingerprint"].startswith("SHA256:"))
        self.assertEqual(ctx.exception.details["key_type"], self.fake.host_key.get_name())

    def test_known_hosts_match_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            known_hosts=self.known_hosts)["id"]
        self.client.close(conn_id)

    def test_accept_host_key_persists(self):
        target = os.path.join(self.tmp, "accepted_known_hosts")
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            known_hosts=target, accept_host_key=True)["id"]
        self.client.close(conn_id)
        self.assertTrue(os.path.isfile(target))
        with open(target, encoding="utf-8") as handle:
            self.assertIn("ssh-rsa", handle.read())
        # A second connection no longer needs the flag.
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            known_hosts=target)["id"]
        self.client.close(conn_id)

    def test_changed_host_key_is_always_rejected(self):
        # A different server whose known_hosts entry holds the wrong key.
        other = FakeSSHServer()
        wrong = paramiko.RSAKey.generate(2048)
        wrong_hosts = _write_known_hosts(
            os.path.join(self.tmp, "wrong_hosts"), wrong, other.port)
        try:
            with self.assertRaises(ConnectError) as ctx:
                self.client.connect("127.0.0.1", other.port, FAKE_USER, FAKE_PASS,
                                    known_hosts=wrong_hosts, accept_host_key=True)
            self.assertEqual(ctx.exception.code, "host_key_mismatch")
        finally:
            other.stop()

    def test_missing_known_hosts_file_reports_error(self):
        missing = os.path.join(self.tmp, "does_not_exist")
        with self.assertRaises(SSHConnectError) as ctx:
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
                                known_hosts=missing)
        self.assertIn("known_hosts", str(ctx.exception).lower())

    def test_no_host_key_check_escape_hatch(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            no_host_key_check=True)["id"]
        self.client.close(conn_id)


class TestKeyAuthentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)
        cls.other_key = paramiko.RSAKey.generate(2048)
        cls.tmp = _temp_dir("keys")
        cls.plain_path = os.path.join(cls.tmp, "id_rsa")
        cls.key.write_private_key_file(cls.plain_path)
        cls.enc_path = os.path.join(cls.tmp, "id_rsa_enc")
        cls.key.write_private_key_file(cls.enc_path, password="secret")
        cls.fake = FakeSSHServer(authorized_key=cls.key)
        cls.state_dir = _temp_dir("key_state")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)
        _cleanup_dir(cls.tmp)

    def test_key_auth_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, "", key_path=self.plain_path,
            no_host_key_check=True)["id"]
        session = [s for s in self.client.list() if s["id"] == conn_id][0]
        self.assertEqual(session["auth_mode"], "key")
        self.client.close(conn_id)

    def test_encrypted_key_with_passphrase_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, "", key_path=self.enc_path,
            key_passphrase="secret", no_host_key_check=True)["id"]
        self.client.close(conn_id)

    def test_unauthorized_key_is_rejected(self):
        other = os.path.join(self.tmp, "other")
        self.other_key.write_private_key_file(other)
        with self.assertRaises(SSHConnectError):
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, "",
                                key_path=other, no_host_key_check=True)

    def test_password_still_works_without_key(self):
        conn_id = _connect(self.client, self.fake)
        session = [s for s in self.client.list() if s["id"] == conn_id][0]
        self.assertEqual(session["auth_mode"], "password")
        self.client.close(conn_id)


class TestIdleTimeout(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("idle_state")
        cls.daemon, cls.client = _start_daemon(cls.state_dir, idle_timeout=1)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def test_idle_reaper_reaps(self):
        conn_id = _connect(self.client, self.fake)
        time.sleep(2.5)
        with self.assertRaises(SessionError):
            for _ in self.client.exec_stream(conn_id, "echo hello"):
                pass
        self.assertNotIn(conn_id, [s["id"] for s in self.client.list()])

    def test_busy_session_is_not_reaped(self):
        conn_id = _connect(self.client, self.fake)
        try:
            status = [None]

            def run():
                for tag, text in self.client.exec_stream(conn_id, "sleep 3"):
                    if tag == "RETURN":
                        status[0] = text

            worker = threading.Thread(target=run)
            worker.start()
            time.sleep(2.0)
            self.assertIn(conn_id, [s["id"] for s in self.client.list()])
            worker.join(timeout=15)
            self.assertEqual(status[0], 0)
        finally:
            try:
                self.client.close(conn_id)
            except Exception:
                pass


class TestKeepalive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("keepalive_state")
        cls.daemon, cls.client = _start_daemon(
            cls.state_dir, idle_timeout=600, keepalive_interval=0.5)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        cls.fake.stop()
        _cleanup_dir(cls.state_dir)

    def test_keepalive_frame_arrives_during_silence(self):
        conn_id = _connect(self.client, self.fake)
        try:
            sock = self.client._send_and_get_sock(
                {"op": "exec", "id": conn_id, "command": "sleep 3", "timeout": None})
            sock.settimeout(5.0)
            try:
                saw_keepalive = False
                while True:
                    frame = protocol.recv_frame(sock)
                    self.assertIsNotNone(frame)
                    if frame.get("type") == "keepalive":
                        saw_keepalive = True
                        break
                    if frame.get("type") in ("done", "error"):
                        break
                self.assertTrue(saw_keepalive)
            finally:
                sock.close()
        finally:
            self.client.close(conn_id)

    def test_queued_exec_is_kept_alive_while_waiting(self):
        conn_id = _connect(self.client, self.fake)
        try:
            results = {}

            def run(name, command):
                status = None
                for tag, text in self.client.exec_stream(conn_id, command):
                    if tag == "RETURN":
                        status = text
                results[name] = status

            first = threading.Thread(target=run, args=("first", "sleep 3"))
            first.start()
            time.sleep(0.3)
            second = threading.Thread(target=run, args=("second", "echo hello"))
            second.start()
            first.join(timeout=20)
            second.join(timeout=20)
            self.assertEqual(results.get("first"), 0)
            self.assertEqual(results.get("second"), 0)
        finally:
            try:
                self.client.close(conn_id)
            except Exception:
                pass


class TestLogRotation(unittest.TestCase):

    def test_log_rotates_and_tail_reads(self):
        state_dir = _temp_dir("logrot")
        try:
            old = os.environ.get("SSH_MANAGER_LOG_MAX_KB")
            os.environ["SSH_MANAGER_LOG_MAX_KB"] = "1"
            try:
                for index in range(400):
                    write_log("line %d %s" % (index, "x" * 80), state_dir)
            finally:
                if old is None:
                    os.environ.pop("SSH_MANAGER_LOG_MAX_KB", None)
                else:
                    os.environ["SSH_MANAGER_LOG_MAX_KB"] = old
            self.assertTrue(os.path.isfile(os.path.join(state_dir, "daemon.log.1")))
        finally:
            _cleanup_dir(state_dir)


class TestConcurrentColdStart(unittest.TestCase):

    def test_only_one_daemon_is_spawned(self):
        state_dir = _temp_dir("coldstart_state")
        spawns = []
        original = DaemonClient._spawn_daemon

        def counting_spawn(self):
            spawns.append(1)
            return original(self)

        DaemonClient._spawn_daemon = counting_spawn
        try:
            clients = [DaemonClient(state_dir=state_dir) for _ in range(4)]
            errors = []

            def boot(client):
                try:
                    client.ensure_daemon()
                except Exception as exc:  # pragma: no cover - diagnostic only
                    errors.append(exc)

            threads = [threading.Thread(target=boot, args=(c,)) for c in clients]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
            self.assertEqual(errors, [])
            self.assertEqual(len(spawns), 1, "expected exactly one daemon spawn")
            self.assertTrue(clients[0]._daemon_alive())
            clients[0].stop()
            for client in clients:
                child = getattr(client, "_child", None)
                if child is not None:
                    try:
                        child.wait(timeout=15)
                    except Exception:
                        pass
        finally:
            DaemonClient._spawn_daemon = original
            _cleanup_dir(state_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):

    def test_status_output(self):
        import subprocess
        state_dir = _temp_dir("cli_state")
        env = dict(os.environ)
        env[STATE_DIR_ENV] = state_dir
        try:
            result = subprocess.run(
                [sys.executable, os.path.join(_SCRIPT_DIR, "ssh_manager.py"), "status"],
                capture_output=True, text=True, timeout=30, cwd=_SCRIPT_DIR, env=env)
            self.assertEqual(result.returncode, 0)
            self.assertTrue("not running" in result.stdout
                            or "daemon running" in result.stdout)
        finally:
            _cleanup_dir(state_dir)

    def test_version_flag(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(_SCRIPT_DIR, "ssh_manager.py"), "--version"],
            capture_output=True, text=True, timeout=30, cwd=_SCRIPT_DIR)
        self.assertEqual(result.returncode, 0)
        self.assertIn(VERSION, result.stdout)

    def test_json_flag_before_and_after_subcommand(self):
        from ssh_manager.cli import build_parser
        parser = build_parser()
        self.assertTrue(parser.parse_args(["--json", "list"]).json_output)
        self.assertTrue(parser.parse_args(["list", "--json"]).json_output)
        self.assertFalse(parser.parse_args(["list"]).json_output)

    def test_exec_flags_parse(self):
        from ssh_manager.cli import build_parser, _parse_pty
        parser = build_parser()
        args = parser.parse_args(["exec", "-i", "abc", "--pty", "ls -la"])
        self.assertEqual(args.command, "ls -la")
        self.assertEqual(_parse_pty(args)["width"], 80)
        args = parser.parse_args(
            ["exec", "-i", "abc", "--pty", "--pty-size", "120x40", "ls"])
        self.assertEqual(_parse_pty(args), {"term": "vt100", "width": 120, "height": 40})
        self.assertTrue(parser.parse_args(["exec", "-i", "abc", "--stdin", "cat"]).stdin)
        self.assertTrue(parser.parse_args(["exec", "-i", "abc", "--bg", "sleep 5"]).background)

    def test_key_flag_does_not_break_exec_parsing(self):
        from ssh_manager.cli import build_parser
        parser = build_parser()
        self.assertEqual(parser.parse_args(["exec", "-i", "abc", "ls -la /tmp"]).command,
                         "ls -la /tmp")
        self.assertEqual(parser.parse_args(["exec", "-i", "abc", "-t", "30", "ls"]).timeout, 30)
        self.assertEqual(parser.parse_args(["connect", "-h", "h", "-u", "u", "--key"]).key,
                         auth.KEY_DISCOVER)
        self.assertIsNone(parser.parse_args(["connect", "-h", "h", "-u", "u", "-w", "pw"]).key)

    def test_cli_connect_and_exec_end_to_end(self):
        """The real CLI must work against a live daemon (catches signature bugs)."""
        import subprocess
        fake = FakeSSHServer()
        state_dir = _temp_dir("cli_e2e")
        daemon, client = _start_daemon(state_dir, idle_timeout=600)
        env = dict(os.environ)
        env[STATE_DIR_ENV] = state_dir
        script = os.path.join(_SCRIPT_DIR, "ssh_manager.py")
        try:
            connect = subprocess.run(
                [sys.executable, script, "connect", "-h", "127.0.0.1",
                 "-p", str(fake.port), "-u", FAKE_USER, "-w", FAKE_PASS,
                 "--no-host-key-check", "--name", "clitest"],
                capture_output=True, text=True, timeout=60, cwd=_SCRIPT_DIR, env=env)
            self.assertEqual(connect.returncode, 0, connect.stderr)
            exec_run = subprocess.run(
                [sys.executable, script, "exec", "-i", "clitest", "echo hello"],
                capture_output=True, text=True, timeout=60, cwd=_SCRIPT_DIR, env=env)
            self.assertEqual(exec_run.returncode, 0, exec_run.stderr)
            self.assertIn("OUT: hello", exec_run.stdout)
            pty_run = subprocess.run(
                [sys.executable, script, "exec", "-i", "clitest", "--pty", "tty_info"],
                capture_output=True, text=True, timeout=60, cwd=_SCRIPT_DIR, env=env)
            self.assertEqual(pty_run.returncode, 0, pty_run.stderr)
            self.assertIn("tty=vt100 80x24", pty_run.stdout)
            jobs_run = subprocess.run(
                [sys.executable, script, "--json", "jobs"],
                capture_output=True, text=True, timeout=60, cwd=_SCRIPT_DIR, env=env)
            self.assertEqual(jobs_run.returncode, 0, jobs_run.stderr)
            self.assertIn("jobs", jobs_run.stdout)
        finally:
            try:
                daemon.stop()
            except Exception:
                pass
            fake.stop()
            _cleanup_dir(state_dir)

    def test_bare_key_enables_agent_mode(self):
        import contextlib
        import io as _io
        from ssh_manager import cli
        original = cli.auth.resolve_private_key
        cli.auth.resolve_private_key = lambda *a, **k: (
            None, None, ["no private key found; will try ssh-agent"])
        try:
            args = cli.build_parser().parse_args(["connect", "-h", "h", "-u", "u", "--key"])
            with contextlib.redirect_stderr(_io.StringIO()):
                key_path, passphrase, use_agent = cli._resolve_key_material(args)
        finally:
            cli.auth.resolve_private_key = original
        self.assertIsNone(key_path)
        self.assertTrue(use_agent)


# ---------------------------------------------------------------------------
# Smoke helper
# ---------------------------------------------------------------------------

def _smoke_main():
    """Start the fake server, print its port, and block until Ctrl+C."""
    server = FakeSSHServer(sftp_root=tempfile.mkdtemp(prefix="sshm_smoke_sftp_"))
    print("Fake SSH server running on 127.0.0.1:%d" % server.port)
    print("Credentials: %s / %s" % (FAKE_USER, FAKE_PASS))
    print("SFTP root: %s" % server.sftp_root)
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    if "--smoke" in sys.argv:
        _smoke_main()
    else:
        unittest.main()
