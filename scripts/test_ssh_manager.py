# -*- coding: utf-8 -*-
"""
Test suite for the SSH Connection Manager.

Starts a fake paramiko SSH server so no real SSH server or network is needed.
Run with:

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
from ssh_manager.config import STATE_DIR_ENV
from ssh_manager.daemon import Daemon
from ssh_manager.encoding import AdaptiveDecoder
from ssh_manager.errors import SSHConnectError, SessionError

FAKE_USER = "testuser"
FAKE_PASS = "testpass"


# ---------------------------------------------------------------------------
# Fake SSH server
# ---------------------------------------------------------------------------

class FakeServerInterface(paramiko.ServerInterface):
    """Paramiko server interface supporting password and public-key auth."""

    def __init__(self, authorized_key=None):
        self.authorized_key = authorized_key

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

    def __init__(self, authorized_key=None):
        self.host_key = paramiko.RSAKey.generate(2048)
        self.authorized_key = authorized_key
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
                transport.start_server(
                    server=FakeServerInterface(authorized_key=self.authorized_key))
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
    # Windows may briefly hold files open while a daemon process exits.
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


# ---------------------------------------------------------------------------
# AdaptiveDecoder
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
        result = decoder.decode(b"\xff\xfe\x01\x80")
        self.assertIsInstance(result, str)
        self.assertEqual(decoder._locked, "latin-1")

    def test_forced_utf8(self):
        decoder = AdaptiveDecoder(encoding="utf-8")
        self.assertEqual(decoder.decode("你好".encode("utf-8")), "你好")

    def test_forced_gbk(self):
        decoder = AdaptiveDecoder(encoding="gbk")
        self.assertEqual(decoder.decode("中文测试".encode("gbk")), "中文测试")

    def test_forced_latin1(self):
        decoder = AdaptiveDecoder(encoding="latin-1")
        self.assertEqual(decoder.decode(b"\xff\xfe\x01"), "\xff\xfe\x01")

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
        self.assertEqual(decoder.decode(b"abc"), "abc")

    def test_flush_emits_pending_bytes(self):
        decoder = AdaptiveDecoder()
        decoder.decode(b"\xe4\xb8")  # truncated UTF-8, still undecided
        self.assertIsInstance(decoder.flush(), str)


class TestStreamDecoders(unittest.TestCase):
    """stdout and stderr are independent byte streams and need separate decoders."""

    def test_stream_decoders_are_independent(self):
        from ssh_manager.session import Session
        session = Session("id", None, "h", 22, "u", 0.0, AdaptiveDecoder())
        # A split multi-byte character on stdout must not consume stderr bytes.
        self.assertEqual(session.decoder_for("stdout").decode(b"\xe4"), "")
        self.assertEqual(session.decoder_for("stderr").decode(b"abc"), "abc")
        self.assertEqual(session.decoder_for("stdout").decode(b"\xb8\xad"), "中")

    def test_reset_decoders_unlocks_both_streams(self):
        from ssh_manager.session import Session
        session = Session("id", None, "h", 22, "u", 0.0, AdaptiveDecoder())
        session.decoder_for("stdout").decode(b"\xd6\xd0")
        session.decoder_for("stderr").decode(b"\xd6\xd0")
        session.reset_decoders()
        self.assertIsNone(session.decoder_for("stdout")._locked)
        self.assertIsNone(session.decoder_for("stderr")._locked)


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
            self.assertIsNone(passphrase)
            self.assertTrue(any("ssh-agent" in note for note in notes))
        finally:
            _cleanup_dir(ssh_dir)


# ---------------------------------------------------------------------------
# Protocol framing
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


# ---------------------------------------------------------------------------
# Integration: fake server + in-process daemon + client
# ---------------------------------------------------------------------------

class TestIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("state")
        cls.daemon = Daemon(state_dir=cls.state_dir, idle_timeout=600)
        threading.Thread(target=cls.daemon.serve_forever, daemon=True).start()
        time.sleep(0.3)
        cls.client = DaemonClient(state_dir=cls.state_dir)
        for _ in range(30):
            if cls.client._daemon_alive():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("daemon failed to start")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        try:
            cls.fake.stop()
        except Exception:
            pass
        _cleanup_dir(cls.state_dir)

    def setUp(self):
        self.conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS, no_host_key_check=True)
        self.assertIsNotNone(self.conn_id)

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
        sessions = self.client.list()
        ids = [s["id"] for s in sessions]
        self.assertIn(self.conn_id, ids)

    def test_list_timestamp_is_iso8601(self):
        session = [s for s in self.client.list() if s["id"] == self.conn_id][0]
        self.assertRegex(session["connected_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")

    def test_connect_wrong_password(self):
        with self.assertRaises(SSHConnectError):
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, "wrongpass",
                                no_host_key_check=True)

    def test_exec_echo(self):
        status, out, err = self._exec_get_output(self.conn_id, "echo hello")
        self.assertEqual(status, 0)
        self.assertEqual(out, "hello\n")

    def test_exec_chinese_utf8(self):
        status, out, err = self._exec_get_output(self.conn_id, "chinese_utf8")
        self.assertEqual(status, 0)
        self.assertEqual(out, "你好世界\n")

    def test_exec_chinese_gbk(self):
        status, out, err = self._exec_get_output(self.conn_id, "chinese_gbk")
        self.assertEqual(status, 0)
        self.assertEqual(out, "中文测试\n")

    def test_exec_big_output(self):
        collected = []
        for tag, text in self.client.exec_stream(self.conn_id, "big_output"):
            if tag == "OUT: ":
                collected.append(text)
        self.assertAlmostEqual(len("".join(collected)), 199998, delta=5)

    def test_exec_slow_stream(self):
        frames = 0
        for tag, text in self.client.exec_stream(self.conn_id, "slow_stream"):
            if tag == "RETURN":
                break
            frames += 1
        self.assertGreater(frames, 0, "expected data frames before done")

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
        status, out, err = self._exec_get_output(self.conn_id, "exit_42")
        self.assertEqual(status, 42)

    def test_exec_timeout_returns_124(self):
        status, out, err = self._exec_get_output(self.conn_id, "hang", timeout=1)
        self.assertEqual(status, 124)
        self.assertIn("timeout after", err)

    def test_exec_timeout_leaves_daemon_log_clean(self):
        self._exec_get_output(self.conn_id, "hang", timeout=1)
        time.sleep(0.3)
        log_file = os.path.join(self.state_dir, "daemon.log")
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            contents = f.read()
        self.assertNotIn("Traceback", contents)
        self.assertNotIn("UnboundLocalError", contents)

    def test_silent_command_survives_keepalive_window(self):
        status, out, err = self._exec_get_output(self.conn_id, "sleep 2")
        self.assertEqual(status, 0)

    def test_close(self):
        self.client.close(self.conn_id)
        with self.assertRaises(SessionError):
            self._exec_get_output(self.conn_id, "echo hello")
        ids = [s["id"] for s in self.client.list()]
        self.assertNotIn(self.conn_id, ids)

    def test_close_unknown(self):
        with self.assertRaises(SessionError):
            self.client.close("nonexistent-id")

    def test_exec_unknown_id(self):
        with self.assertRaises(SessionError):
            self._exec_get_output("nonexistent-id", "echo hello")


class TestHostKeyVerification(unittest.TestCase):
    """Strict host-key checking (the v2 default)."""

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("hostkey_state")
        cls.tmp = _temp_dir("hostkey")
        cls.known_hosts = _write_known_hosts(
            os.path.join(cls.tmp, "known_hosts"), cls.fake.host_key, cls.fake.port)
        cls.daemon = Daemon(state_dir=cls.state_dir, idle_timeout=600)
        threading.Thread(target=cls.daemon.serve_forever, daemon=True).start()
        time.sleep(0.3)
        cls.client = DaemonClient(state_dir=cls.state_dir)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        try:
            cls.fake.stop()
        except Exception:
            pass
        _cleanup_dir(cls.state_dir)
        _cleanup_dir(cls.tmp)

    def test_unknown_host_is_rejected(self):
        with self.assertRaises(SSHConnectError) as ctx:
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS)
        self.assertIn("host key", str(ctx.exception).lower())

    def test_known_hosts_match_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            known_hosts=self.known_hosts)
        self.client.close(conn_id)

    def test_missing_known_hosts_file_reports_error(self):
        missing = os.path.join(self.tmp, "does_not_exist")
        with self.assertRaises(SSHConnectError) as ctx:
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
                                known_hosts=missing)
        self.assertIn("known_hosts", str(ctx.exception).lower())

    def test_no_host_key_check_escape_hatch(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            no_host_key_check=True)
        self.client.close(conn_id)


class TestKeyAuthentication(unittest.TestCase):
    """Public-key auth, including encrypted keys."""

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
        cls.daemon = Daemon(state_dir=cls.state_dir, idle_timeout=600)
        threading.Thread(target=cls.daemon.serve_forever, daemon=True).start()
        time.sleep(0.3)
        cls.client = DaemonClient(state_dir=cls.state_dir)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        try:
            cls.fake.stop()
        except Exception:
            pass
        _cleanup_dir(cls.state_dir)
        _cleanup_dir(cls.tmp)

    def test_key_auth_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, "",
            key_path=self.plain_path, no_host_key_check=True)
        sessions = [s for s in self.client.list() if s["id"] == conn_id]
        self.assertEqual(sessions[0]["auth_mode"], "key")
        self.client.close(conn_id)

    def test_encrypted_key_with_passphrase_succeeds(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, "",
            key_path=self.enc_path, key_passphrase="secret",
            no_host_key_check=True)
        self.client.close(conn_id)

    def test_unauthorized_key_is_rejected(self):
        other = os.path.join(self.tmp, "other")
        self.other_key.write_private_key_file(other)
        with self.assertRaises(SSHConnectError):
            self.client.connect("127.0.0.1", self.fake.port, FAKE_USER, "",
                                key_path=other, no_host_key_check=True)

    def test_password_still_works_without_key(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS,
            no_host_key_check=True)
        sessions = [s for s in self.client.list() if s["id"] == conn_id]
        self.assertEqual(sessions[0]["auth_mode"], "password")
        self.client.close(conn_id)


class TestIdleTimeout(unittest.TestCase):
    """Idle reaper behaviour, including the busy-session guard."""

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("idle_state")
        cls.daemon = Daemon(state_dir=cls.state_dir, idle_timeout=1)
        threading.Thread(target=cls.daemon.serve_forever, daemon=True).start()
        time.sleep(0.3)
        cls.client = DaemonClient(state_dir=cls.state_dir)
        for _ in range(30):
            if cls.client._daemon_alive():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("idle daemon failed to start")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        try:
            cls.fake.stop()
        except Exception:
            pass
        _cleanup_dir(cls.state_dir)

    def test_idle_reaper_reaps(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS, no_host_key_check=True)
        time.sleep(2.5)
        with self.assertRaises(SessionError):
            for _ in self.client.exec_stream(conn_id, "echo hello"):
                pass
        self.assertNotIn(conn_id, [s["id"] for s in self.client.list()])

    def test_busy_session_is_not_reaped(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS, no_host_key_check=True)
        try:
            status = [None]

            def run():
                for tag, text in self.client.exec_stream(conn_id, "sleep 3"):
                    if tag == "RETURN":
                        status[0] = text

            worker = threading.Thread(target=run)
            worker.start()
            time.sleep(2.0)  # longer than idle_timeout=1s
            self.assertIn(conn_id, [s["id"] for s in self.client.list()])
            worker.join(timeout=10)
            self.assertEqual(status[0], 0)
        finally:
            try:
                self.client.close(conn_id)
            except Exception:
                pass


class TestKeepalive(unittest.TestCase):
    """The daemon must emit keepalive frames during silent stretches."""

    @classmethod
    def setUpClass(cls):
        cls.fake = FakeSSHServer()
        cls.state_dir = _temp_dir("keepalive_state")
        cls.daemon = Daemon(state_dir=cls.state_dir, idle_timeout=600,
                            keepalive_interval=0.5)
        threading.Thread(target=cls.daemon.serve_forever, daemon=True).start()
        time.sleep(0.3)
        cls.client = DaemonClient(state_dir=cls.state_dir)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.daemon.stop()
        except Exception:
            pass
        try:
            cls.fake.stop()
        except Exception:
            pass
        _cleanup_dir(cls.state_dir)

    def test_queued_exec_is_kept_alive_while_waiting(self):
        """A second exec on a busy connection must not be reported as unresponsive."""
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS, no_host_key_check=True)
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
            time.sleep(0.3)  # let the first command take the session lock
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

    def test_keepalive_frame_arrives_during_silence(self):
        conn_id = self.client.connect(
            "127.0.0.1", self.fake.port, FAKE_USER, FAKE_PASS, no_host_key_check=True)
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
                self.assertTrue(saw_keepalive, "expected a keepalive frame during silence")
            finally:
                sock.close()
        finally:
            self.client.close(conn_id)


class TestConcurrentColdStart(unittest.TestCase):
    """Two clients racing to start the daemon must produce exactly one daemon."""

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
            output = result.stdout.strip()
            self.assertTrue("not running" in output or "daemon running" in output)
        finally:
            _cleanup_dir(state_dir)

    def test_version_flag(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(_SCRIPT_DIR, "ssh_manager.py"), "--version"],
            capture_output=True, text=True, timeout=30, cwd=_SCRIPT_DIR)
        self.assertEqual(result.returncode, 0)
        self.assertIn(VERSION, result.stdout)

    def test_bare_key_enables_agent_mode(self):
        from ssh_manager import cli
        import contextlib
        import io as _io
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

    def test_key_flag_does_not_break_exec_parsing(self):
        from ssh_manager.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["exec", "-i", "abc", "ls -la /tmp"])
        self.assertEqual(args.command, "ls -la /tmp")
        args = parser.parse_args(["exec", "-i", "abc", "-t", "30", "ls"])
        self.assertEqual(args.timeout, 30)
        args = parser.parse_args(["connect", "-h", "h", "-u", "u", "--key"])
        self.assertEqual(args.key, auth.KEY_DISCOVER)
        args = parser.parse_args(["connect", "-h", "h", "-u", "u", "--key", "/tmp/k"])
        self.assertEqual(args.key, "/tmp/k")
        args = parser.parse_args(["connect", "-h", "h", "-u", "u", "-w", "pw"])
        self.assertIsNone(args.key)


# ---------------------------------------------------------------------------
# Smoke helper
# ---------------------------------------------------------------------------

def _smoke_main():
    """Start the fake server, print its port, and block until Ctrl+C."""
    server = FakeSSHServer()
    print("Fake SSH server running on 127.0.0.1:%d" % server.port)
    print("Credentials: %s / %s" % (FAKE_USER, FAKE_PASS))
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
