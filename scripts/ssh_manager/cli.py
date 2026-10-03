# -*- coding: utf-8 -*-
"""Command line interface for the SSH manager."""

import argparse
import getpass
import os
import sys

from . import auth
from .client import DaemonClient
from .config import (
    KEY_PASSPHRASE_ENV,
    PASSWORD_ENV,
    VERSION,
)
from .daemon import Daemon
from .errors import SSHConnectError, SessionError


def _force_utf8_stdio():
    """Reconfigure stdout/stderr to UTF-8 with errors='replace'."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _exit_usage(message):
    sys.stderr.write("usage error: %s\n" % message)
    sys.exit(2)


def _prompt_password():
    """Interactive password prompt; returns None without a terminal."""
    try:
        if not os.isatty(0):
            return None
    except (AttributeError, ValueError):
        return None
    try:
        return getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        return None


def _resolve_key_material(args):
    """Resolve --key into (key_path, key_passphrase, use_agent).

    ``use_agent`` is True whenever --key was passed, so a bare --key still
    works when no key file exists but ssh-agent holds one.
    """
    if args.key is None:
        return None, None, False
    passphrase = args.key_passphrase or os.environ.get(KEY_PASSPHRASE_ENV)
    key_path, key_passphrase, notes = auth.resolve_private_key(
        args.key, passphrase=passphrase, prompt=auth.terminal_prompt)
    for note in notes:
        sys.stderr.write("warning: %s\n" % note)
    return key_path, key_passphrase, True


# -- commands ------------------------------------------------------------------

def cmd_connect(args):
    password = args.password or os.environ.get(PASSWORD_ENV) or ""
    try:
        key_path, key_passphrase, use_agent = _resolve_key_material(args)
    except auth.AuthError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    if not password and key_path is None and not use_agent:
        password = _prompt_password() or ""
    if not password and key_path is None and not use_agent:
        _exit_usage("-w <password> required (or set %s, or pass --key)" % PASSWORD_ENV)

    client = DaemonClient()
    try:
        client.ensure_daemon()
        conn_id = client.connect(
            args.host, args.port, args.user, password,
            encoding=args.encoding,
            key_path=key_path,
            key_passphrase=key_passphrase,
            use_agent=use_agent,
            known_hosts=args.known_hosts,
            no_host_key_check=args.no_host_key_check,
        )
    except SSHConnectError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    sys.stdout.write("%s\n" % conn_id)
    sys.exit(0)


def cmd_exec(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        status = 1
        for tag, text in client.exec_stream(args.conn_id, args.command, args.timeout):
            if tag == "RETURN":
                status = text
            else:
                sys.stdout.write(tag)
                sys.stdout.write(text)
                sys.stdout.flush()
    except SessionError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(2)
    except SSHConnectError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    sys.exit(status)


def cmd_close(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        client.close(args.conn_id)
    except SessionError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(2)
    except SSHConnectError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    sys.exit(0)


def cmd_list(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        sessions = client.list()
    except SSHConnectError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    if not sessions:
        sys.stdout.write("no active connections\n")
        sys.exit(0)
    header = "%-36s  %-40s  %-24s  %s" % ("ID", "USER@HOST:PORT", "CONNECTED_AT", "IDLE_S")
    sys.stdout.write(header + "\n")
    sys.stdout.write("-" * len(header) + "\n")
    for session in sessions:
        sys.stdout.write("%-36s  %-40s  %-24s  %s\n" % (
            session.get("id", ""),
            "%s@%s:%s" % (session.get("user", ""), session.get("host", ""),
                          session.get("port", "")),
            session.get("connected_at", ""),
            session.get("idle_seconds", 0),
        ))
    sys.exit(0)


def cmd_status(args):
    client = DaemonClient()
    state = client._read_state()
    if state is None:
        sys.stdout.write("daemon not running\n")
        sys.exit(0)
    try:
        if client.ping():
            sessions = client.list()
            sys.stdout.write("daemon running (pid %s, port %s, version %s, sessions: %d)\n" % (
                state.get("pid"), state.get("port"),
                state.get("version", "?"), len(sessions)))
            sys.exit(0)
    except (SSHConnectError, OSError):
        pass
    sys.stdout.write("daemon not running\n")
    sys.exit(0)


def cmd_stop(args):
    client = DaemonClient()
    state = client._read_state()
    if state is None or not client._daemon_alive():
        sys.stdout.write("daemon not running\n")
        sys.exit(0)
    try:
        client.stop()
    except SSHConnectError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
    sys.stdout.write("stopped\n")
    sys.exit(0)


def cmd_daemon(args):
    Daemon().serve_forever()
    sys.exit(0)


# -- parser --------------------------------------------------------------------

def build_parser():
    """Build the argparse CLI. The top-level parser uses add_help=False so -h is free."""
    parser = argparse.ArgumentParser(
        prog="ssh_manager.py", add_help=False,
        description="SSH connection manager: persistent SSH session daemon + CLI.")
    parser.add_argument("--version", action="version", version="ssh-manager %s" % VERSION)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_connect = sub.add_parser("connect", add_help=False,
                               help="establish an SSH connection and print its id")
    p_connect.add_argument("-h", dest="host", required=True, help="remote host")
    p_connect.add_argument("-p", dest="port", type=int, default=22,
                           help="remote port (default 22)")
    p_connect.add_argument("-u", dest="user", required=True, help="username")
    p_connect.add_argument("-w", dest="password", default="",
                           help="password (or env %s)" % PASSWORD_ENV)
    p_connect.add_argument("--key", dest="key", nargs="?", const=auth.KEY_DISCOVER, default=None,
                           metavar="PATH",
                           help="use public-key auth; bare --key discovers ~/.ssh keys and "
                                "allows ssh-agent")
    p_connect.add_argument("--key-passphrase", dest="key_passphrase", default=None,
                           help="private key passphrase (or env %s)" % KEY_PASSPHRASE_ENV)
    p_connect.add_argument("--known-hosts", dest="known_hosts", default=None,
                           help="extra known_hosts file to trust")
    p_connect.add_argument("--no-host-key-check", dest="no_host_key_check",
                           action="store_true",
                           help="disable host key verification (insecure)")
    p_connect.add_argument("--encoding", dest="encoding", default=None,
                           choices=["auto", "utf-8", "gbk", "latin-1"],
                           help="output encoding (default auto)")
    p_connect.set_defaults(func=cmd_connect)

    for name in ("exec", "run"):
        p_exec = sub.add_parser(name, add_help=False, help="run a command on a connection")
        p_exec.add_argument("-i", dest="conn_id", required=True, help="connection id")
        p_exec.add_argument("command", help="command to run remotely")
        p_exec.add_argument("-t", dest="timeout", type=int, default=None,
                            help="timeout in seconds")
        p_exec.set_defaults(func=cmd_exec)

    p_close = sub.add_parser("close", add_help=False, help="close a connection")
    p_close.add_argument("-i", dest="conn_id", required=True, help="connection id")
    p_close.set_defaults(func=cmd_close)

    p_list = sub.add_parser("list", add_help=False, help="list active connections")
    p_list.set_defaults(func=cmd_list)

    p_status = sub.add_parser("status", add_help=False, help="show daemon status")
    p_status.set_defaults(func=cmd_status)

    p_stop = sub.add_parser("stop", add_help=False, help="stop the daemon")
    p_stop.set_defaults(func=cmd_stop)

    p_daemon = sub.add_parser("daemon", add_help=False, help="run the daemon in the foreground")
    p_daemon.set_defaults(func=cmd_daemon)

    return parser


def main(argv=None):
    _force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        parser.print_help()
        sys.exit(0)
    args.func(args)
