# -*- coding: utf-8 -*-
"""Command line interface for the SSH manager."""

import argparse
import getpass
import json
import os
import re
import sys

from . import auth
from .client import DaemonClient
from .config import (
    KEY_PASSPHRASE_ENV,
    PASSWORD_ENV,
    VERSION,
    log_path,
    read_log_tail,
)
from .daemon import Daemon
from .errors import ConnectError, SSHConnectError, SessionError

_PTY_PATTERN = re.compile(r"^(\d+)x(\d+)$")


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


def _error(message, code):
    sys.stderr.write("error: %s\n" % message)
    sys.exit(code)


def _emit_json(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


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
    """Resolve --key into (key_path, key_passphrase, use_agent)."""
    if args.key is None:
        return None, None, False
    passphrase = args.key_passphrase or os.environ.get(KEY_PASSPHRASE_ENV)
    key_path, key_passphrase, notes = auth.resolve_private_key(
        args.key, passphrase=passphrase, prompt=auth.terminal_prompt)
    for note in notes:
        sys.stderr.write("warning: %s\n" % note)
    return key_path, key_passphrase, True


def _parse_pty(args):
    """Turn --pty / --pty-size into a request dict, or None when unused.

    --pty is a boolean flag on purpose: an optional-value flag would swallow the
    command word (``exec -i x --pty ls`` would parse ``ls`` as the PTY size).
    """
    if not args.pty and not args.pty_size:
        return None
    if not args.pty_size:
        return {"term": "vt100", "width": 80, "height": 24}
    match = _PTY_PATTERN.match(args.pty_size)
    if not match:
        _exit_usage("--pty-size expects COLSxROWS (e.g. --pty-size 120x40)")
    return {"term": "vt100", "width": int(match.group(1)), "height": int(match.group(2))}


def _confirm_host_key(exc):
    """Ask the user to trust an unknown host key; False without a terminal."""
    details = exc.details or {}
    try:
        interactive = os.isatty(0)
    except (AttributeError, ValueError):
        interactive = False
    if not interactive:
        return False
    sys.stderr.write("The authenticity of host %s:%s can't be established.\n" % (
        details.get("host", "?"), details.get("port", "?")))
    sys.stderr.write("%s key fingerprint is %s.\n" % (
        details.get("key_type", "?"), details.get("fingerprint", "?")))
    try:
        answer = input("Save this host key to known_hosts and continue? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def _connect(args, client, password, key_path, key_passphrase, use_agent):
    """Connect, offering to save an unknown host key when the user confirms."""
    kwargs = dict(
        encoding=args.encoding, key_path=key_path, key_passphrase=key_passphrase,
        use_agent=use_agent, known_hosts=args.known_hosts,
        no_host_key_check=args.no_host_key_check, name=args.name,
    )
    try:
        return client.connect(args.host, args.port, args.user, password,
                              accept_host_key=args.accept_host_key, **kwargs)
    except ConnectError as exc:
        if exc.code != "unknown_host" or args.accept_host_key or not _confirm_host_key(exc):
            raise
        return client.connect(args.host, args.port, args.user, password,
                              accept_host_key=True, **kwargs)


# -- commands ------------------------------------------------------------------

def cmd_connect(args):
    password = args.password or os.environ.get(PASSWORD_ENV) or ""
    try:
        key_path, key_passphrase, use_agent = _resolve_key_material(args)
    except auth.AuthError as exc:
        _error(str(exc), 1)
    if not password and key_path is None and not use_agent:
        password = _prompt_password() or ""
    if not password and key_path is None and not use_agent:
        _exit_usage("-w <password> required (or set %s, or pass --key)" % PASSWORD_ENV)

    client = DaemonClient()
    try:
        client.ensure_daemon()
        result = _connect(args, client, password, key_path, key_passphrase, use_agent)
    except ConnectError as exc:
        _error(str(exc), 2 if exc.code in ("duplicate_name", "bad_name", "bad_request") else 1)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json({"id": result["id"], "name": result["name"], "host": args.host,
                    "port": args.port, "user": args.user,
                    "auth_mode": "key" if (key_path or use_agent) else "password"})
    else:
        sys.stdout.write("%s\n" % result["id"])
    sys.exit(0)


def cmd_exec(args):
    pty = _parse_pty(args)
    stdin_source = None
    if args.stdin:
        if args.background:
            _exit_usage("--stdin cannot be combined with --bg")
        stdin_source = getattr(sys.stdin, "buffer", sys.stdin)
    client = DaemonClient()
    try:
        client.ensure_daemon()
        if args.background:
            job_id = client.exec_background(args.conn_id, args.command, args.timeout, pty)
            if args.json_output:
                _emit_json({"job_id": job_id})
            else:
                sys.stdout.write("%s\n" % job_id)
            sys.exit(0)
        status = 1
        for tag, text in client.exec_stream(args.conn_id, args.command, args.timeout,
                                            pty=pty, stdin_source=stdin_source):
            if tag == "RETURN":
                status = text
            elif args.json_output:
                _emit_json({"type": "data",
                            "stream": "stdout" if tag == "OUT: " else "stderr",
                            "text": text})
            else:
                sys.stdout.write(tag)
                sys.stdout.write(text)
                sys.stdout.flush()
        if args.json_output:
            _emit_json({"type": "done", "exit_status": status})
    except SessionError as exc:
        _error(str(exc), 2)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    sys.exit(status)


def cmd_close(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        client.close(args.conn_id)
    except SessionError as exc:
        _error(str(exc), 2)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json({"ok": True, "id": args.conn_id})
    else:
        sys.stdout.write("closed %s\n" % args.conn_id)
    sys.exit(0)


def cmd_list(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        sessions = client.list()
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json({"sessions": sessions})
        sys.exit(0)
    if not sessions:
        sys.stdout.write("no active connections\n")
        sys.exit(0)
    header = "%-36s  %-16s  %-32s  %-19s  %-5s  %s" % (
        "ID", "NAME", "USER@HOST:PORT", "CONNECTED_AT", "STATE", "IDLE_S")
    sys.stdout.write(header + "\n")
    sys.stdout.write("-" * len(header) + "\n")
    for session in sessions:
        sys.stdout.write("%-36s  %-16s  %-32s  %-19s  %-5s  %s\n" % (
            session.get("id", ""),
            session.get("name") or "-",
            "%s@%s:%s" % (session.get("user", ""), session.get("host", ""),
                          session.get("port", "")),
            session.get("connected_at", ""),
            session.get("state", ""),
            session.get("idle_seconds", 0),
        ))
    sys.exit(0)


def cmd_status(args):
    client = DaemonClient()
    state = client._read_state()
    if state is None:
        if args.json_output:
            _emit_json({"running": False})
        else:
            sys.stdout.write("daemon not running\n")
        sys.exit(0)
    try:
        if client.ping():
            sessions = client.list()
            jobs = client.jobs()
            info = {"running": True, "pid": state.get("pid"), "port": state.get("port"),
                    "version": state.get("version"), "sessions": len(sessions),
                    "jobs": len(jobs)}
            if args.json_output:
                _emit_json(info)
            else:
                sys.stdout.write(
                    "daemon running (pid %s, port %s, version %s, sessions: %d, jobs: %d)\n" % (
                        info["pid"], info["port"], info["version"],
                        info["sessions"], info["jobs"]))
            sys.exit(0)
    except (SSHConnectError, OSError):
        pass
    if args.json_output:
        _emit_json({"running": False})
    else:
        sys.stdout.write("daemon not running\n")
    sys.exit(0)


def cmd_stop(args):
    client = DaemonClient()
    state = client._read_state()
    if state is None or not client._daemon_alive():
        if args.json_output:
            _emit_json({"stopped": False, "reason": "not running"})
        else:
            sys.stdout.write("daemon not running\n")
        sys.exit(0)
    try:
        client.stop()
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json({"stopped": True})
    else:
        sys.stdout.write("stopped\n")
    sys.exit(0)


def cmd_jobs(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        jobs = client.jobs()
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json({"jobs": jobs})
        sys.exit(0)
    if not jobs:
        sys.stdout.write("no background jobs\n")
        sys.exit(0)
    header = "%-36s  %-36s  %-8s  %-5s  %-9s  %s" % (
        "JOB_ID", "SESSION", "STATUS", "EXIT", "DURATION", "COMMAND")
    sys.stdout.write(header + "\n")
    sys.stdout.write("-" * len(header) + "\n")
    for job in jobs:
        sys.stdout.write("%-36s  %-36s  %-8s  %-5s  %-9s  %s\n" % (
            job.get("job_id", ""),
            job.get("session_id", ""),
            job.get("status", ""),
            "-" if job.get("exit_status") is None else job.get("exit_status"),
            "%ss" % job.get("duration_seconds", 0),
            job.get("command", ""),
        ))
    sys.exit(0)


def cmd_logs(args):
    if bool(args.job_id) == bool(args.daemon):
        _exit_usage("logs requires exactly one of <job_id> or --daemon")
    if args.daemon:
        text = read_log_tail(log_path(), args.tail)
        if args.json_output:
            for line in text.splitlines():
                _emit_json({"type": "line", "text": line})
        else:
            sys.stdout.write(text)
        sys.exit(0)
    client = DaemonClient()
    try:
        client.ensure_daemon()
        if args.follow:
            for tag, text in client.job_logs(args.job_id, follow=True):
                if tag == "RETURN":
                    if args.json_output:
                        _emit_json({"type": "done", "exit_status": text})
                elif args.json_output:
                    _emit_json({"type": "data",
                                "stream": "stdout" if tag == "OUT: " else "stderr",
                                "text": text})
                else:
                    sys.stdout.write(tag)
                    sys.stdout.write(text)
                    sys.stdout.flush()
            sys.exit(0)
        frames, _next_seq, info = client.job_logs(args.job_id, follow=False)
        text = "".join(chunk for _tag, chunk in frames)
        if args.tail:
            text = "".join(text.splitlines(True)[-args.tail:])
        if args.json_output:
            _emit_json({"job": info, "output": text})
        else:
            sys.stdout.write(text)
    except SessionError as exc:
        _error(str(exc), 2)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    sys.exit(0)


def cmd_kill(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        info = client.job_kill(args.job_id)
    except SessionError as exc:
        _error(str(exc), 2)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json(info)
    else:
        sys.stdout.write("killed %s\n" % args.job_id)
    sys.exit(0)


def _sftp_kwargs(args):
    if args.sftp_op == "put":
        return {"local_path": args.local, "remote_path": args.remote}
    if args.sftp_op == "get":
        return {"remote_path": args.remote, "local_path": args.local}
    if args.sftp_op == "ls":
        return {"path": args.path or "."}
    return {"path": args.path}


def cmd_sftp(args):
    client = DaemonClient()
    try:
        client.ensure_daemon()
        result = client.sftp(args.sftp_op, args.conn_id, **_sftp_kwargs(args))
    except ConnectError as exc:
        _error(str(exc), 2 if exc.code == "unknown_session" else 1)
    except SessionError as exc:
        _error(str(exc), 2)
    except SSHConnectError as exc:
        _error(str(exc), 1)
    if args.json_output:
        _emit_json(result)
        sys.exit(0)
    operation = result.get("operation")
    if operation in ("put", "get"):
        sys.stdout.write("%s %s -> %s (%d bytes)\n" % (
            "uploaded" if operation == "put" else "downloaded",
            result.get("local"), result.get("remote"), result.get("bytes", 0)))
    elif operation == "ls":
        for entry in result.get("entries", []):
            sys.stdout.write("%s %10d  %-6s  %s\n" % (
                entry.get("mode", ""), entry.get("size", 0),
                "dir" if entry.get("is_dir") else "file", entry.get("name")))
    elif operation == "stat":
        sys.stdout.write("%s  %s  %d bytes  %s\n" % (
            result.get("mode", ""), "dir" if result.get("is_dir") else "file",
            result.get("size", 0), result.get("mtime") or "-"))
    else:
        sys.stdout.write("%s %s\n" % (operation, result.get("path", "")))
    sys.exit(0)


def cmd_daemon(args):
    Daemon().serve_forever()
    sys.exit(0)


# -- parser --------------------------------------------------------------------

def _add_json_flag(parser):
    """--json works both before and after the subcommand.

    SUPPRESS on the subparser keeps the top-level value from being clobbered by
    the subparser default.
    """
    parser.add_argument("--json", dest="json_output", action="store_true",
                        default=argparse.SUPPRESS, help="emit JSON output")


def build_parser():
    """Build the argparse CLI. The top-level parser uses add_help=False so -h is free."""
    parser = argparse.ArgumentParser(
        prog="ssh_manager.py", add_help=False,
        description="SSH connection manager: persistent SSH session daemon + CLI.")
    parser.add_argument("--version", action="version", version="ssh-manager %s" % VERSION)
    parser.add_argument("--json", dest="json_output", action="store_true", default=False,
                        help="emit JSON output")
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
                           action="store_true", help="disable host key verification (insecure)")
    p_connect.add_argument("--accept-host-key", dest="accept_host_key",
                           action="store_true",
                           help="save an unknown host key to known_hosts and continue")
    p_connect.add_argument("--name", dest="name", default=None,
                           help="name this session so -i can use it instead of the UUID")
    p_connect.add_argument("--encoding", dest="encoding", default=None,
                           choices=["auto", "utf-8", "gbk", "latin-1"],
                           help="output encoding (default auto)")
    _add_json_flag(p_connect)
    p_connect.set_defaults(func=cmd_connect)

    for name in ("exec", "run"):
        p_exec = sub.add_parser(name, add_help=False, help="run a command on a connection")
        p_exec.add_argument("-i", dest="conn_id", required=True, help="connection id or name")
        p_exec.add_argument("command", help="command to run remotely")
        p_exec.add_argument("-t", dest="timeout", type=int, default=None,
                            help="timeout in seconds")
        p_exec.add_argument("--pty", dest="pty", action="store_true",
                            help="allocate a PTY (default 80x24); merges stderr into stdout")
        p_exec.add_argument("--pty-size", dest="pty_size", default=None, metavar="COLSxROWS",
                            help="PTY size, implies --pty")
        p_exec.add_argument("--stdin", dest="stdin", action="store_true",
                            help="stream local stdin to the remote command")
        p_exec.add_argument("--bg", dest="background", action="store_true",
                            help="run in the background and print a job id")
        _add_json_flag(p_exec)
        p_exec.set_defaults(func=cmd_exec)

    p_close = sub.add_parser("close", add_help=False, help="close a connection")
    p_close.add_argument("-i", dest="conn_id", required=True, help="connection id or name")
    _add_json_flag(p_close)
    p_close.set_defaults(func=cmd_close)

    p_list = sub.add_parser("list", add_help=False, help="list active connections")
    _add_json_flag(p_list)
    p_list.set_defaults(func=cmd_list)

    p_status = sub.add_parser("status", add_help=False, help="show daemon status")
    _add_json_flag(p_status)
    p_status.set_defaults(func=cmd_status)

    p_stop = sub.add_parser("stop", add_help=False, help="stop the daemon")
    _add_json_flag(p_stop)
    p_stop.set_defaults(func=cmd_stop)

    p_jobs = sub.add_parser("jobs", add_help=False, help="list background jobs")
    _add_json_flag(p_jobs)
    p_jobs.set_defaults(func=cmd_jobs)

    p_logs = sub.add_parser("logs", add_help=False,
                            help="show background job output or the daemon log")
    p_logs.add_argument("job_id", nargs="?", default=None, help="background job id")
    p_logs.add_argument("--daemon", dest="daemon", action="store_true",
                        help="show the daemon log instead of a job")
    p_logs.add_argument("-f", "--follow", dest="follow", action="store_true",
                        help="stream new job output until it finishes")
    p_logs.add_argument("--tail", dest="tail", type=int, default=None,
                        help="only show the last N lines")
    _add_json_flag(p_logs)
    p_logs.set_defaults(func=cmd_logs)

    p_kill = sub.add_parser("kill", add_help=False, help="terminate a background job")
    p_kill.add_argument("job_id", help="background job id")
    _add_json_flag(p_kill)
    p_kill.set_defaults(func=cmd_kill)

    p_sftp = sub.add_parser("sftp", add_help=False, help="transfer files over SFTP")
    sftp_sub = p_sftp.add_subparsers(dest="sftp_op", metavar="<op>")
    p_put = sftp_sub.add_parser("put", add_help=False, help="upload a local file")
    p_put.add_argument("-i", dest="conn_id", required=True, help="connection id or name")
    p_put.add_argument("local")
    p_put.add_argument("remote")
    _add_json_flag(p_put)
    p_put.set_defaults(func=cmd_sftp)
    p_get = sftp_sub.add_parser("get", add_help=False, help="download a remote file")
    p_get.add_argument("-i", dest="conn_id", required=True, help="connection id or name")
    p_get.add_argument("remote")
    p_get.add_argument("local")
    _add_json_flag(p_get)
    p_get.set_defaults(func=cmd_sftp)
    for op in ("ls", "stat", "mkdir", "rm"):
        p_op = sftp_sub.add_parser(op, add_help=False, help="%s a remote path" % op)
        p_op.add_argument("-i", dest="conn_id", required=True, help="connection id or name")
        if op == "ls":
            p_op.add_argument("path", nargs="?", default=".")
        else:
            p_op.add_argument("path")
        _add_json_flag(p_op)
        p_op.set_defaults(func=cmd_sftp)

    p_daemon = sub.add_parser("daemon", add_help=False, help="run the daemon in the foreground")
    p_daemon.set_defaults(func=cmd_daemon)

    return parser


def main(argv=None):
    _force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "json_output", False):
        args.json_output = False
    if getattr(args, "command", None) is None or not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    args.func(args)
