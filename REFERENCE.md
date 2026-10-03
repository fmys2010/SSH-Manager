# SSH Manager — Reference

Version 2.0.0. The implementation is a package under `scripts/ssh_manager/`;
`scripts/ssh_manager.py` is a thin compatibility shim, so every command below
keeps working exactly as before.

## CLI Reference

### Global
All commands except `status`, `stop` and `daemon` auto-start the daemon on
first use. `python -m ssh_manager <command>` works as an alternative entry point
when run from `scripts/`.

### `connect`
```
python scripts/ssh_manager.py connect -h <host> [-p <port>] -u <user>
       [-w <password>] [--key [PATH]] [--key-passphrase <text>]
       [--known-hosts <file>] [--no-host-key-check] [--encoding auto]
```
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | `-h` | required | SSH server hostname/IP |
| `--port` | `-p` | `22` | SSH server port |
| `--user` | `-u` | required | Login username |
| `--password` | `-w` | env `SSH_MANAGER_PASSWORD`, else interactive prompt | Login password |
| `--key` | | off | Enable public-key auth. `--key PATH` uses that private key; bare `--key` discovers `~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa` and allows `ssh-agent` |
| `--key-passphrase` | | env `SSH_MANAGER_KEY_PASSPHRASE`, else interactive prompt | Passphrase for an encrypted private key |
| `--known-hosts` | | none | Extra known_hosts file to trust (on top of the system file) |
| `--no-host-key-check` | | off | Disable host-key verification (insecure) |
| `--encoding` | | `auto` | Encoding: `auto`, `utf-8`, `gbk`, `latin-1` |

Prints the connection ID (UUID) on stdout on success. Exit code 0.

Authentication order inside one SSH connection: **private key → ssh-agent →
password**. Key auth is only attempted when `--key` is present; otherwise the
manager behaves like v1 (`allow_agent=False`, `look_for_keys=False`).

### `exec` / `run`
```
python scripts/ssh_manager.py exec -i <conn_id> "<command>" [-t <seconds>]
python scripts/ssh_manager.py run  -i <conn_id> "<command>" [-t <seconds>]
```
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--id` | `-i` | required | Connection ID from `connect` |
| `--timeout` | `-t` | none | Kill the command after N seconds |

Streams output with `OUT:` and `ERR:` prefixes. Exits with the remote command's
exit code. On timeout, prints `ERR: [timeout after Ns]` and exits 124.

### `close`
```
python scripts/ssh_manager.py close -i <conn_id>
```
Closes the connection in the daemon. Exit code 0.

### `list`
```
python scripts/ssh_manager.py list
```
Table of active connections: ID, user@host:port, connected_at (ISO-8601 local
time), idle seconds.

### `status`
```
python scripts/ssh_manager.py status
```
Shows daemon pid/port/version and the session count, or "not running".

### `stop`
```
python scripts/ssh_manager.py stop
```
Closes all connections and stops the daemon.

### Exit codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Connect/auth failure, host-key verification failure, or fatal client error |
| 2 | Bad connection ID, or usage error (e.g. no password and no `--key`) |
| 124 | Command timeout (`-t`) |

## Daemon Architecture

```
CLI (ssh_manager.py connect/exec/...) ── TCP 127.0.0.1 ──► Daemon (ssh_manager daemon)
                                                              │
                                                              ├── Session A (paramiko SSHClient, host:port, last_activity, busy)
                                                              ├── Session B
                                                              └── Reaper thread (every <=60s: close idle > 30min, never while busy)
```

- **Auto-start**: any client command spawns a detached daemon when none is
  running. Concurrent cold starts are serialized with `daemon.lock`
  (`O_CREAT|O_EXCL`), so exactly one daemon wins; a lock older than 30s with no
  live daemon is treated as stale and reclaimed.
- **State file** (`~/.ssh-manager/daemon.json`): `port`, `pid`, `token`,
  `version`, `keepalive_interval`, `started_at`. Written atomically
  (temp file + `os.replace`); mode 0600 on POSIX.
- **Token auth**: every request carries the token from the state file, so other
  local processes cannot drive your SSH sessions.
- **Frame limit**: protocol frames are capped at 16 MiB to protect the daemon
  from a malformed local client.
- **Per-connection lock**: commands on the same connection are serialized, so
  output never interleaves.
- **Keepalive**: while a command is running and produces no output, the daemon
  sends `{"type":"keepalive"}` every `SSH_MANAGER_KEEPALIVE_INTERVAL` seconds
  (default 30). The client ignores these frames and uses a read timeout of
  3× the interval, so a genuinely wedged daemon is still detected.
- **Idle timeout**: default 30 minutes (`SSH_MANAGER_IDLE_TIMEOUT` to override,
  set before the daemon starts). Sessions with an in-flight command are never
  reaped.
- **Logs**: `~/.ssh-manager/daemon.log`. Passwords and passphrases are never
  logged.

## Authentication & Host Keys

- **Host keys**: strict verification against the system `known_hosts` plus any
  `--known-hosts` file. Unknown hosts fail with the `ssh-keyscan` command you
  need to run. `--no-host-key-check` switches to `AutoAddPolicy` for the
  explicit opt-out case.
- **Private keys**: `--key PATH` uses one file; bare `--key` tries
  `id_ed25519`, then `id_rsa`, then `id_ecdsa` from `~/.ssh`.
- **Passphrases**: `--key-passphrase` → `SSH_MANAGER_KEY_PASSPHRASE` →
  interactive `getpass` prompt. With no terminal available, an encrypted
  candidate is skipped (and reported) so the next candidate can be tried; if
  none works the command fails with per-candidate reasons.
- **Permissions**: on POSIX, a private key that is group/world readable
  produces a warning suggesting `chmod 600`.

## Encoding Strategy

The classic failure mode with SSH + CJK is a multi-byte character split across
TCP packets. The decoder therefore locks its encoding once, at the head of the
stream, instead of flipping mid-stream:

1. Pure ASCII is emitted immediately and does not lock anything.
2. When non-ASCII bytes appear, the buffer is decoded strictly as **UTF-8**.
   If UTF-8 is merely *incomplete* (a split multi-byte character), the decoder
   keeps buffering — this is the common Linux case and is never mis-detected.
3. If UTF-8 is definitively invalid, **GBK** is tried next.
4. If both fail, **latin-1** is the last resort and cannot fail.
5. The undecided buffer is capped at 4 KiB; past the cap, UTF-8 with
   `errors="replace"` is locked.

Pass `--encoding gbk` (or `utf-8`/`latin-1`) to skip detection entirely. The
forced decoder is re-initialised for every command, so one command's encoding
never leaks into the next.

### Console output
CLI stdout/stderr are set to UTF-8 with `errors="replace"` so CJK renders safely.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `host key verification failed` | Host not in known_hosts (strict default) | Run the printed `ssh-keyscan` command, pass `--known-hosts`, or `--no-host-key-check` |
| `Authentication failed` | Wrong password/key, or the server rejects that method | Verify credentials; try `--key PATH`; note key-only servers reject password auth |
| `no usable private key: ...` | Every candidate was encrypted and no passphrase was available | Pass `--key-passphrase` or set `SSH_MANAGER_KEY_PASSPHRASE` |
| `Connection ID not found` | Session reaped (idle > 30 min) or never created | `list` to verify; reconnect |
| Garbled Chinese text | Mixed-encoding stream that defeats detection | Pass `--encoding gbk` or `--encoding utf-8` explicitly |
| `daemon unresponsive` | Daemon process wedged | `status` to check; `stop` then retry |
| `paramiko` not found | Missing dependency | `pip install -r scripts/requirements.txt` |
| Daemon won't start on Windows | Antivirus blocking port binding | Check `~/.ssh-manager/daemon.log` |

## Package Layout

```
scripts/ssh_manager.py        compatibility shim (python scripts/ssh_manager.py ...)
scripts/ssh_manager/
    cli.py        argparse + command handlers
    client.py     daemon client, auto-start, stream reading
    daemon.py     daemon, exec engine, idle reaper
    session.py    per-connection state
    auth.py       host-key policy, key discovery, passphrases
    encoding.py   AdaptiveDecoder (stream-head locking)
    protocol.py   length-prefixed JSON framing
    config.py     constants, env handling, state paths
    errors.py     SSHConnectError, SessionError
scripts/test_ssh_manager.py   self-contained test suite (fake SSH server)
```
