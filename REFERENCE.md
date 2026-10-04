# SSH Manager — Reference

Version 2.1.0. The implementation is a package under `scripts/ssh_manager/`;
`scripts/ssh_manager.py` is a thin compatibility shim, so every command below
keeps working exactly as before.

## CLI Reference

### Global
`--json` works before or after the subcommand. All commands except `status`,
`stop`, `logs --daemon` and `daemon` auto-start the daemon on first use.
`python -m ssh_manager <command>` works as an alternative entry point when run
from `scripts/`.

### `connect`
```
python scripts/ssh_manager.py connect -h <host> [-p <port>] -u <user>
       [-w <password>] [--key [PATH]] [--key-passphrase <text>]
       [--known-hosts <file>] [--no-host-key-check] [--accept-host-key]
       [--name <name>] [--encoding auto] [--json]
```
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | `-h` | required | SSH server hostname/IP |
| `--port` | `-p` | `22` | SSH server port |
| `--user` | `-u` | required | Login username |
| `--password` | `-w` | env `SSH_MANAGER_PASSWORD`, else interactive prompt | Login password |
| `--key` | | off | Public-key auth. `--key PATH` uses that key; bare `--key` discovers `~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa` and allows `ssh-agent` |
| `--key-passphrase` | | env `SSH_MANAGER_KEY_PASSPHRASE`, else interactive prompt | Passphrase for an encrypted key |
| `--known-hosts` | | none | Extra known_hosts file to trust |
| `--no-host-key-check` | | off | Disable host-key verification (insecure) |
| `--accept-host-key` | | off | Save an unknown host key to known_hosts and continue |
| `--name` | | none | Name the session; `-i` then accepts the name (`[A-Za-z0-9._-]{1,64}`) |
| `--encoding` | | `auto` | `auto`, `utf-8`, `gbk`, `latin-1` |

Prints the connection ID on stdout (or a JSON object with `--json`).
Exit code 0 on success, 1 on connect/auth/host-key failure, 2 for a duplicate or
invalid name.

Authentication order inside one SSH connection: **private key → ssh-agent →
password**. Key auth is only attempted when `--key` is present.

### `exec` / `run`
```
python scripts/ssh_manager.py exec -i <id|name> "<command>"
       [-t <seconds>] [--pty] [--pty-size COLSxROWS] [--stdin] [--bg] [--json]
```
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--id` | `-i` | required | Connection ID or session name |
| `--timeout` | `-t` | none | Kill the command after N seconds |
| `--pty` | | off | Allocate a PTY (default 80x24); stderr merges into stdout |
| `--pty-size` | | `80x24` | PTY size; implies `--pty` |
| `--stdin` | | off | Stream local stdin to the remote command |
| `--bg` | | off | Run in the background and print a job id |

`--pty` is a boolean flag rather than an optional-value one on purpose: an
optional value would swallow the command word (`--pty ls` would parse `ls` as
the size). Use `--pty-size` for a custom size.

Streams output with `OUT:` and `ERR:` prefixes, then exits with the remote exit
code (124 on timeout). `--stdin` and `--bg` are mutually exclusive.

### `jobs`
```
python scripts/ssh_manager.py jobs [--json]
```
Lists background jobs: job id, session, status (`running`/`done`/`failed`/
`killed`), exit status, duration and command.

### `logs`
```
python scripts/ssh_manager.py logs <job_id> [--follow] [--tail N] [--json]
python scripts/ssh_manager.py logs --daemon [--tail N] [--json]
```
Reads a background job's buffered output, or the daemon log. `--follow` streams
new output until the job finishes. Exactly one of `<job_id>` / `--daemon` is
required.

### `kill`
```
python scripts/ssh_manager.py kill <job_id> [--json]
```
Terminates a background job. (Sessions are closed with `close -i`.)

### `sftp`
```
python scripts/ssh_manager.py sftp put   -i <id|name> <local> <remote> [--json]
python scripts/ssh_manager.py sftp get   -i <id|name> <remote> <local> [--json]
python scripts/ssh_manager.py sftp ls    -i <id|name> [path]           [--json]
python scripts/ssh_manager.py sftp stat  -i <id|name> <path>           [--json]
python scripts/ssh_manager.py sftp mkdir -i <id|name> <path>           [--json]
python scripts/ssh_manager.py sftp rm    -i <id|name> <path>           [--json]
```
Each operation opens a short-lived SFTP channel on the existing session. `rm`
removes a file or an empty directory.

### `close`
```
python scripts/ssh_manager.py close -i <id|name> [--json]
```
Closes the connection and kills its background jobs.

### `list`
```
python scripts/ssh_manager.py list [--json]
```
Table of ID, NAME, user@host:port, connected_at (ISO-8601 local), STATE
(`alive`/`dead`) and idle seconds.

### `status`
```
python scripts/ssh_manager.py status [--json]
```
Daemon pid/port/version plus session and job counts, or "not running".

### `stop`
```
python scripts/ssh_manager.py stop [--json]
```
Closes all connections and stops the daemon.

### Exit codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Connect/auth/host-key failure, SFTP failure, or fatal client error |
| 2 | Bad connection id, unknown job, usage error, or duplicate/invalid session name |
| 124 | Command timeout (`-t`) |

## JSON output

`--json` applies to every command. `connect`, `list`, `status`, `jobs`,
`sftp *`, `logs <job>` (snapshot) and `kill` emit a single JSON object.
`exec` and `logs --follow` emit **NDJSON** — one object per line — so streaming
output stays parseable:

```
{"type": "data", "stream": "stdout", "text": "hello\n"}
{"type": "done", "exit_status": 0}
```

Keepalive frames are transport-level and never appear in user output.

## Daemon Architecture

```
CLI ── TCP 127.0.0.1 ──► Daemon
                           ├── Session A  (paramiko SSHClient, semaphore of N channels)
                           ├── Session B
                           ├── JobRegistry (background jobs, in-memory ring buffers)
                           └── Reaper (idle timeout + dead-transport eviction)
```

- **Auto-start**: any client command spawns a detached daemon when none is
  running. Concurrent cold starts are serialized with `daemon.lock`
  (`O_CREAT|O_EXCL`); a lock older than 30s with no live daemon is reclaimed.
- **State file** (`~/.ssh-manager/daemon.json`): port, pid, token, version,
  keepalive interval, max channels, started_at. Written atomically; mode 0600
  on POSIX.
- **Token auth**: every request carries the token from the state file.
- **Frame limit**: protocol frames are capped at 16 MiB.
- **Concurrency**: each command takes one slot from a per-session semaphore
  (default 10, `SSH_MANAGER_MAX_CHANNELS`). Commands beyond the limit queue and
  receive keepalive frames while waiting.
- **Health**: the reaper probes `transport.is_active()` every ≤30s; a dead
  transport is evicted so later commands fail fast with `session_dead`.
- **Keepalive**: while a command produces no output, the daemon sends
  `{"type":"keepalive"}` every `SSH_MANAGER_KEEPALIVE_INTERVAL` seconds
  (default 30). The client uses a read timeout of 3× that interval.
- **Idle timeout**: default 30 minutes (`SSH_MANAGER_IDLE_TIMEOUT`). Sessions
  with active channels are never reaped.
- **Logs**: `~/.ssh-manager/daemon.log`, rotated at 1 MB
  (`SSH_MANAGER_LOG_MAX_KB`) keeping 3 backups. Commands are recorded as a
  length + SHA-256 prefix, never in full.

## Background Jobs

`exec --bg` returns immediately with a job id. Output is buffered in memory in a
ring buffer (default 256 KB per job, `SSH_MANAGER_JOB_BUFFER_KB`); when the
budget is exceeded the oldest chunks are dropped. Finished jobs are kept for the
lifetime of their session (at most 50 per session, oldest evicted). Closing a
session kills and removes its jobs. Jobs live only as long as the daemon.

## Authentication & Host Keys

- **Host keys**: strict verification against the system `known_hosts` plus any
  `--known-hosts` file. Unknown hosts fail and report the SHA256 fingerprint;
  `--accept-host-key` saves it (interactive terminals offer a y/N prompt
  instead). A **changed** key is always rejected — no flag overrides it.
  Accepted keys are appended to the file, so existing hashed entries survive.
- **Private keys**: `--key PATH`, or bare `--key` to try `id_ed25519`, `id_rsa`,
  `id_ecdsa` from `~/.ssh`.
- **Passphrases**: `--key-passphrase` → `SSH_MANAGER_KEY_PASSPHRASE` →
  interactive prompt. Without a terminal, an encrypted candidate is skipped and
  the next one is tried; if none works, the command fails with the reasons.
- **Permissions**: on POSIX a group/world-readable private key produces a
  warning suggesting `chmod 600`.

## Encoding Strategy

1. Pure ASCII is emitted immediately and does not lock anything.
2. When non-ASCII bytes appear, the buffer is decoded strictly as **UTF-8**.
   If UTF-8 is merely *incomplete* (a split multi-byte character), the decoder
   keeps buffering — the common Linux case is never mis-detected.
3. If UTF-8 is definitively invalid, **GBK** is tried next.
4. If both fail, **latin-1** is the last resort.
5. The undecided buffer is capped at 4 KiB; past the cap, UTF-8 with
   `errors="replace"` is locked.

Decoders are created per channel and per stream, so concurrent commands and
interleaved stdout/stderr can never contaminate each other. Pass
`--encoding gbk` (or `utf-8`/`latin-1`) to skip detection entirely.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `host key verification failed` / `unknown_host` | Host not in known_hosts (strict default) | Re-run with `--accept-host-key`, run the printed `ssh-keyscan`, or `--known-hosts` |
| `host key mismatch` | The server's key changed | Verify out-of-band, then remove the stale known_hosts entry |
| `Authentication failed` | Wrong password/key, or the server rejects that method | Verify credentials; try `--key PATH` |
| `no usable private key: ...` | Every candidate was encrypted and no passphrase was available | Pass `--key-passphrase` or set `SSH_MANAGER_KEY_PASSPHRASE` |
| `session_dead` / `connection closed` | The transport died; the reaper evicted it | Reconnect |
| `unknown job` | The job was removed (session closed, or pruned) | `jobs` to list what remains |
| `Connection ID not found` | Session reaped (idle > 30 min) or never created | `list` to verify; reconnect |
| Garbled Chinese text | Mixed-encoding stream that defeats detection | Pass `--encoding gbk` or `--encoding utf-8` |
| `daemon unresponsive` | Daemon process wedged | `status` to check; `stop` then retry |
| `paramiko` not found | Missing dependency | `pip install -r scripts/requirements.txt` |
| Daemon won't start on Windows | Antivirus blocking port binding | Check `~/.ssh-manager/daemon.log` |

## Package Layout

```
scripts/ssh_manager.py        compatibility shim (python scripts/ssh_manager.py ...)
scripts/ssh_manager/
    cli.py        argparse + command handlers, JSON rendering
    client.py     daemon client, auto-start, streaming, stdin pump
    daemon.py     daemon, exec engine, reaper, job/sftp dispatch
    session.py    per-connection state, channel semaphore
    jobs.py       background jobs and their ring buffers
    sftp.py       SFTP operations
    auth.py       host-key policy, key discovery, fingerprints, known_hosts
    encoding.py   AdaptiveDecoder (stream-head locking)
    protocol.py   length-prefixed JSON framing
    config.py     constants, env handling, state paths, log rotation
    errors.py     SSHConnectError, ConnectError, SessionError
scripts/test_ssh_manager.py   self-contained test suite (fake SSH server)
```
