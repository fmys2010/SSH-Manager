# SSH Manager

Persistent SSH sessions for CLI and agent workflows: a local daemon keeps the
connections open, and every command talks to it over a token-authenticated
localhost socket.

Built for the case where a single `ssh host "cmd"` invocation is not enough —
you need several commands on the same session, real-time streaming output,
correct handling of Chinese/GBK servers, and the ability to push files, run
background jobs and get machine-readable output.

## Features

- **Persistent sessions** — connect once, run many commands, close when done.
- **Real-time streaming** — stdout and stderr are forwarded as they arrive.
- **Concurrent commands** — several commands run on one connection at once
  (10 by default; `SSH_MANAGER_MAX_CHANNELS` to change), and the idle reaper
  never touches a connection that is working.
- **Key authentication** — `--key PATH`, or bare `--key` to discover `~/.ssh`
  keys and fall back to `ssh-agent`; encrypted keys supported.
- **Strict host-key verification by default** — unknown hosts report a SHA256
  fingerprint; `--accept-host-key` (or an interactive confirmation) saves it.
- **PTY and stdin** — `exec --pty` allocates a terminal, `exec --stdin` pipes
  local input to the remote command.
- **SFTP** — `sftp put|get|ls|stat|mkdir|rm` for pushing configs and pulling
  logs on the same session.
- **Background jobs** — `exec --bg` returns a job id immediately; `jobs`,
  `logs`, `logs --follow` and `kill` manage the output.
- **JSON output** — `--json` on any command; `exec` emits NDJSON, so streaming
  stays machine-readable.
- **Named sessions** — `connect --name prod-web`, then `exec -i prod-web ...`.
- **CJK-safe decoding** — the encoding is locked once per stream
  (UTF-8 → GBK → latin-1), so multi-byte characters split across packets are
  never garbled.
- **Long commands survive silence** — keepalive frames keep a quiet connection
  alive without mistaking a wedged daemon for a healthy one.
- **Health detection** — dead transports are detected and evicted instead of
  failing later with a confusing error.
- **Log rotation** — `daemon.log` rotates at 1 MB with 3 backups; read it back
  with `logs --daemon`.
- **Exit codes pass through** — the remote exit status becomes the CLI exit
  status (`124` on timeout).

## Quick start

```powershell
# Password authentication
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w mypassword
# -> a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Public-key authentication (explicit key, or bare --key to discover + use agent)
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key ~/.ssh/id_ed25519
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key --name prod-web

# Run commands (by id or by name)
python scripts/ssh_manager.py exec -i prod-web "uname -a"
python scripts/ssh_manager.py exec -i prod-web "df -h /"

# PTY / stdin / background
python scripts/ssh_manager.py exec -i prod-web --pty "sudo -S id"
"payload" | python scripts/ssh_manager.py exec -i prod-web --stdin "cat > /tmp/x"
python scripts/ssh_manager.py exec -i prod-web --bg "docker build -t app ."
python scripts/ssh_manager.py jobs
python scripts/ssh_manager.py logs <job_id> --follow

# File transfer
python scripts/ssh_manager.py sftp put -i prod-web ./app.conf /etc/app/app.conf
python scripts/ssh_manager.py sftp get -i prod-web /var/log/app.log ./app.log

# Machine-readable output
python scripts/ssh_manager.py --json list
python scripts/ssh_manager.py --json exec -i prod-web "df -h"

# Inspect and clean up
python scripts/ssh_manager.py list
python scripts/ssh_manager.py logs --daemon --tail 20
python scripts/ssh_manager.py close -i prod-web
python scripts/ssh_manager.py stop
```

Requirements: Python 3.8+ and `paramiko>=3.0`.

```powershell
pip install -r scripts/requirements.txt
```

## 中文快速开始

常驻 SSH 会话管理器：本地守护进程持有连接，CLI 通过带 token 鉴权的本机
socket 与之通信，适合「一次连接、多次执行命令」、中文/GBK 服务器，以及需要
传文件、跑后台任务、取结构化输出的场景。

```powershell
# 密码登录 / 密钥登录（--key 可指定私钥，裸用则自动发现并允许 ssh-agent）
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w 密码
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key --name prod-web

# 执行命令（-i 可用连接 ID 或名字）
python scripts/ssh_manager.py exec -i prod-web "systemctl status nginx"

# PTY / 标准输入 / 后台执行
python scripts/ssh_manager.py exec -i prod-web --pty "sudo -S id"
"data" | python scripts/ssh_manager.py exec -i prod-web --stdin "cat > /tmp/x"
python scripts/ssh_manager.py exec -i prod-web --bg "make -j8"
python scripts/ssh_manager.py jobs
python scripts/ssh_manager.py logs <作业ID> --follow

# SFTP 上传下载
python scripts/ssh_manager.py sftp put -i prod-web ./a.txt /tmp/a.txt
python scripts/ssh_manager.py sftp get -i prod-web /var/log/app.log ./app.log

# JSON 输出 / 查看 / 关闭
python scripts/ssh_manager.py --json list
python scripts/ssh_manager.py close -i prod-web
python scripts/ssh_manager.py stop
```

默认开启主机密钥严格校验：首次连接陌生主机会打印 SHA256 指纹并被拒绝，可用
`--accept-host-key` 保存后继续（交互终端下会询问确认）。加密私钥的口令可用
`--key-passphrase` 或环境变量 `SSH_MANAGER_KEY_PASSPHRASE` 传入。

## Documentation

- [`SKILL.md`](SKILL.md) — agent-facing skill entry point.
- [`REFERENCE.md`](REFERENCE.md) — full CLI reference, daemon protocol, exit codes.
- [`EXAMPLES.md`](EXAMPLES.md) — copy-paste recipes.

## Tests

```powershell
python scripts/test_ssh_manager.py -v
```

The suite starts a fake paramiko SSH server (PTY, stdin and SFTP included), so
no real server is required. It covers password and key auth, host-key
verification and trust-on-first-use, encoding, timeouts, keepalive, idle
reaping, background jobs, SFTP round trips, concurrency limits, health
detection, log rotation and concurrent daemon start.

## License

MIT — see [`LICENSE`](LICENSE).
