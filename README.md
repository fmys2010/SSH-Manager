# SSH Manager

Persistent SSH sessions for CLI and agent workflows: a local daemon keeps the
connections open, and every command talks to it over a token-authenticated
localhost socket.

Built for the case where a single `ssh host "cmd"` invocation is not enough —
you need several commands on the same session, real-time streaming output, and
correct handling of Chinese/GBK servers.

## Features

- **Persistent sessions** — connect once, run many commands, close when done.
- **Real-time streaming** — stdout and stderr are forwarded as they arrive.
- **Key authentication** — `--key PATH` or bare `--key` to discover `~/.ssh`
  keys and fall back to `ssh-agent`; encrypted keys supported.
- **Strict host-key verification by default** — unknown hosts are rejected with
  an actionable message; `--no-host-key-check` is an explicit opt-out.
- **CJK-safe decoding** — the stream encoding is locked once per stream
  (UTF-8 → GBK → latin-1), so multi-byte characters split across packets are
  never garbled.
- **Long commands survive silence** — the daemon emits keepalive frames during
  quiet stretches, so a 40-minute build is not mistaken for a dead connection.
- **Idle reaper that respects running work** — idle sessions are closed after 30
  minutes, but never while a command is in flight.
- **Exit codes pass through** — the remote command's exit status becomes the
  CLI exit status (`124` on timeout).

## Quick start

```powershell
# Password authentication
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w mypassword
# -> a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Public-key authentication (explicit key)
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key ~/.ssh/id_ed25519

# Public-key authentication (discover ~/.ssh keys, allow ssh-agent)
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key

# Run commands on the stored session
python scripts/ssh_manager.py exec -i a1b2c3d4-... "uname -a"
python scripts/ssh_manager.py exec -i a1b2c3d4-... "df -h /"

# Inspect and clean up
python scripts/ssh_manager.py list
python scripts/ssh_manager.py close -i a1b2c3d4-...
python scripts/ssh_manager.py stop
```

Requirements: Python 3.8+ and `paramiko>=3.0`.

```powershell
pip install -r scripts/requirements.txt
```

## 中文快速开始

常驻 SSH 会话管理器：本地守护进程持有连接，CLI 通过带 token 鉴权的本机
socket 与之通信，适合「一次连接、多次执行命令」以及中文/GBK 服务器的场景。

```powershell
# 密码登录
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w 密码

# 密钥登录（指定私钥）
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key ~/.ssh/id_ed25519

# 密钥登录（自动发现 ~/.ssh 下的密钥，并允许 ssh-agent）
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key

# 在已建立的会话上执行命令
python scripts/ssh_manager.py exec -i <连接ID> "systemctl status nginx"

# 查看 / 关闭 / 停止
python scripts/ssh_manager.py list
python scripts/ssh_manager.py close -i <连接ID>
python scripts/ssh_manager.py stop
```

默认开启主机密钥严格校验：首次连接陌生主机时会被拒绝，按提示把主机密钥写入
`known_hosts`，或显式加 `--no-host-key-check` 放行。加密私钥的口令可用
`--key-passphrase` 或环境变量 `SSH_MANAGER_KEY_PASSPHRASE` 传入；两者都没有且
处于交互终端时会提示输入。

## Documentation

- [`SKILL.md`](SKILL.md) — agent-facing skill entry point.
- [`REFERENCE.md`](REFERENCE.md) — full CLI reference, daemon protocol, exit codes.
- [`EXAMPLES.md`](EXAMPLES.md) — copy-paste recipes.

## Tests

```powershell
python scripts/test_ssh_manager.py -v
```

The suite starts a fake paramiko SSH server, so no real server is required. It
covers password and key auth, host-key verification, encoding, timeouts,
keepalive, idle reaping and concurrent daemon start.

## License

MIT — see [`LICENSE`](LICENSE).
