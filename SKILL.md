---
name: ssh-manager
description: >
  Persistent SSH connection manager with real-time command streaming,
  daemon-based connection pooling, password and public-key authentication
  (including encrypted keys and ssh-agent), strict host-key verification,
  PTY and stdin support, SFTP transfers, background jobs, concurrent commands,
  adaptive encoding (UTF-8/GBK/latin-1), JSON output and automatic idle
  timeout. Use when users need to SSH into servers, run commands remotely,
  transfer files, run long jobs in the background, maintain persistent
  connections across multiple CLI invocations, or handle CJK/Chinese remote
  output encoding.
---

# SSH Manager

## Quick start

```powershell
# Connect (returns a connection ID; --name makes it addressable)
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w password --name prod-web

# Connect with a private key (bare --key discovers ~/.ssh and allows ssh-agent)
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key

# Run a command (-i accepts the id or the name)
python scripts/ssh_manager.py exec -i prod-web "ls -la /tmp"

# Close when done
python scripts/ssh_manager.py close -i prod-web
```

## Workflows

### Connect & run commands
1. `connect -h <host> -p <port> -u <user> -w <pass>` or `connect ... --key [PATH]` — prints the connection ID
2. `exec -i <id|name> "<command>"` — streams stdout+stderr in real-time, exits with the remote exit code
3. `close -i <id|name>` — release the connection

### Long or interactive commands
```powershell
python scripts/ssh_manager.py exec -i prod-web --pty "sudo -S id"          # allocate a PTY
"payload" | python scripts/ssh_manager.py exec -i prod-web --stdin "cat > /tmp/x"
python scripts/ssh_manager.py exec -i prod-web --bg "make -j8"            # returns a job id
python scripts/ssh_manager.py jobs
python scripts/ssh_manager.py logs <job_id> --follow
python scripts/ssh_manager.py kill <job_id>
```

### File transfer
```powershell
python scripts/ssh_manager.py sftp put -i prod-web ./app.conf /etc/app/app.conf
python scripts/ssh_manager.py sftp get -i prod-web /var/log/app.log ./app.log
python scripts/ssh_manager.py sftp ls  -i prod-web /etc/app
```

### Inspect
```powershell
python scripts/ssh_manager.py list
python scripts/ssh_manager.py status
python scripts/ssh_manager.py --json list          # machine-readable
python scripts/ssh_manager.py logs --daemon --tail 20
```

## Security defaults

- Host keys are verified against `~/.ssh/known_hosts`; unknown hosts are
  rejected and their SHA256 fingerprint is printed. `--accept-host-key` saves
  it (interactive terminals also get a y/N prompt). A *changed* key is always
  rejected.
- Key authentication is opt-in: it only activates when `--key` is passed.
- Encrypted keys take their passphrase from `--key-passphrase`, then
  `SSH_MANAGER_KEY_PASSPHRASE`, then an interactive prompt.
- The daemon never stores credentials, and commands are logged only as a
  length + digest.

## Advanced features

See [REFERENCE.md](REFERENCE.md) for:
- Full CLI reference (all commands, flags, exit codes)
- Daemon protocol, concurrency and health detection
- Authentication and host-key policy details
- Encoding strategy (CJK/GBK/UTF-8 stream-head locking)
- Background jobs, SFTP, JSON output and log rotation
- Troubleshooting

See [EXAMPLES.md](EXAMPLES.md) for copy-paste agent recipes.

## Requirements

Python 3.8+ and `paramiko>=3.0`:
```powershell
pip install -r scripts/requirements.txt
```
