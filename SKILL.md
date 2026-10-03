---
name: ssh-manager
description: >
  Persistent SSH connection manager with real-time command streaming,
  daemon-based connection pooling, password and public-key authentication
  (including encrypted keys and ssh-agent), strict host-key verification,
  adaptive encoding (UTF-8/GBK/latin-1), and automatic idle timeout. Use when
  users need to SSH into servers, run commands remotely, maintain persistent
  connections across multiple CLI invocations, or handle CJK/Chinese remote
  output encoding.
---

# SSH Manager

## Quick start

```powershell
# Connect with a password (returns a connection ID)
python scripts/ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w password

# Connect with a private key
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key ~/.ssh/id_ed25519

# Connect with key discovery + ssh-agent
python scripts/ssh_manager.py connect -h 192.168.1.100 -u root --key

# Run a command (use the ID from above)
python scripts/ssh_manager.py exec -i <conn_id> "ls -la /tmp"

# Close when done
python scripts/ssh_manager.py close -i <conn_id>
```

## Workflows

### Connect & run commands
1. `connect -h <host> -p <port> -u <user> -w <pass>` or `connect ... --key [PATH]` — prints the connection ID
2. `exec -i <id> "<command>"` — streams stdout+stderr in real-time, exits with the remote exit code
3. `close -i <id>` — release the connection

### List active connections
```powershell
python scripts/ssh_manager.py list
```

### Check daemon status
```powershell
python scripts/ssh_manager.py status
```

## Security defaults

- Host keys are verified against `~/.ssh/known_hosts`; unknown hosts are
  rejected with instructions. Use `--known-hosts <file>` to trust another file,
  or `--no-host-key-check` to opt out explicitly.
- Key authentication is opt-in: it only activates when `--key` is passed.
- Encrypted keys take their passphrase from `--key-passphrase`, then
  `SSH_MANAGER_KEY_PASSPHRASE`, then an interactive prompt (if a terminal is
  attached); otherwise the candidate key is skipped.

## Advanced features

See [REFERENCE.md](REFERENCE.md) for:
- Full CLI reference (all flags, exit codes)
- Daemon protocol and architecture
- Authentication and host-key policy details
- Encoding strategy (CJK/GBK/UTF-8 stream-head locking)
- Keepalive and idle-timeout configuration
- Troubleshooting

See [EXAMPLES.md](EXAMPLES.md) for copy-paste agent recipes.

## Requirements

Python 3.8+ and `paramiko>=3.0`:
```powershell
pip install -r scripts/requirements.txt
```
