# SSH Manager — Examples

## Basic usage (password)

```powershell
python scripts\ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w mypassword
# -> a1b2c3d4-e5f6-7890-abcd-ef1234567890

python scripts\ssh_manager.py exec -i a1b2c3d4-e5f6-7890-abcd-ef1234567890 "uname -a"
# OUT: Linux myserver 5.15.0-91-generic #101-Ubuntu SMP ... x86_64 GNU/Linux

python scripts\ssh_manager.py exec -i a1b2c3d4-e5f6-7890-abcd-ef1234567890 "df -h /"
# OUT: Filesystem      Size  Used Avail Use% Mounted on
# OUT: /dev/sda1        98G   45G   53G  46% /

python scripts\ssh_manager.py close -i a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Omitting `-w` on an interactive terminal prompts for the password, so it never
enters your shell history. `SSH_MANAGER_PASSWORD` is the non-interactive option.

## Key authentication

```powershell
# Explicit private key
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key ~/.ssh/id_ed25519

# Encrypted key, passphrase on the command line
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key ~/.ssh/id_ed25519 --key-passphrase "s3cret"

# Encrypted key, passphrase from the environment (recommended for scripts)
$env:SSH_MANAGER_KEY_PASSPHRASE = "s3cret"
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key ~/.ssh/id_ed25519

# Discovery: tries ~/.ssh/id_ed25519, id_rsa, id_ecdsa and allows ssh-agent
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key
```

With a terminal attached, an encrypted key with no passphrase prompts once and
reuses the answer. Without a terminal the candidate is skipped and the next one
is tried, so unattended runs never hang.

## Host-key verification

Strict verification is on by default.

```powershell
# Unknown host -> refused, with the exact command to fix it
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key
# error: host key verification failed for 10.0.0.50:22. Add the host key to known_hosts, e.g.
#   ssh-keyscan -p 22 10.0.0.50 >> ~/.ssh/known_hosts
# or pass --known-hosts <file>, or explicitly disable the check with --no-host-key-check.

# Trust a project-local known_hosts instead
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --known-hosts .\deploy_known_hosts

# Lab box you knowingly accept the risk for
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --no-host-key-check
```

## Multiple commands on one connection

```powershell
$ID = python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key | Select-Object -Last 1
python scripts\ssh_manager.py exec -i $ID "git pull"
python scripts\ssh_manager.py exec -i $ID "npm run build"
python scripts\ssh_manager.py exec -i $ID "systemctl restart app"
python scripts\ssh_manager.py list
python scripts\ssh_manager.py close -i $ID
```

## Long-running commands

```powershell
# No output for minutes is fine: the daemon sends keepalive frames and the
# session is not reaped while the command is in flight.
python scripts\ssh_manager.py exec -i $ID "docker build -t app ."

# Bound the runtime instead
python scripts\ssh_manager.py exec -i $ID -t 30 "sleep 300"
# ERR: [timeout after 30s]
# Exit code: 124
```

## Encoding handling (Chinese servers)

```powershell
# Auto-detect (stream-head lock: UTF-8 -> GBK -> latin-1)
python scripts\ssh_manager.py connect -h 172.16.0.10 -p 22 -u admin -w pass

# If a stream mixes encodings and looks garbled, force one
python scripts\ssh_manager.py connect -h 172.16.0.10 -p 22 -u admin -w pass --encoding gbk

python scripts\ssh_manager.py exec -i <id> "echo 中文测试"
# OUT: 中文测试
```

## CI/CD usage (non-interactive)

```powershell
$env:SSH_MANAGER_PASSWORD = $PASS          # or SSH_MANAGER_KEY_PASSPHRASE for a key
$ID = python scripts\ssh_manager.py connect -h $HOST -p 22 -u $USER --key | Select-Object -Last 1
python scripts\ssh_manager.py exec -i $ID "deploy.sh"
if ($LASTEXITCODE -ne 0) { throw "Deploy failed" }
python scripts\ssh_manager.py close -i $ID
```

## Agent tips

When the agent is asked to SSH into a server:

```markdown
1. `connect -h <host> -p <port> -u <user> -w <password>` (or `--key [PATH]`) -> capture the ID
2. Use `exec -i <id> "<command>"` for each command
3. Stream output: `OUT:` and `ERR:` prefixes distinguish stdout/stderr
4. `close -i <id>` when done
5. If the ID is missing, `list` to check, or `connect` again
6. Host-key failure is expected for a new host: read the printed `ssh-keyscan`
   hint, or use `--no-host-key-check` when the environment is trusted
7. For Chinese servers, add `--encoding gbk` if output is garbled
```

## Troubleshooting commands

```powershell
# Check daemon health (pid, port, version, sessions)
python scripts\ssh_manager.py status

# Force stop and restart
python scripts\ssh_manager.py stop
python scripts\ssh_manager.py connect -h myserver -p 22 -u root -w pass

# Clean up stale state
python scripts\ssh_manager.py stop
Remove-Item -Recurse ~\.ssh-manager\ -Force
```
