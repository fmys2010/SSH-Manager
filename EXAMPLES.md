# SSH Manager — Examples

## Basic usage (password)

```powershell
python scripts\ssh_manager.py connect -h 192.168.1.100 -p 22 -u root -w mypassword
# -> a1b2c3d4-e5f6-7890-abcd-ef1234567890

python scripts\ssh_manager.py exec -i a1b2c3d4-... "uname -a"
# OUT: Linux myserver 5.15.0-91-generic #101-Ubuntu SMP ... x86_64 GNU/Linux

python scripts\ssh_manager.py close -i a1b2c3d4-...
```

Omitting `-w` on an interactive terminal prompts for the password, so it never
enters your shell history. `SSH_MANAGER_PASSWORD` is the non-interactive option.

## Named sessions

```powershell
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --name prod-web
python scripts\ssh_manager.py exec -i prod-web "systemctl status nginx"
python scripts\ssh_manager.py sftp put -i prod-web .\nginx.conf /etc/nginx/nginx.conf
python scripts\ssh_manager.py close -i prod-web
```

Names are unique per daemon; reusing one fails with exit code 2. `-i` accepts
either the name or the UUID.

## Key authentication

```powershell
# Explicit private key
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key ~/.ssh/id_ed25519

# Encrypted key, passphrase from the environment (recommended for scripts)
$env:SSH_MANAGER_KEY_PASSPHRASE = "s3cret"
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key ~/.ssh/id_ed25519

# Discovery: tries ~/.ssh/id_ed25519, id_rsa, id_ecdsa and allows ssh-agent
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key
```

## Host-key verification and trust

```powershell
# Unknown host -> refused, fingerprint printed, with the fix
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key
# error: host key verification failed for 10.0.0.50:22. Re-run with --accept-host-key ...

# Save the fingerprint and continue
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --accept-host-key

# Trust a project-local known_hosts instead
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --known-hosts .\deploy_known_hosts

# Lab box you knowingly accept the risk for
python scripts\ssh_manager.py connect -h 10.0.0.50 -u deploy --key --no-host-key-check
```

On an interactive terminal an unknown host prints the SHA256 fingerprint and
asks for confirmation instead of failing. A *changed* host key is always
rejected.

## PTY and stdin

```powershell
# Commands that need a terminal (sudo prompt, top, less)
python scripts\ssh_manager.py exec -i prod-web --pty "sudo -S id"
python scripts\ssh_manager.py exec -i prod-web --pty --pty-size 120x40 "top -b -n1"

# Feed local input to the remote command
"hello world" | python scripts\ssh_manager.py exec -i prod-web --stdin "cat > /tmp/greeting"
Get-Content .\dump.sql -Raw | python scripts\ssh_manager.py exec -i prod-web --stdin "mysql app"
```

With a PTY, stderr merges into stdout (that is how terminals work).

## Background jobs

```powershell
# Start and get a job id immediately
$job = python scripts\ssh_manager.py exec -i prod-web --bg "docker build -t app ." | Select-Object -Last 1

# Inspect
python scripts\ssh_manager.py jobs
python scripts\ssh_manager.py logs $job --tail 50
python scripts\ssh_manager.py logs $job --follow      # stream until it finishes

# Stop it
python scripts\ssh_manager.py kill $job
```

Output is buffered in memory (default 256 KB per job). Older output is dropped
when the budget is exceeded, so `logs --tail` is the right way to inspect a
noisy job. Jobs disappear when their session closes.

## SFTP

```powershell
python scripts\ssh_manager.py sftp put   -i prod-web .\app.conf /etc/app/app.conf
python scripts\ssh_manager.py sftp get   -i prod-web /var/log/app.log .\app.log
python scripts\ssh_manager.py sftp ls    -i prod-web /etc/app
python scripts\ssh_manager.py sftp stat  -i prod-web /etc/app/app.conf
python scripts\ssh_manager.py sftp mkdir -i prod-web /etc/app/conf.d
python scripts\ssh_manager.py sftp rm    -i prod-web /etc/app/old.conf
```

## JSON output

```powershell
python scripts\ssh_manager.py --json list
# {"sessions": [{"id": "...", "name": "prod-web", "state": "alive", ...}]}

python scripts\ssh_manager.py --json status
# {"running": true, "pid": 1234, "port": 51234, "version": "2.1.0", "sessions": 1, "jobs": 0}

# exec streams NDJSON, one object per line
python scripts\ssh_manager.py --json exec -i prod-web "df -h"
# {"type": "data", "stream": "stdout", "text": "Filesystem ...\n"}
# {"type": "done", "exit_status": 0}
```

## Multiple commands on one connection

```powershell
python scripts\ssh_manager.py exec -i prod-web "git pull"
python scripts\ssh_manager.py exec -i prod-web "npm run build"
python scripts\ssh_manager.py exec -i prod-web "systemctl restart app"
python scripts\ssh_manager.py list
```

Commands on one connection run concurrently (up to 10 by default), so parallel
`exec` calls are fine and do not block each other.

## Long-running commands

```powershell
# No output for minutes is fine: keepalive frames keep the stream alive.
python scripts\ssh_manager.py exec -i prod-web "docker build -t app ."

# Bound the runtime instead
python scripts\ssh_manager.py exec -i prod-web -t 30 "sleep 300"
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

## Daemon logs

```powershell
python scripts\ssh_manager.py status
python scripts\ssh_manager.py logs --daemon --tail 50
python scripts\ssh_manager.py stop
```

The daemon log rotates at 1 MB keeping three backups, and records commands only
as a length plus a SHA-256 prefix.

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
1. `connect -h <host> -p <port> -u <user> -w <password> --name <short>` (or `--key [PATH]`) -> capture the ID
2. Use `exec -i <name> "<command>"` for each command; add `--json` for structured output
3. Stream output: `OUT:` and `ERR:` prefixes distinguish stdout/stderr
4. Use `--stdin` to feed input, `--pty` for terminal-only commands
5. Use `exec --bg` + `logs --follow` for long jobs so you are not blocked
6. Use `sftp put|get` to move files instead of shell redirection
7. `close -i <name>` when done; `jobs` to see leftover background work
8. Host-key failure is expected for a new host: re-run with `--accept-host-key`
   when the environment is trusted
9. For Chinese servers, add `--encoding gbk` if output is garbled
```

## Troubleshooting commands

```powershell
python scripts\ssh_manager.py status
python scripts\ssh_manager.py logs --daemon --tail 100
python scripts\ssh_manager.py jobs
python scripts\ssh_manager.py stop
Remove-Item -Recurse ~\.ssh-manager\ -Force
```
