# command_runner.py — Shell Dispatcher

## What it does

Takes a raw command string typed by the attacker and:
1. Strips `sudo` (we allow everything)
2. Splits pipes (`cmd1 | cmd2`) and runs them left-to-right, feeding each output as stdin to the next
3. Handles output redirect (`cmd > file`, `cmd >> file`)
4. Detects `exit` / `logout` and signals the shell to close
5. Adds a short realistic delay (20–150ms) so the shell doesn't feel instant

## Entry point

```python
output, should_exit = run_command("ls /etc | grep pass", fs)
```

- `output` — string to send back to the attacker
- `should_exit` — `True` only when the attacker types `exit`/`logout`

## Pipe handling

```
ps aux | grep ssh | wc -l
```

Each stage runs as a separate `_dispatch_single()` call. The output of stage N becomes the `stdin` of stage N+1. Currently only the final output is returned — full stdin passing to `grep` etc. is handled inside each command's own logic.

## Redirect handling

```
echo "test" > /tmp/out.txt
cat /tmp/out.txt
```

When `>` is detected, the output is written to the fake file via `fs.write_file()` instead of being returned to the terminal. With `>>` it appends instead.

## COMMAND_HANDLERS

`_dispatch_single()` loops through:

1. `handle_filesystem` — ls, cd, pwd, mkdir, rm, cp, mv, touch, chmod
2. `handle_core`       — cat, grep, echo, find, head, tail, wc, history
3. `handle_system`     — ps, top, uname, whoami, id, uptime, date, df, free
4. `handle_network`    — ifconfig, ip, netstat, ping, wget, curl, nmap
5. `handle_package`    — apt, pip, yum
6. `handle_service`    — systemctl, service, crontab

Each handler returns `(output, success)` if it recognises the command, or `None` to pass to the next handler. If none match:

```
bash: unknowncmd: command not found
```

## Why not one giant if/elif?

Splitting handlers by category keeps each file small and focused. Adding a new command (e.g. `git`) means adding one new file — nothing else changes.
