# pseudo_fs.py — Fake In-Memory Filesystem

## What problem does it solve?

When an attacker logs in over SSH and types `ls /etc` or `cat /etc/passwd`, we need to return something realistic — not an error, and not data from the real machine.

`PseudoFS` simulates a full Linux directory tree in memory. Nothing it does touches the real filesystem.

## How the tree is structured

The entire filesystem is a single nested Python dict:

```python
FAKE_FS = {
    "/": {
        "etc": {
            "passwd": "root:x:0:0:...",   # string = file
            "ssh": {                        # dict = directory
                "sshd_config": "Port 22\n..."
            }
        },
        "tmp": {},                          # empty dict = empty directory
    }
}
```

- **dict** → directory  
- **str** → file content

## One instance per session

`PseudoFS.__init__()` does `copy.deepcopy(FAKE_FS)` — so every attacker gets their own **independent** copy. If attacker A creates a file in `/tmp`, attacker B can't see it.

If we used `.copy()` (shallow), all sessions would share the same nested dicts and one attacker's `rm -rf /` would corrupt everyone's view.

## Key methods

| Method | What it does |
|--------|-------------|
| `resolve_path(path)` | Converts relative/`~` paths to absolute. Handles `..` and `.` |
| `_get_node(path)` | Walks the dict tree and returns the node at a path (or `None`) |
| `cd(path)` | Changes `_cwd`, returns an error string if invalid |
| `ls(path, show_hidden)` | Lists entries in a directory |
| `read_file(path)` | Returns file content string, or `None` if not found |
| `write_file(path, content)` | Creates or overwrites a file (used by redirect `>`) |
| `mkdir(path)` | Creates a directory |
| `remove(path, recursive)` | Deletes a file or directory |
| `get_current_directory()` | Returns cwd with `/root` displayed as `~` |

## The prompt uses the state

The SSH shell reads `fs.get_current_directory()` before each command to show:

```
root@ubuntu:~# cd /etc
root@ubuntu:/etc# ls
```

The prompt changes as the attacker navigates — just like a real shell.
