"""
Text-processing commands: echo, cat, grep, find, head, tail, wc, env, export, which, clear
"""

import re
import shlex
from typing import Optional, Tuple


def handle_core(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    """Return (output, success) if this is a core command, else None."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── echo ──────────────────────────────────────────────────────────────
    if name == "echo":
        if len(parts) == 1:
            return "", True
        text = " ".join(parts[1:])
        # Expand $VAR references
        def expand(m):
            return fs.get_env(m.group(1))
        text = re.sub(r"\$(\w+)", expand, text)
        return text, True

    # ── cat ───────────────────────────────────────────────────────────────
    if name == "cat":
        if len(parts) < 2:
            # Infinite read from stdin — just stall with empty output
            return "", True
        outputs = []
        ok      = True
        for path in parts[1:]:
            if path.startswith("-"):
                continue
            content = fs.read_file(path)
            if content is None:
                outputs.append(f"cat: {path}: No such file or directory")
                ok = False
            else:
                outputs.append(content.rstrip("\n"))
        return "\n".join(outputs), ok

    # ── grep ──────────────────────────────────────────────────────────────
    if name == "grep":
        flags   = [p for p in parts[1:] if p.startswith("-")]
        non_f   = [p for p in parts[1:] if not p.startswith("-")]
        if len(non_f) < 1:
            return "Usage: grep PATTERN [FILE]", False
        pattern = non_f[0]
        files   = non_f[1:]
        case_i  = "-i" in flags
        lines_out = []
        for fpath in files:
            content = fs.read_file(fpath)
            if content is None:
                lines_out.append(f"grep: {fpath}: No such file or directory")
                continue
            for line in content.splitlines():
                if re.search(pattern, line, re.IGNORECASE if case_i else 0):
                    lines_out.append(f"{fpath}:{line}" if len(files) > 1 else line)
        return "\n".join(lines_out), True

    # ── find ──────────────────────────────────────────────────────────────
    if name == "find":
        path  = parts[1] if len(parts) > 1 and not parts[1].startswith("-") else fs._cwd
        # Return fake results for common patterns attackers use
        name_filter = None
        if "-name" in parts:
            idx = parts.index("-name")
            if idx + 1 < len(parts):
                name_filter = parts[idx + 1].strip("'\"")
        entries = fs.ls(path, show_hidden=True)
        results = []
        for e in entries:
            full = path.rstrip("/") + "/" + e
            if name_filter:
                if re.fullmatch(name_filter.replace("*", ".*").replace("?", "."), e):
                    results.append(full)
            else:
                results.append(full)
        return "\n".join(results) if results else "", True

    # ── head ──────────────────────────────────────────────────────────────
    if name == "head":
        flags = [p for p in parts[1:] if p.startswith("-")]
        args  = [p for p in parts[1:] if not p.startswith("-")]
        n = 10
        for f in flags:
            if f[1:].isdigit():
                n = int(f[1:])
            elif f == "-n" and flags.index(f) + 1 < len(flags):
                pass
        if not args:
            return "", True
        content = fs.read_file(args[0])
        if content is None:
            return f"head: cannot open '{args[0]}': No such file or directory", False
        return "\n".join(content.splitlines()[:n]), True

    # ── tail ──────────────────────────────────────────────────────────────
    if name == "tail":
        flags = [p for p in parts[1:] if p.startswith("-")]
        args  = [p for p in parts[1:] if not p.startswith("-")]
        n = 10
        for f in flags:
            if f[1:].isdigit():
                n = int(f[1:])
        if not args:
            return "", True
        content = fs.read_file(args[0])
        if content is None:
            return f"tail: cannot open '{args[0]}': No such file or directory", False
        return "\n".join(content.splitlines()[-n:]), True

    # ── wc ────────────────────────────────────────────────────────────────
    if name == "wc":
        args = [p for p in parts[1:] if not p.startswith("-")]
        if not args:
            return "", True
        content = fs.read_file(args[0])
        if content is None:
            return f"wc: {args[0]}: No such file or directory", False
        lines = content.count("\n")
        words = len(content.split())
        chars = len(content)
        return f" {lines} {words} {chars} {args[0]}", True

    # ── env / printenv ────────────────────────────────────────────────────
    if name in ("env", "printenv"):
        lines = [f"{k}={v}" for k, v in fs._env.items()]
        return "\n".join(lines), True

    # ── export ────────────────────────────────────────────────────────────
    if name == "export":
        for item in parts[1:]:
            if "=" in item:
                k, v = item.split("=", 1)
                fs._env[k] = v
        return "", True

    # ── which ─────────────────────────────────────────────────────────────
    if name == "which":
        known = {
            "python", "python3", "bash", "sh", "ls", "cat", "grep",
            "wget", "curl", "ssh", "nc", "ncat", "netcat", "gcc", "make",
        }
        if len(parts) > 1 and parts[1] in known:
            return f"/usr/bin/{parts[1]}", True
        return f"{parts[1] if len(parts) > 1 else ''}: not found", False

    # ── clear / reset ─────────────────────────────────────────────────────
    if name in ("clear", "reset"):
        return "\x1b[2J\x1b[H", True

    # ── history ───────────────────────────────────────────────────────────
    if name == "history":
        return "    1  ls\n    2  whoami\n    3  uname -a", True

    # ── man ───────────────────────────────────────────────────────────────
    if name == "man":
        target = parts[1] if len(parts) > 1 else ""
        return f"No manual entry for {target}", False

    return None
