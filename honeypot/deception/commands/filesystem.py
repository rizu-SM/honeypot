"""
Filesystem commands: ls, cd, mkdir, rm, cp, mv, touch, pwd, chmod, cat (file path variant)
"""

import shlex
from typing import Optional, Tuple


def handle_filesystem(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    """Return (output, success) if this is a filesystem command, else None."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── pwd ───────────────────────────────────────────────────────────────
    if name == "pwd":
        return fs._cwd, True

    # ── ls ────────────────────────────────────────────────────────────────
    if name == "ls":
        flags      = [p for p in parts[1:] if p.startswith("-")]
        args       = [p for p in parts[1:] if not p.startswith("-")]
        show_hidden = any("a" in f for f in flags)
        long_fmt    = any("l" in f for f in flags)
        path        = args[0] if args else None
        entries     = fs.ls(path, show_hidden=show_hidden)
        if not entries:
            return "", True
        if long_fmt:
            lines = []
            for e in entries:
                full = fs.resolve_path(e) if path is None else fs.resolve_path(f"{path}/{e}")
                kind = "d" if fs.is_dir(full) else "-"
                perm = "rwxr-xr-x" if kind == "d" else "rw-r--r--"
                lines.append(f"{kind}{perm}  1 root root  4096 Jun  1 00:00 {e}")
            return "\n".join(lines), True
        return "\n".join(entries), True

    # ── cd ────────────────────────────────────────────────────────────────
    if name == "cd":
        target = parts[1] if len(parts) > 1 else "~"
        err    = fs.cd(target)
        return err, err == ""

    # ── mkdir ─────────────────────────────────────────────────────────────
    if name == "mkdir":
        if len(parts) < 2:
            return "mkdir: missing operand", False
        err = fs.mkdir(parts[-1])   # ignore -p flag, just create the path
        return err, err == ""

    # ── touch ─────────────────────────────────────────────────────────────
    if name == "touch":
        if len(parts) < 2:
            return "touch: missing file operand", False
        for fname in parts[1:]:
            if not fs.exists(fname):
                fs.write_file(fname, "")
        return "", True

    # ── rm ────────────────────────────────────────────────────────────────
    if name == "rm":
        flags     = [p for p in parts[1:] if p.startswith("-")]
        args      = [p for p in parts[1:] if not p.startswith("-")]
        recursive = any("r" in f.lower() for f in flags)
        if not args:
            return "rm: missing operand", False
        msgs = []
        ok   = True
        for path in args:
            err = fs.remove(path, recursive=recursive)
            if err:
                msgs.append(err)
                ok = False
        return "\n".join(msgs), ok

    # ── cp ────────────────────────────────────────────────────────────────
    if name == "cp":
        if len(parts) < 3:
            return "cp: missing file operand", False
        src, dst = parts[-2], parts[-1]
        content  = fs.read_file(src)
        if content is None:
            return f"cp: cannot stat '{src}': No such file or directory", False
        fs.write_file(dst, content)
        return "", True

    # ── mv ────────────────────────────────────────────────────────────────
    if name == "mv":
        if len(parts) < 3:
            return "mv: missing file operand", False
        src, dst = parts[-2], parts[-1]
        content  = fs.read_file(src)
        if content is None:
            return f"mv: cannot stat '{src}': No such file or directory", False
        fs.write_file(dst, content)
        fs.remove(src)
        return "", True

    # ── chmod ─────────────────────────────────────────────────────────────
    if name == "chmod":
        # silently succeed — no real permissions in a fake FS
        return "", True

    # ── chown ─────────────────────────────────────────────────────────────
    if name == "chown":
        return "", True

    return None
