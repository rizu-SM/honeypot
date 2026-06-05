"""
Command dispatcher for the fake shell.
Handles:
  - sudo prefix (stripped)
  - output redirect: cmd > file
  - pipe: cmd1 | cmd2
  - exits: exit / logout / quit
  - realistic delay
  - unknown commands
"""

import random
import time
from typing import Tuple

from .pseudo_fs import PseudoFS
from .commands  import COMMAND_HANDLERS


def _dispatch_single(cmd: str, fs: PseudoFS, stdin: str = "") -> Tuple[str, bool]:
    """Run one command (no pipes, no redirects) and return (output, success)."""
    cmd = cmd.strip()

    if cmd.startswith("sudo "):
        cmd = cmd[5:].strip()
    if cmd == "sudo":
        return "", True

    if not cmd:
        return "", True

    # Inject piped stdin into grep/head/tail/wc when no file arg is given
    parts = cmd.split()
    if stdin and parts[0] in ("grep", "head", "tail", "wc", "sort", "uniq", "awk", "sed"):
        non_flags = [p for p in parts[1:] if not p.startswith("-")]
        # grep: first non-flag is the pattern, rest are files
        # head/tail/wc: all non-flags are files
        min_args = 2 if parts[0] == "grep" else 1
        has_file_arg = len(non_flags) >= min_args
        if not has_file_arg:
            # Append stdin as a virtual file by writing it to a temp path
            import uuid
            tmp = f"/tmp/_pipe_{uuid.uuid4().hex[:8]}"
            fs.write_file(tmp, stdin)
            cmd = cmd + f" {tmp}"
            result_out = None
            for handler in COMMAND_HANDLERS:
                result_out = handler(cmd, fs)
                if result_out is not None:
                    break
            fs.remove(tmp)
            return result_out if result_out is not None else ("", True)

    for handler in COMMAND_HANDLERS:
        result = handler(cmd, fs)
        if result is not None:
            return result

    name = cmd.split()[0]
    return f"bash: {name}: command not found", False


def run_command(cmd: str, fs: PseudoFS) -> Tuple[str, bool]:
    """
    Execute a command string, supporting:
      - output redirect: cmd > file or cmd >> file
      - pipe: cmd1 | cmd2 | ...
      - built-in: exit, logout, quit
    Returns (output, should_exit).
    """
    # Realistic processing delay
    time.sleep(random.uniform(0.02, 0.15))

    cmd = cmd.strip()
    if not cmd:
        return "", False

    # ── exit / logout ─────────────────────────────────────────────────────
    if cmd in ("exit", "logout", "quit"):
        return "logout", True

    # ── output redirect ───────────────────────────────────────────────────
    append = False
    redirect_file = None
    if " >> " in cmd:
        cmd, redirect_file = cmd.split(" >> ", 1)
        redirect_file = redirect_file.strip()
        append = True
    elif " > " in cmd:
        cmd, redirect_file = cmd.split(" > ", 1)
        redirect_file = redirect_file.strip()

    # ── pipe chain ────────────────────────────────────────────────────────
    stages = [s.strip() for s in cmd.split(" | ")]
    output = ""
    ok     = True

    for stage in stages:
        out, ok = _dispatch_single(stage, fs, stdin=output)
        output  = out

    # ── write redirect output to fake file ────────────────────────────────
    if redirect_file:
        if append:
            existing = fs.read_file(redirect_file) or ""
            fs.write_file(redirect_file, existing + output + "\n")
        else:
            fs.write_file(redirect_file, output + "\n")
        return "", False

    return output, False
