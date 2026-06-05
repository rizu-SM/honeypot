"""
System info commands: ps, top, uname, whoami, id, uptime, date, hostname, free, df
"""

import shlex
from typing import Optional, Tuple


_PS = """\
  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  123 ?        00:00:00 sshd
  456 ?        00:00:01 apache2
  789 ?        00:00:00 mysql
 1234 pts/0    00:00:00 bash
 1235 pts/0    00:00:00 ps
"""

_TOP = """\
top - 00:00:01 up  1:23,  1 user,  load average: 0.08, 0.03, 0.01
Tasks:  87 total,   1 running,  86 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.5 id,  0.0 wa
MiB Mem :    985.0 total,    432.0 free,    312.0 used,    241.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.    523.0 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  102516  11692   8488 S   0.0   1.2   0:02.10 systemd
  123 root      20   0   72300   6800   6024 S   0.0   0.7   0:00.12 sshd
"""

_FREE = """\
              total        used        free      shared  buff/cache   available
Mem:        1008640      319488      442368        1024      246784      535552
Swap:       2097152           0     2097152
"""

_DF = """\
Filesystem     1K-blocks    Used Available Use% Mounted on
udev              491520       0    491520   0% /dev
tmpfs             100864     804     100060   1% /run
/dev/sda1       20511312 4823040  14634220  25% /
tmpfs             504320       0    504320   0% /dev/shm
"""


def handle_system(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── whoami ────────────────────────────────────────────────────────────
    if name == "whoami":
        return fs.get_user(), True

    # ── id ────────────────────────────────────────────────────────────────
    if name == "id":
        return "uid=0(root) gid=0(root) groups=0(root)", True

    # ── uname ─────────────────────────────────────────────────────────────
    if name == "uname":
        if "-a" in parts:
            return "Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux", True
        if "-r" in parts:
            return "5.4.0-42-generic", True
        return "Linux", True

    # ── hostname ──────────────────────────────────────────────────────────
    if name == "hostname":
        return fs.hostname, True

    # ── ps ────────────────────────────────────────────────────────────────
    if name == "ps":
        return _PS, True

    # ── top ───────────────────────────────────────────────────────────────
    if name == "top":
        return _TOP, True

    # ── uptime ────────────────────────────────────────────────────────────
    if name == "uptime":
        return " 00:00:01 up  1:23,  1 user,  load average: 0.08, 0.03, 0.01", True

    # ── date ──────────────────────────────────────────────────────────────
    if name == "date":
        return "Thu Jun  1 00:00:01 UTC 2024", True

    # ── free ──────────────────────────────────────────────────────────────
    if name == "free":
        return _FREE, True

    # ── df ────────────────────────────────────────────────────────────────
    if name == "df":
        return _DF, True

    # ── lscpu ─────────────────────────────────────────────────────────────
    if name == "lscpu":
        return (
            "Architecture:                    x86_64\n"
            "CPU(s):                          1\n"
            "Model name:                      Intel(R) Xeon(R) CPU E5-2676 v3\n"
            "CPU MHz:                         2399.998\n"
        ), True

    # ── lsb_release ───────────────────────────────────────────────────────
    if name == "lsb_release":
        return (
            "No LSB modules are available.\n"
            "Distributor ID:\tUbuntu\n"
            "Description:\tUbuntu 20.04.6 LTS\n"
            "Release:\t20.04\n"
            "Codename:\tfocal"
        ), True

    # ── w / who ───────────────────────────────────────────────────────────
    if name in ("w", "who"):
        return "root     pts/0        00:00:00 00:00 (:0)", True

    # ── last ──────────────────────────────────────────────────────────────
    if name == "last":
        return "root     pts/0        :0               Thu Jun  1 00:00   still logged in", True

    # ── dmesg ─────────────────────────────────────────────────────────────
    if name == "dmesg":
        return "[    0.000000] Linux version 5.4.0-42-generic\n[    0.000001] BIOS-provided physical RAM map:", True

    # ── kill / killall ────────────────────────────────────────────────────
    if name in ("kill", "killall"):
        return "", True

    return None
