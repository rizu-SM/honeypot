"""
Service management: systemctl, service, crontab
"""

import shlex
from typing import Optional, Tuple

_RUNNING_SERVICES = {
    "ssh", "sshd", "apache2", "nginx", "mysql", "cron",
    "NetworkManager", "rsyslog", "ufw",
}


def handle_service(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── systemctl ─────────────────────────────────────────────────────────
    if name == "systemctl":
        if len(parts) < 2:
            return "systemctl: requires a command", False
        sub = parts[1]

        if sub in ("status",):
            svc = parts[2] if len(parts) > 2 else "system"
            running = svc.rstrip(".service") in _RUNNING_SERVICES
            state   = "active (running)" if running else "inactive (dead)"
            return (
                f"● {svc} - {svc.capitalize()} Service\n"
                f"   Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)\n"
                f"   Active: {state}\n"
                f"   CGroup: /system.slice/{svc}.service"
            ), running

        if sub in ("start", "stop", "restart", "enable", "disable", "reload"):
            return "", True

        if sub in ("list-units", "list-unit-files"):
            lines = ["UNIT                       LOAD   ACTIVE SUB     DESCRIPTION"]
            for s in sorted(_RUNNING_SERVICES):
                lines.append(f"{s+'.service':<30} loaded active running {s.capitalize()}")
            return "\n".join(lines), True

        return f"systemctl: unknown command '{sub}'", False

    # ── service ───────────────────────────────────────────────────────────
    if name == "service":
        if len(parts) < 3:
            return "Usage: service <name> <action>", False
        svc, action = parts[1], parts[2]
        if action == "status":
            running = svc in _RUNNING_SERVICES
            state   = "is running" if running else "is not running"
            return f" * {svc} {state}", running
        if action in ("start", "stop", "restart", "reload"):
            return f" * {'Starting' if action == 'start' else action.capitalize()+' ing'} {svc} ... [ ok ]", True
        return f"service: Unknown action '{action}'", False

    # ── crontab ───────────────────────────────────────────────────────────
    if name == "crontab":
        if "-l" in parts:
            content = fs.read_file("/etc/crontab") or "no crontab for root"
            return content, True
        if "-e" in parts:
            # Can't open editor — just acknowledge
            return "", True
        return "crontab: unknown option", False

    return None
