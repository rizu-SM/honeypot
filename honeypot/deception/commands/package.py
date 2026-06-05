"""
Package manager commands: apt, apt-get, pip, pip3, yum, dnf
"""

import shlex
from typing import Optional, Tuple


def handle_package(cmd: str, fs) -> Optional[Tuple[str, bool]]:
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()

    if not parts:
        return None

    name = parts[0]

    # ── apt / apt-get ─────────────────────────────────────────────────────
    if name in ("apt", "apt-get"):
        if len(parts) < 2:
            return f"{name}: requires a command", False
        sub = parts[1]
        if sub == "update":
            return (
                "Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease\n"
                "Hit:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease\n"
                "Reading package lists... Done"
            ), True
        if sub in ("install", "reinstall"):
            pkg = parts[2] if len(parts) > 2 else "PACKAGE"
            return (
                f"Reading package lists... Done\n"
                f"Building dependency tree\n"
                f"Reading state information... Done\n"
                f"The following NEW packages will be installed:\n"
                f"  {pkg}\n"
                f"0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
                f"Need to get 0 B/512 kB of archives.\n"
                f"After this operation, 1,024 kB of additional disk space will be used.\n"
                f"Selecting previously unselected package {pkg}.\n"
                f"Setting up {pkg} ... done"
            ), True
        if sub in ("remove", "purge"):
            pkg = parts[2] if len(parts) > 2 else "PACKAGE"
            return f"Removing {pkg} ...\nPurging configuration files for {pkg} ...", True
        if sub == "upgrade":
            return "Reading package lists... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", True
        if sub in ("list", "show"):
            return "Listing... Done", True
        return f"{name} {sub}: command not found", False

    # ── pip / pip3 ────────────────────────────────────────────────────────
    if name in ("pip", "pip3", "python3 -m pip"):
        if len(parts) < 2:
            return "pip: try 'pip help'", False
        sub = parts[1]
        if sub == "install":
            pkg = parts[2] if len(parts) > 2 else "PACKAGE"
            return (
                f"Collecting {pkg}\n"
                f"  Downloading {pkg}-1.0.0-py3-none-any.whl (10 kB)\n"
                f"Installing collected packages: {pkg}\n"
                f"Successfully installed {pkg}-1.0.0"
            ), True
        if sub in ("list", "freeze"):
            return (
                "Package    Version\n"
                "---------- -------\n"
                "flask      3.1.0\n"
                "requests   2.31.0\n"
                "paramiko   3.4.0"
            ), True
        if sub == "uninstall":
            pkg = parts[2] if len(parts) > 2 else "PACKAGE"
            return f"Found existing installation: {pkg}\nSuccessfully uninstalled {pkg}", True
        return f"pip: No command '{sub}'", False

    # ── yum / dnf ─────────────────────────────────────────────────────────
    if name in ("yum", "dnf"):
        if len(parts) < 2:
            return f"{name}: requires a command", False
        sub = parts[1]
        if sub == "install":
            pkg = parts[2] if len(parts) > 2 else "PACKAGE"
            return (
                f"Dependencies resolved.\n"
                f"Installing : {pkg}-1.0.0.x86_64\n"
                f"Installed  : {pkg}-1.0.0.x86_64\n"
                f"Complete!"
            ), True
        if sub == "update":
            return "Last metadata expiration check. Nothing to do.", True
        return f"{name}: No command '{sub}'", False

    return None
