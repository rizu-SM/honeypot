"""
Fake in-memory Linux filesystem for the honeypot shell.
Does NOT touch the real filesystem — everything is simulated.
"""

import copy
import datetime

# The fake filesystem tree
# Keys are absolute paths, values are either:
#   dict  → directory (key = filename, value = content string or nested dict)
#   str   → file content
FAKE_FS = {
    "/": {
        "root": {
            ".bashrc": "# .bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
            ".bash_history": "",
            ".ssh": {
                "authorized_keys": "",
                "known_hosts": "",
            },
        },
        "etc": {
            "passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            ),
            "shadow": "root:$6$xyz$fakehashvalue:19000:0:99999:7:::\n",
            "hostname":  "ubuntu\n",
            "hosts":     "127.0.0.1 localhost\n127.0.1.1 ubuntu\n",
            "os-release": (
                'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\n'
                'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
            ),
            "crontab":   "# m h dom mon dow command\n",
            "ssh": {
                "sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
            },
        },
        "var": {
            "log": {
                "auth.log":   "Jun  1 00:00:01 ubuntu sshd[1234]: Accepted password for root\n",
                "syslog":     "Jun  1 00:00:01 ubuntu kernel: Linux version 5.4.0-42-generic\n",
                "dpkg.log":   "",
            },
            "www": {
                "html": {
                    "index.html": "<html><body>It works!</body></html>\n",
                }
            },
        },
        "tmp": {},
        "home": {
            "ubuntu": {
                ".bashrc": "# user bashrc\n",
            }
        },
        "proc": {
            "version": "Linux version 5.4.0-42-generic (buildd@lcy01-amd64-027)\n",
            "cpuinfo":  "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2676 v3\n",
            "meminfo":  "MemTotal:        1024000 kB\nMemFree:          512000 kB\n",
        },
        "usr": {
            "bin": {},
            "local": {
                "bin": {},
            },
        },
        "bin": {},
        "sbin": {},
    }
}


class PseudoFS:
    """
    Simulates a Linux filesystem in memory.
    One instance per SSH session — state is not shared between attackers.
    """

    hostname = "ubuntu"
    _username = "root"

    def __init__(self):
        self._tree = copy.deepcopy(FAKE_FS)
        self._cwd  = "/root"             # start in /root like a real root login
        self._env  = {
            "HOME":  "/root",
            "USER":  "root",
            "SHELL": "/bin/bash",
            "PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD":   "/root",
        }

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def get_current_directory(self) -> str:
        """Return cwd, replacing /root with ~ for display."""
        if self._cwd == "/root":
            return "~"
        if self._cwd.startswith("/root/"):
            return "~" + self._cwd[5:]
        return self._cwd

    def get_user(self) -> str:
        return self._username

    def resolve_path(self, path: str) -> str:
        """Turn a relative or absolute path into an absolute path."""
        if not path or path == "~":
            return "/root"
        if path.startswith("~/"):
            path = "/root/" + path[2:]
        if not path.startswith("/"):
            path = self._cwd.rstrip("/") + "/" + path
        # Resolve .. and .
        parts = []
        for part in path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        return "/" + "/".join(parts)

    def _get_node(self, path: str):
        """Return the dict/string at the given absolute path, or None."""
        node = self._tree["/"]
        if path == "/":
            return node
        parts = [p for p in path.split("/") if p]
        for part in parts:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def cd(self, path: str) -> str:
        """Change current directory. Returns error message or empty string."""
        target = self.resolve_path(path)
        node   = self._get_node(target)
        if node is None:
            return f"bash: cd: {path}: No such file or directory"
        if not isinstance(node, dict):
            return f"bash: cd: {path}: Not a directory"
        self._cwd    = target
        self._env["PWD"] = target
        return ""

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    def ls(self, path: str = None, show_hidden: bool = False) -> list[str]:
        """Return list of filenames in a directory."""
        target = self.resolve_path(path) if path else self._cwd
        node   = self._get_node(target)
        if node is None:
            return []
        if isinstance(node, str):
            return [target.split("/")[-1]]
        entries = list(node.keys())
        if not show_hidden:
            entries = [e for e in entries if not e.startswith(".")]
        return sorted(entries)

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def read_file(self, path: str) -> str | None:
        """Return file contents or None if not found / is a directory."""
        target = self.resolve_path(path)
        node   = self._get_node(target)
        if node is None or isinstance(node, dict):
            return None
        return node

    def write_file(self, path: str, content: str) -> None:
        """Create or overwrite a file."""
        target = self.resolve_path(path)
        parts  = [p for p in target.split("/") if p]
        node   = self._tree["/"]
        for part in parts[:-1]:
            if part not in node:
                node[part] = {}
            node = node[part]
        node[parts[-1]] = content

    def mkdir(self, path: str) -> str:
        """Create a directory. Returns error or empty string."""
        target = self.resolve_path(path)
        parts  = [p for p in target.split("/") if p]
        node   = self._tree["/"]
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                return f"mkdir: cannot create directory '{path}': No such file or directory"
            node = node[part]
        name = parts[-1]
        if name in node:
            return f"mkdir: cannot create directory '{path}': File exists"
        node[name] = {}
        return ""

    def remove(self, path: str, recursive: bool = False) -> str:
        """Remove a file or directory."""
        target = self.resolve_path(path)
        parts  = [p for p in target.split("/") if p]
        if not parts:
            return "rm: cannot remove '/': Permission denied"
        node = self._tree["/"]
        for part in parts[:-1]:
            if part not in node:
                return f"rm: cannot remove '{path}': No such file or directory"
            node = node[part]
        name = parts[-1]
        if name not in node:
            return f"rm: cannot remove '{path}': No such file or directory"
        if isinstance(node[name], dict) and not recursive:
            return f"rm: cannot remove '{path}': Is a directory"
        del node[name]
        return ""

    def exists(self, path: str) -> bool:
        return self._get_node(self.resolve_path(path)) is not None

    def is_dir(self, path: str) -> bool:
        node = self._get_node(self.resolve_path(path))
        return isinstance(node, dict)

    def get_env(self, key: str) -> str:
        return self._env.get(key, "")
