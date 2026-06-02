import datetime
import socket
import threading

import paramiko

from honeypot.core.config import Config
from honeypot.core.event_bus import EventBus
from honeypot.core.logger import get_logger
from honeypot.services.base import BaseService

logger = get_logger(__name__)

# The banner that identifies our "server" to the attacker
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"

# Fake responses to common commands typed in the shell
FAKE_RESPONSES = {
    "id":           "uid=0(root) gid=0(root) groups=0(root)",
    "whoami":       "root",
    "pwd":          "/root",
    "uname -a":     "Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux",
    "ls":           "snap",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "ifconfig":     "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15",
    "exit":         "",
    "logout":       "",
}


class SSHServerInterface(paramiko.ServerInterface):
    """
    Paramiko calls methods on this class during the SSH handshake.
    We override them to control what gets accepted and to capture credentials.
    """

    def __init__(self, client_ip: str, client_port: int, event_bus: EventBus):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.event_bus   = event_bus
        self.username    = ""
        self.password    = ""
        # Event that signals the shell is ready to use
        self.shell_ready = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Called when attacker requests a channel. We allow 'session' channels."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Called when attacker tries to log in with a password. We capture and accept."""
        self.username = username
        self.password = password

        self.event_bus.publish({
            "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "protocol":    "SSH",
            "source_ip":   self.client_ip,
            "source_port": self.client_port,
            "username":    username,
            "password":    password,
        })

        logger.info("SSH login attempt", extra={"extra": {
            "ip": self.client_ip,
            "username": username,
        }})

        # Always accept — maximises how many commands we capture next
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        """Called when attacker requests an interactive shell. Signal that it's ready."""
        self.shell_ready.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        """Called when attacker runs a single command (ssh host 'command')."""
        cmd = command.decode("utf-8", errors="replace").strip()
        response = FAKE_RESPONSES.get(cmd, f"bash: {cmd.split()[0]}: command not found")
        if response:
            channel.sendall((response + "\n").encode())
        channel.send_exit_status(0)
        return True


class SSHHoneypot(BaseService):

    def __init__(self, config: Config, event_bus: EventBus):
        super().__init__(config, event_bus)
        self._host_key = self._load_or_generate_key()

    def _load_or_generate_key(self) -> paramiko.RSAKey:
        """
        Load the RSA host key from disk, or generate a new one if it doesn't exist.
        The key must stay the same across restarts — changing it makes SSH clients
        think the server identity changed (man-in-the-middle warning).
        """
        key_path = self.config.data_dir / "ssh_host_key"
        if key_path.exists():
            logger.info("Loaded existing SSH host key")
            return paramiko.RSAKey(filename=str(key_path))

        logger.info("Generating new SSH host key")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        return key

    def _run(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", self.config.ssh_port))
        server_sock.listen(100)
        server_sock.settimeout(1.0)

        self.logger.info(f"SSH honeypot listening on port {self.config.ssh_port}")

        while not self._stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue

            thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
            )
            thread.start()

        server_sock.close()

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        ip, port = addr
        transport = None
        try:
            # Wrap the raw socket in a paramiko Transport (handles all SSH crypto)
            transport = paramiko.Transport(client_sock)
            transport.local_version = SSH_BANNER
            transport.add_server_key(self._host_key)

            server_interface = SSHServerInterface(ip, port, self.event_bus)

            # Start the SSH handshake — paramiko calls server_interface methods
            transport.start_server(server=server_interface)

            # Wait for the attacker to open a channel (up to 30 seconds)
            channel = transport.accept(30)
            if channel is None:
                return

            # Wait for the attacker to request a shell (up to 10 seconds)
            if not server_interface.shell_ready.wait(10):
                return

            self._run_shell(channel, ip, port, server_interface.username)

        except Exception:
            pass
        finally:
            if transport:
                transport.close()

    def _run_shell(self, channel: paramiko.Channel, ip: str, port: int, username: str):
        """Simulate an interactive shell session after login."""
        commands = []

        # Send a realistic welcome message
        channel.sendall(
            b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n"
            b"Last login: Mon Jan  1 00:00:01 2024 from 192.168.1.1\r\n"
        )

        while not self._stop_event.is_set():
            channel.sendall(b"root@ubuntu:~# ")

            cmd = self._read_channel(channel)
            if cmd is None:
                break

            commands.append(cmd)

            if cmd.lower() in ("exit", "logout", "quit", ""):
                break

            response = FAKE_RESPONSES.get(cmd, f"bash: {cmd.split()[0] if cmd else ''}: command not found")
            if response:
                channel.sendall((response + "\r\n").encode())

        # Log the full session commands if any were captured
        if commands:
            self.event_bus.publish({
                "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "protocol":    "SSH_SESSION",
                "source_ip":   ip,
                "source_port": port,
                "username":    username,
                "commands":    commands,
            })

    def _read_channel(self, channel: paramiko.Channel) -> str | None:
        """Read one line of input from the SSH channel."""
        buf = b""
        try:
            while True:
                chunk = channel.recv(1)
                if not chunk:
                    return None
                # Enter key sends \r — treat as end of line
                if chunk in (b"\r", b"\n"):
                    channel.sendall(b"\r\n")   # echo the newline back
                    return buf.decode("utf-8", errors="replace").strip()
                # Backspace
                if chunk == b"\x7f" and buf:
                    buf = buf[:-1]
                    channel.sendall(b"\b \b")  # erase character on terminal
                    continue
                buf += chunk
                channel.sendall(chunk)         # echo character back to attacker
        except Exception:
            return None
