import datetime
import socket
import threading

from honeypot.core.config import Config
from honeypot.core.event_bus import EventBus
from honeypot.core.logger import get_logger
from honeypot.services.base import BaseService

logger = get_logger(__name__)

# Fake banner shown when the attacker connects
BANNER = (
    "\r\n"
    "Ubuntu 20.04.6 LTS\r\n"
    "\r\n"
)


def strip_iac(data: bytes) -> bytes:
    """
    Remove Telnet IAC (Interpret As Command) control sequences from raw bytes.
    IAC sequences start with 0xFF and are 2 or 3 bytes long.
    Without this, attacker input contains garbage bytes mixed with real text.
    """
    result = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]

        if byte == 0xFF:                        # IAC — start of control sequence
            if i + 1 < len(data):
                next_byte = data[i + 1]
                if next_byte in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT
                    i += 3                      # skip: IAC + verb + option byte
                else:
                    i += 2                      # skip: IAC + single command byte
            else:
                i += 1
        else:
            result.append(byte)                 # normal character — keep it
            i += 1

    return bytes(result)


class TelnetHoneypot(BaseService):

    def __init__(self, config: Config, event_bus: EventBus):
        super().__init__(config, event_bus)

    def _run(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", self.config.telnet_port))
        server_sock.listen(100)
        server_sock.settimeout(1.0)  # allows _stop_event check every second

        self.logger.info(f"Telnet honeypot listening on port {self.config.telnet_port}")

        while not self._stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue   # no connection this second, check stop flag and loop

            # Handle each connection in its own thread
            thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
            )
            thread.start()

        server_sock.close()

    def _handle_client(self, sock: socket.socket, addr: tuple):
        ip, port = addr
        logger.info("Telnet connection", extra={"extra": {"ip": ip, "port": port}})

        try:
            sock.settimeout(30)  # disconnect idle clients after 30 seconds

            # Send welcome banner and login prompt
            self._send(sock, BANNER)
            self._send(sock, "login: ")
            username = self._read_line(sock)
            if username is None:
                return

            self._send(sock, "\r\nPassword: ")
            password = self._read_line(sock)
            if password is None:
                return

            # Publish captured credentials
            self.event_bus.publish({
                "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "protocol":    "Telnet",
                "source_ip":   ip,
                "source_port": port,
                "username":    username,
                "password":    password,
            })
            logger.info("Telnet credentials captured", extra={"extra": {
                "ip": ip, "username": username,
            }})

            # Show a fake "login failed" message — keeps it realistic
            self._send(sock, "\r\nLogin incorrect\r\n")

        except Exception:
            pass
        finally:
            sock.close()

    def _send(self, sock: socket.socket, text: str) -> None:
        """Send a string to the client."""
        try:
            sock.sendall(text.encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _read_line(self, sock: socket.socket) -> str | None:
        """
        Read one line of input from the client, one byte at a time.
        Strips IAC control bytes and stops at newline or carriage return.
        """
        buf = b""
        try:
            while True:
                chunk = sock.recv(1)
                if not chunk:
                    return None          # client disconnected
                buf += chunk
                clean = strip_iac(buf)
                # Stop when we see a newline or carriage return
                if b"\n" in clean or b"\r" in clean:
                    return clean.replace(b"\r", b"").replace(b"\n", b"").decode(
                        "utf-8", errors="replace"
                    ).strip()
        except Exception:
            return None
