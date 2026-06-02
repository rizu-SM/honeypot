import socketserver

from honeypot.core.config import Config
from honeypot.core.event_bus import EventBus
from honeypot.core.logger import get_logger
from honeypot.services.base import BaseService

logger = get_logger(__name__)


class FTPHandler(socketserver.StreamRequestHandler):
    """
    Handles one FTP client connection.
    StreamRequestHandler gives us self.rfile (read) and self.wfile (write)
    so we can treat the socket like a file — readline() and write().
    """

    # Injected by FTPHoneypot before the server starts
    # (can't pass via __init__ because socketserver creates handlers internally)
    event_bus: EventBus = None

    def handle(self):
        ip, port = self.client_address
        logger.info("FTP connection", extra={"extra": {"ip": ip, "port": port}})

        username = ""
        password = ""

        # Step 1 — send the welcome banner
        self._send("220 FTP server ready (vsftpd 3.0.3)")

        # Step 2 — process commands until client disconnects or quits
        while True:
            line = self._read()
            if line is None:
                break   # client disconnected

            # FTP commands are "COMMAND argument" — split on first space
            parts = line.split(" ", 1)
            cmd  = parts[0].upper()
            arg  = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                self._send("331 Please specify the password.")

            elif cmd == "PASS":
                password = arg
                # Emit the captured credentials to the EventBus
                self.event_bus.publish({
                    "timestamp":   self._now(),
                    "protocol":    "FTP",
                    "source_ip":   ip,
                    "source_port": port,
                    "username":    username,
                    "password":    password,
                })
                logger.info("FTP credentials captured", extra={"extra": {
                    "ip": ip, "username": username,
                }})
                self._send("230 Login successful.")

            elif cmd == "QUIT":
                self._send("221 Goodbye.")
                break

            elif cmd == "SYST":
                self._send("215 UNIX Type: L8")   # pretend to be Linux

            elif cmd == "PWD":
                self._send('257 "/" is the current directory')

            elif cmd in ("LIST", "NLST"):
                self._send("425 Use PORT or PASV first.")

            elif cmd == "TYPE":
                self._send("200 Switching to Binary mode.")

            else:
                self._send(f"500 Unknown command.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, message: str) -> None:
        """Write a response line to the client. FTP lines end with \\r\\n."""
        try:
            self.wfile.write(f"{message}\r\n".encode())
            self.wfile.flush()
        except Exception:
            pass   # client already disconnected

    def _read(self) -> str | None:
        """Read one command line from the client."""
        try:
            line = self.rfile.readline(1024)
            if not line:
                return None
            return line.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    def _now(self) -> str:
        import datetime
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


class FTPServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer that spawns a new thread for each connection."""
    allow_reuse_address = True   # avoid "address already in use" on restart
    daemon_threads = True        # handler threads die when main program exits


class FTPHoneypot(BaseService):

    def __init__(self, config: Config, event_bus: EventBus):
        super().__init__(config, event_bus)

    def _run(self):
        # Inject event_bus into the handler class before starting the server
        FTPHandler.event_bus = self.event_bus

        with FTPServer(("0.0.0.0", self.config.ftp_port), FTPHandler) as server:
            # Use a 1 second timeout so we can check _stop_event regularly
            server.timeout = 1.0
            self.logger.info(f"FTP honeypot listening on port {self.config.ftp_port}")

            while not self._stop_event.is_set():
                server.handle_request()  # handles one connection then returns
