import datetime
import threading

from honeypot.core.event_bus import EventBus
from honeypot.core.config import Config
from honeypot.core.logger import get_logger


class BaseService:
    """
    Parent class for all honeypot services.
    Handles threading, graceful shutdown, and event emitting.
    Each service only needs to implement _run().
    """

    def __init__(self, config: Config, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus
        self.logger = get_logger(self.__class__.__name__)
        self._stop_event = threading.Event()  # flag to signal shutdown
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Spin up the service in a background daemon thread."""
        self._thread = threading.Thread(
            target=self._safe_run,
            daemon=True,
            name=self.__class__.__name__,
        )
        self._thread.start()
        self.logger.info(f"{self.__class__.__name__} started")

    def stop(self) -> None:
        """Signal the service to stop. The thread will exit on its next loop."""
        self._stop_event.set()
        self.logger.info(f"{self.__class__.__name__} stopping")

    def _safe_run(self) -> None:
        """Wraps _run() so an unhandled exception doesn't silently kill the thread."""
        try:
            self._run()
        except Exception:
            self.logger.exception(f"{self.__class__.__name__} crashed")

    def _run(self) -> None:
        """Override this in each honeypot service. Contains the main listen loop."""
        raise NotImplementedError

    def _emit(self, **kwargs) -> None:
        """
        Build an event dict and publish it to the EventBus.
        Called from inside _run() whenever an attacker interaction is captured.
        """
        event = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **kwargs,
        }
        self.event_bus.publish(event)
