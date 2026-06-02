import queue
import threading
from typing import Callable

from honeypot.core.logger import get_logger

logger = get_logger(__name__)


class EventBus:
    """
    Decouples event producers (honeypot services) from consumers (database,
    GeoIP, alerts). Producers never block — they drop the event in the queue
    and move on. A single background thread processes events one at a time.
    """

    def __init__(self, maxsize: int = 1000):
        # The queue holds raw event dicts waiting to be processed
        # maxsize=1000 means if the worker falls behind, we drop events
        # rather than letting memory grow forever
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)

        # List of functions to call for every event
        self._subscribers: list[Callable[[dict], None]] = []

        # Single background thread that drains the queue
        self._worker = threading.Thread(
            target=self._dispatch_loop,
            daemon=True,         # dies automatically when main program exits
            name="EventBusWorker",
        )

    def subscribe(self, handler: Callable[[dict], None]) -> None:
        """Register a function to be called for every event."""
        self._subscribers.append(handler)

    def publish(self, event: dict) -> None:
        """
        Called by honeypot services. Non-blocking — if the queue is full,
        the event is dropped rather than stalling the caller.
        """
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full — dropping event", extra={"extra": {
                "protocol": event.get("protocol"),
                "source_ip": event.get("source_ip"),
            }})

    def start(self) -> None:
        """Start the background worker thread."""
        self._worker.start()
        logger.info("EventBus started")

    def _dispatch_loop(self) -> None:
        """
        Runs forever in the background thread.
        Takes one event at a time and calls every subscriber.
        """
        while True:
            event = self._queue.get()   # blocks here until an event arrives

            for handler in self._subscribers:
                try:
                    handler(event)
                except Exception:
                    logger.exception("Subscriber raised an error", extra={"extra": {
                        "handler": getattr(handler, "__name__", str(handler)),
                    }})

            self._queue.task_done()
