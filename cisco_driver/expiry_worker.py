"""Background job that removes blocks when their TTL runs out."""

from __future__ import annotations

import logging
import threading
from typing import List, Optional

from .driver import CiscoDriver, Result

log = logging.getLogger(__name__)


class ExpiryWorker:
    def __init__(self, driver: CiscoDriver, interval: float = 10.0):
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.driver = driver
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def run_once(self) -> List[Result]:
        results = self.driver.expire_due()
        for r in results:
            log.info("expiry: %s %s on %s -> %s", r.ip, r.seq, r.device, r.status)
        return results

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # keep the worker alive whatever happens
                log.exception("Expiry run failed; will try again")
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="expiry-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def __enter__(self) -> "ExpiryWorker":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
