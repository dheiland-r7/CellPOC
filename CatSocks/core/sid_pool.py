"""Thread-safe FIFO modem socket-ID allocator with quarantine support."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Iterable


class SidPool:
    """Manage modem socket IDs using FIFO rotation and quarantine."""

    def __init__(self, socket_ids: Iterable[int]):
        ids = list(socket_ids)
        if not ids:
            raise ValueError("SidPool requires at least one socket ID")
        if len(ids) != len(set(ids)):
            raise ValueError("SidPool socket IDs must be unique")
        self._free = deque(ids)
        self._all_ids = frozenset(ids)
        self._quarantined: dict[int, str] = {}
        self._lock = threading.Lock()

    def acquire(self) -> int:
        with self._lock:
            if not self._free:
                raise RuntimeError("No socket IDs available")
            sid = self._free.popleft()
            logging.debug("[SID %s] allocated; free SID queue=%s", sid, list(self._free))
            return sid

    def release(self, sid: int) -> bool:
        self._validate(sid)
        with self._lock:
            if sid in self._quarantined:
                logging.warning(
                    "[SID %s] release deferred; quarantined (%s)",
                    sid,
                    self._quarantined[sid],
                )
                return False
            if sid in self._free:
                return False
            self._free.append(sid)
            logging.debug("[SID %s] released; free SID queue=%s", sid, list(self._free))
            return True

    def quarantine(self, sid: int, reason: str) -> bool:
        self._validate(sid)
        with self._lock:
            try:
                self._free.remove(sid)
            except ValueError:
                pass
            newly_quarantined = sid not in self._quarantined
            self._quarantined[sid] = reason
            logging.warning("[SID %s] quarantined: %s", sid, reason)
            return newly_quarantined

    def recover(self, sid: int) -> bool:
        self._validate(sid)
        with self._lock:
            was_quarantined = self._quarantined.pop(sid, None) is not None
            if sid not in self._free:
                self._free.append(sid)
            logging.info("[SID %s] recovered; free SID queue=%s", sid, list(self._free))
            return was_quarantined

    def is_quarantined(self, sid: int) -> bool:
        self._validate(sid)
        with self._lock:
            return sid in self._quarantined

    def quarantine_reason(self, sid: int) -> str | None:
        self._validate(sid)
        with self._lock:
            return self._quarantined.get(sid)

    def snapshot(self) -> list[int]:
        with self._lock:
            return list(self._free)

    def quarantine_snapshot(self) -> dict[int, str]:
        with self._lock:
            return dict(self._quarantined)

    def _validate(self, sid: int) -> None:
        if sid not in self._all_ids:
            raise ValueError(f"Unknown socket ID: {sid}")

    def __len__(self) -> int:
        with self._lock:
            return len(self._free)
