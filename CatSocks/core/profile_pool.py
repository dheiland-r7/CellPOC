"""Thread-safe FIFO Cinterion Internet-service profile allocator."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Iterable


class ProfilePool:
    """Manage Cinterion Internet service profile IDs using FIFO rotation."""

    def __init__(self, profile_ids: Iterable[int]):
        ids = list(profile_ids)
        if not ids:
            raise ValueError("ProfilePool requires at least one profile ID")
        if len(ids) != len(set(ids)):
            raise ValueError("Profile IDs must be unique")
        self._free = deque(ids)
        self._all = frozenset(ids)
        self._lock = threading.Lock()

    def acquire(self) -> int:
        with self._lock:
            if not self._free:
                raise RuntimeError("No Internet service profiles available")
            profile = self._free.popleft()
            logging.debug("[PROFILE %s] allocated; free=%s", profile, list(self._free))
            return profile

    def release(self, profile: int) -> bool:
        self._validate(profile)
        with self._lock:
            if profile in self._free:
                return False
            self._free.append(profile)
            logging.debug("[PROFILE %s] released; free=%s", profile, list(self._free))
            return True

    def snapshot(self) -> list[int]:
        with self._lock:
            return list(self._free)

    def _validate(self, profile: int) -> None:
        if profile not in self._all:
            raise ValueError(f"Unknown Internet service profile: {profile}")

    def __len__(self) -> int:
        with self._lock:
            return len(self._free)
