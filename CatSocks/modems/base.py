"""Vendor-neutral modem driver contracts and metadata."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re
from typing import Protocol


@dataclass(frozen=True)
class ModemIdentity:
    manufacturer: str = ""
    model: str = ""
    revision: str = ""


@dataclass(frozen=True)
class TestedModule:
    model: str
    firmware: str = "Any"
    status: str = "tested"


@dataclass(frozen=True)
class DriverInfo:
    driver_id: str
    display_name: str
    driver_version: str
    manufacturer_patterns: tuple[str, ...]
    model_patterns: tuple[str, ...] = ()
    tested_modules: tuple[TestedModule, ...] = ()
    features: tuple[str, ...] = ()

    def matches(self, identity: ModemIdentity) -> bool:
        manufacturer = identity.manufacturer.strip()
        model = identity.model.strip()
        if not any(re.search(pattern, manufacturer, re.I) for pattern in self.manufacturer_patterns):
            return False
        if self.model_patterns and not any(re.search(pattern, model, re.I) for pattern in self.model_patterns):
            return False
        return True

    def tested_match(self, identity: ModemIdentity) -> TestedModule | None:
        normalized = re.sub(r"[^a-z0-9]", "", identity.model.lower())
        for module in self.tested_modules:
            expected = re.sub(r"[^a-z0-9]", "", module.model.lower())
            if normalized and (normalized in expected or expected in normalized):
                return module
        return None


@dataclass(frozen=True)
class ModemCapabilities:
    max_sockets: int
    max_tcp_chunk: int
    max_udp_payload: int
    supports_tcp: bool = True
    supports_udp: bool = True
    supports_ipv6: bool = False
    max_active_connections: int | None = None
    max_parallel_opens: int = 1
    tcp_idle_timeout: float | None = None


class ModemConnection(Protocol):
    sock_id: int
    protocol: str

    def send(self, data: bytes) -> None: ...
    def recv(self, timeout: float | None = None) -> bytes | None: ...
    def close(self) -> None: ...


class CellularModemDriver(ABC):
    @property
    @abstractmethod
    def capabilities(self) -> ModemCapabilities:
        raise NotImplementedError

    @abstractmethod
    def open_tcp_connection(self, host: str, port: int) -> ModemConnection | None:
        raise NotImplementedError

    @abstractmethod
    def open_udp_connection(self, host: str, port: int) -> ModemConnection | None:
        raise NotImplementedError

    @abstractmethod
    def shutdown(self) -> None:
        raise NotImplementedError
