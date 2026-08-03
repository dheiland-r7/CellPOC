"""Serial AT transport for CatSocks.

This module owns all raw serial-port interaction:

* serial port lifetime
* the single reader thread
* CRLF line framing
* raw payload reads
* serialized AT command transactions
* command response timing
* QISEND prompt dispatch

Vendor-specific interpretation remains in the modem driver through callbacks.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import logging
import re
import threading
import time
from typing import Callable, Protocol

try:
    import serial
except ModuleNotFoundError:  # Allows transport unit tests without pyserial installed.
    serial = None


LineHandler = Callable[[str], None]
PromptHandler = Callable[[], None]


def _redact_at_payload(value: str) -> str:
    """Redact large hexadecimal socket payloads from diagnostic logs.

    The full command/response remains available to the modem driver; only the
    human-facing log representation is shortened.
    """
    patterns = (
        # u-blox HEX-mode TCP write command.
        re.compile(r'^(AT\+USOWR=\d+,\d+),"([0-9A-Fa-f]+)"$'),
        # u-blox HEX-mode TCP read response.
        re.compile(r'^(\+USORD:\s*\d+,\d+),"([0-9A-Fa-f]+)"$'),
        # Future u-blox UDP HEX-mode send/read forms.
        re.compile(r'^(AT\+USOST=.*?,\d+),"([0-9A-Fa-f]+)"$'),
        re.compile(r'^(\+USORF:.*?,\d+),"([0-9A-Fa-f]+)"$'),
    )
    for pattern in patterns:
        match = pattern.match(value)
        if match:
            return f'{match.group(1)},"<{len(match.group(2))} hex chars omitted>"'
    return value


class SerialLike(Protocol):
    def read(self, size: int = 1) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...


@dataclass
class _CommandWaiter:
    cmd: str
    event: threading.Event = field(default_factory=threading.Event)
    ok: bool = False
    lines: list[str] = field(default_factory=list)
    queued_at: float = field(default_factory=time.monotonic)
    lock_acquired_at: float | None = None
    written_at: float | None = None
    first_line_at: float | None = None
    completed_at: float | None = None


@dataclass(frozen=True)
class ATCommandResult:
    command: str
    lines: tuple[str, ...]
    queue_delay: float
    response_time: float
    first_line_time: float | None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


class SerialATTransport:
    """Thread-safe serialized AT transport with asynchronous line callbacks."""

    def __init__(
        self,
        port: str,
        baud: int,
        *,
        line_handler: LineHandler | None = None,
        prompt_handler: PromptHandler | None = None,
        serial_factory: Callable[..., SerialLike] | None = None,
    ) -> None:
        if serial_factory is None:
            if serial is None:
                raise RuntimeError("pyserial is required for hardware serial transport")
            serial_factory = serial.Serial
        self._serial = serial_factory(port, baud, timeout=None, write_timeout=0)
        self._write_lock = threading.Lock()
        self._transaction_lock = threading.Lock()
        self._waiter_lock = threading.Lock()
        self._pending_waiters: list[_CommandWaiter] = []
        self._line_handler = line_handler
        self._prompt_handler = prompt_handler
        self._line_buf = b""
        self._stop_event = threading.Event()
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            daemon=True,
            name="catsocks-serial-reader",
        )
        self._reader_thread.start()

    def set_line_handler(self, handler: LineHandler | None) -> None:
        self._line_handler = handler

    def set_prompt_handler(self, handler: PromptHandler | None) -> None:
        self._prompt_handler = handler


    @contextmanager
    def exclusive_transaction(self):
        """Reserve the AT command channel for a multi-stage exchange.

        QISEND is not a normal line-oriented command: it includes an AT write,
        a prompt, raw payload bytes, and a SEND OK/FAIL result. The modem driver
        uses this context so no regular AT command can interleave with it.
        """
        with self._transaction_lock:
            yield

    def write_raw(self, data: bytes) -> int:
        """Write bytes without AT framing while preserving write atomicity."""
        with self._write_lock:
            return self._serial.write(data)

    def read_exact(self, length: int) -> bytes:
        """Read exactly ``length`` raw bytes from the reader-thread context."""
        payload = bytearray()
        while len(payload) < length and not self._stop_event.is_set():
            chunk = self._serial.read(length - len(payload))
            if chunk:
                payload.extend(chunk)
        if len(payload) != length:
            raise EOFError(f"Serial transport stopped after {len(payload)}/{length} bytes")
        return bytes(payload)

    def execute(self, cmd: str, timeout: float = 5) -> ATCommandResult:
        """Execute one AT command and wait for its terminal OK/ERROR."""
        waiter = _CommandWaiter(cmd)
        log_cmd = _redact_at_payload(cmd)
        logging.debug("[AT] queued: %s", log_cmd)

        with self._transaction_lock:
            waiter.lock_acquired_at = time.monotonic()
            queue_delay = waiter.lock_acquired_at - waiter.queued_at
            logging.debug("[AT] lock acquired after %.3fs: %s", queue_delay, log_cmd)

            with self._waiter_lock:
                self._pending_waiters.append(waiter)

            logging.debug("→ AT %s", log_cmd)
            waiter.written_at = time.monotonic()
            self.write_raw((cmd + "\r").encode())

            if not waiter.event.wait(timeout):
                with self._waiter_lock:
                    if waiter in self._pending_waiters:
                        self._pending_waiters.remove(waiter)
                elapsed = time.monotonic() - waiter.written_at
                logging.warning(
                    "[AT] timeout after %.3fs (queue %.3fs): %s",
                    elapsed,
                    queue_delay,
                    log_cmd,
                )
                raise TimeoutError(f"AT cmd timeout after {elapsed:.3f}s: {cmd}")

            completed_at = waiter.completed_at or time.monotonic()
            response_time = completed_at - waiter.written_at
            first_line_time = (
                waiter.first_line_at - waiter.written_at
                if waiter.first_line_at is not None
                else None
            )

            if first_line_time is None:
                logging.debug(
                    "[AT] complete %.3fs (queue %.3fs): %s",
                    response_time,
                    queue_delay,
                    log_cmd,
                )
            else:
                logging.debug(
                    "[AT] first line %.3fs, complete %.3fs (queue %.3fs): %s",
                    first_line_time,
                    response_time,
                    queue_delay,
                    log_cmd,
                )

            for line in waiter.lines:
                if line:
                    logging.debug("← %s", _redact_at_payload(line))
            if not waiter.ok:
                raise IOError(f"AT cmd error: {log_cmd}")

            return ATCommandResult(
                command=cmd,
                lines=tuple(waiter.lines),
                queue_delay=queue_delay,
                response_time=response_time,
                first_line_time=first_line_time,
            )

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._serial.close()
        finally:
            if self._reader_thread.is_alive():
                self._reader_thread.join(timeout=1.0)

    def _reader_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                byte = self._serial.read(1)
                if not byte:
                    continue

                if byte == b">":
                    handler = self._prompt_handler
                    if handler is not None:
                        handler()
                    continue

                self._line_buf += byte
                if self._line_buf.endswith(b"\r\n"):
                    line = self._line_buf.decode(errors="ignore").strip()
                    self._line_buf = b""
                    self._dispatch_line(line)
        except Exception as exc:
            if not self._stop_event.is_set():
                logging.error("[TRANSPORT] reader failure: %s", exc)

    def _dispatch_line(self, line: str) -> None:
        if line:
            logging.debug("URC: %s", _redact_at_payload(line))
        self._feed_command_waiter(line)
        handler = self._line_handler
        if handler is not None:
            handler(line)

    def _feed_command_waiter(self, line: str) -> None:
        with self._waiter_lock:
            if not self._pending_waiters:
                return
            waiter = self._pending_waiters[0]
            now = time.monotonic()
            if waiter.first_line_at is None:
                waiter.first_line_at = now

            if line == "OK":
                waiter.lines.append("OK")
                waiter.ok = True
                waiter.completed_at = now
                waiter.event.set()
                self._pending_waiters.pop(0)
            elif (
                line.startswith("ERROR")
                or line.startswith("+CME ERROR:")
                or line.startswith("+CMS ERROR:")
                or line == "SEND FAIL"
            ):
                waiter.lines.append(line)
                waiter.ok = False
                waiter.completed_at = now
                waiter.event.set()
                self._pending_waiters.pop(0)
            else:
                waiter.lines.append(line)
