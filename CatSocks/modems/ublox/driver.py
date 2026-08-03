"""u-blox SARA-R4 command-mode TCP socket driver for CatSocks.

CatSocks V0.11.07 uses the u-blox internal TCP/IP stack in command mode:

* AT+UDNSRN resolves domain names to IPv4 addresses.
* AT+USOCR allocates a modem socket identifier.
* AT+USOCO connects a TCP socket.
* AT+USOWR writes binary-safe data in HEX mode.
* +UUSORD announces buffered TCP data.
* AT+USORD drains buffered data in HEX mode.
* +UUSOCL announces remote socket closure.
* AT+USOCL closes and releases a socket.

TCP and UDP are supported through the u-blox command-mode socket API.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import logging
import queue
import re
import threading
import time

from .config import (
    COMMAND_TIMEOUT,
    DNS_TIMEOUT,
    HEX_MODE,
    MAX_PARALLEL_OPENS,
    OPEN_TIMEOUT,
    SOCKET_IDS,
    SOCKET_WAIT_TIMEOUT,
    TCP_IDLE_TIMEOUT,
    TCP_READ_CHUNK,
    TCP_WRITE_CHUNK,
    UDP_MAX_PAYLOAD,
    UDP_READ_CHUNK,
)
from modems.base import (
    CellularModemDriver,
    DriverInfo,
    ModemCapabilities,
    ModemIdentity,
    TestedModule,
)



DRIVER_INFO = DriverInfo(
    driver_id="ublox",
    display_name="u-blox AT Socket Driver",
    driver_version="0.2.1",
    manufacturer_patterns=(r"\bu-blox\b", r"\bublox\b"),
    model_patterns=(),
    tested_modules=(
        TestedModule(
            model="SARA-R410M-02B",
            firmware="L0.0.00.00.05.08 [Apr 17 2019 19:34:02]",
            status="hardware validated; command-mode TCP socket path",
        ),
    ),
    features=(
        "TCP",
        "UDP",
        "IPv4",
        "modem DNS resolution",
        "binary-safe HEX-mode socket I/O",
        "7 socket identifiers (0-6)",
    ),
)


@dataclass
class _ReadState:
    scheduled: bool = False


class UBloxConnection:
    """One connected u-blox TCP socket."""

    def __init__(
        self,
        modem: "UBloxDriver",
        socket_id: int,
        host: str,
        port: int,
        protocol: str = "TCP",
        resolved_host: str | None = None,
    ):
        self.modem = modem
        self.sock_id = socket_id
        self.protocol = protocol
        self.remote_host = host
        self.remote_port = port
        self.resolved_host = resolved_host or host
        self.recv_q: queue.Queue[bytes | None] = queue.Queue()
        self.closed = False
        self.remote_closed = False
        self.close_pending = False
        self.released = False
        self.close_lock = threading.Lock()
        self.release_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.read_lock = threading.Lock()
        self.read_state = _ReadState()

    def send(self, data: bytes) -> None:
        if self.closed or self.remote_closed:
            raise IOError(f"[UBLOX {self.sock_id}] socket is closed")
        if not data:
            return
        if self.protocol == "UDP":
            self.modem._send_udp(self, data)
        else:
            self.modem._send_tcp(self, data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        return self.recv_q.get(timeout=timeout)

    def close(self) -> None:
        with self.close_lock:
            if self.closed:
                return
            self.closed = True
        self.modem._close_connection(self)


class UBloxDriver(CellularModemDriver):
    """u-blox SARA-R4 TCP driver using socket IDs returned by USOCR."""

    def __init__(self, transport, identity: ModemIdentity | None = None):
        self.transport = transport
        self.identity = identity
        self._connections: dict[int, UBloxConnection] = {}
        self._connection_lock = threading.Lock()
        self._capacity = threading.BoundedSemaphore(len(SOCKET_IDS))
        self._open_sem = threading.Semaphore(MAX_PARALLEL_OPENS)
        self._shutdown = False

        self.transport.set_line_handler(self._handle_line)

        # HEX mode makes USOWR/USORD binary-safe while keeping the UART in
        # ordinary AT command mode. It also avoids parsing arbitrary protocol
        # bytes from quoted ASCII responses.
        self._send_at("AT+UDCONF=1,1" if HEX_MODE else "AT+UDCONF=1,0", timeout=COMMAND_TIMEOUT)
        logging.info(
            "u-blox SARA-R4 TCP driver loaded; socket_ids=0..%s, hex_mode=on",
            len(SOCKET_IDS) - 1,
        )

    @property
    def capabilities(self) -> ModemCapabilities:
        return ModemCapabilities(
            max_sockets=len(SOCKET_IDS),
            max_tcp_chunk=TCP_WRITE_CHUNK,
            max_udp_payload=UDP_MAX_PAYLOAD,
            supports_tcp=True,
            supports_udp=True,
            supports_ipv6=False,
            max_active_connections=len(SOCKET_IDS),
            max_parallel_opens=MAX_PARALLEL_OPENS,
            tcp_idle_timeout=TCP_IDLE_TIMEOUT,
        )

    def _send_at(self, cmd: str, timeout: float = COMMAND_TIMEOUT):
        return self.transport.execute(cmd, timeout=timeout)

    def _register(self, conn: UBloxConnection) -> None:
        with self._connection_lock:
            if conn.sock_id in self._connections:
                raise RuntimeError(f"u-blox socket ID {conn.sock_id} is already active")
            self._connections[conn.sock_id] = conn

    def _unregister(self, socket_id: int, expected=None):
        with self._connection_lock:
            current = self._connections.get(socket_id)
            if expected is None or current is expected:
                return self._connections.pop(socket_id, None)
            return None

    def _get(self, socket_id: int):
        with self._connection_lock:
            return self._connections.get(socket_id)

    @staticmethod
    def _parse_socket_id(lines: tuple[str, ...]) -> int:
        for line in lines:
            match = re.search(r"\+USOCR:\s*(\d+)", line)
            if match:
                socket_id = int(match.group(1))
                if 0 <= socket_id < len(SOCKET_IDS):
                    return socket_id
                raise ValueError(f"unexpected u-blox socket ID {socket_id}")
        raise ValueError("AT+USOCR did not return a socket ID")

    @staticmethod
    def _is_ipv4(host: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
        except ValueError:
            return False

    def _resolve_ipv4(self, host: str) -> str:
        if self._is_ipv4(host):
            return host

        # IPv6 remains explicitly out of scope for this release.
        try:
            if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
                raise ValueError("u-blox IPv6 destinations are not supported")
        except ValueError as exc:
            if "IPv6 destinations" in str(exc):
                raise

        result = self._send_at(
            f'AT+UDNSRN=0,"{host}"',
            timeout=DNS_TIMEOUT,
        )
        for line in result.lines:
            for candidate in re.findall(r'"((?:\d{1,3}\.){3}\d{1,3})"', line):
                try:
                    ipaddress.IPv4Address(candidate)
                    logging.debug("[UBLOX] resolved %s to %s", host, candidate)
                    return candidate
                except ipaddress.AddressValueError:
                    continue
        raise IOError(f"u-blox DNS returned no IPv4 address for {host}")

    def open_tcp_connection(self, host: str, port: int):
        if self._shutdown:
            return None

        wait_started = time.monotonic()
        if not self._capacity.acquire(timeout=SOCKET_WAIT_TIMEOUT):
            logging.info(
                "[UBLOX] timed out after %.1fs waiting for socket capacity for TCP %s:%s",
                SOCKET_WAIT_TIMEOUT,
                host,
                port,
            )
            return None
        capacity_wait = time.monotonic() - wait_started
        if capacity_wait >= 0.01:
            logging.info(
                "[UBLOX] waited %.3fs for physical socket capacity for TCP %s:%s",
                capacity_wait,
                host,
                port,
            )

        open_acquired = False
        socket_id: int | None = None
        conn: UBloxConnection | None = None
        try:
            started = time.monotonic()
            open_acquired = self._open_sem.acquire(timeout=OPEN_TIMEOUT)
            waited = time.monotonic() - started
            if waited >= 0.01:
                logging.debug("[UBLOX] waited %.3fs for TCP open slot", waited)
            if not open_acquired:
                logging.info("[UBLOX] TCP open concurrency gate timed out")
                return None

            resolved = self._resolve_ipv4(host)
            create = self._send_at("AT+USOCR=6", timeout=COMMAND_TIMEOUT)
            socket_id = self._parse_socket_id(create.lines)
            conn = UBloxConnection(self, socket_id, host, port, "TCP", resolved)
            self._register(conn)

            self._send_at(
                f'AT+USOCO={socket_id},"{resolved}",{port}',
                timeout=max(OPEN_TIMEOUT, 30.0),
            )
            logging.info(
                "[UBLOX %s] TCP open %s:%s via %s",
                socket_id,
                host,
                port,
                resolved,
            )
            return conn
        except Exception as exc:
            logging.warning("[UBLOX] TCP open failed %s:%s: %s", host, port, exc)
            if conn is not None:
                with conn.close_lock:
                    conn.closed = True
                self._request_close(conn)
            else:
                # No modem socket was allocated, so capacity can be returned
                # immediately. Once USOCR returns an ID, release must wait for
                # the matching UUSOCL confirmation.
                self._capacity.release()
            return None
        finally:
            if open_acquired:
                self._open_sem.release()

    def open_udp_connection(self, host: str, port: int):
        if self._shutdown:
            return None

        wait_started = time.monotonic()
        if not self._capacity.acquire(timeout=SOCKET_WAIT_TIMEOUT):
            logging.info(
                "[UBLOX] timed out after %.1fs waiting for socket capacity for UDP %s:%s",
                SOCKET_WAIT_TIMEOUT,
                host,
                port,
            )
            return None
        capacity_wait = time.monotonic() - wait_started
        if capacity_wait >= 0.01:
            logging.info(
                "[UBLOX] waited %.3fs for physical socket capacity for UDP %s:%s",
                capacity_wait,
                host,
                port,
            )

        open_acquired = False
        conn: UBloxConnection | None = None
        try:
            open_acquired = self._open_sem.acquire(timeout=OPEN_TIMEOUT)
            if not open_acquired:
                logging.info("[UBLOX] UDP open concurrency gate timed out")
                self._capacity.release()
                return None

            resolved = self._resolve_ipv4(host)
            create = self._send_at("AT+USOCR=17", timeout=COMMAND_TIMEOUT)
            socket_id = self._parse_socket_id(create.lines)
            conn = UBloxConnection(
                self,
                socket_id,
                host,
                port,
                "UDP",
                resolved,
            )
            self._register(conn)
            logging.info(
                "[UBLOX %s] UDP open %s:%s via %s",
                socket_id,
                host,
                port,
                resolved,
            )
            return conn
        except Exception as exc:
            logging.warning("[UBLOX] UDP open failed %s:%s: %s", host, port, exc)
            if conn is not None:
                with conn.close_lock:
                    conn.closed = True
                self._request_close(conn)
            else:
                self._capacity.release()
            return None
        finally:
            if open_acquired:
                self._open_sem.release()

    @staticmethod
    def _parse_written(lines: tuple[str, ...], socket_id: int) -> int:
        pattern = rf"\+USOWR:\s*{socket_id},(\d+)"
        for line in lines:
            match = re.search(pattern, line)
            if match:
                return int(match.group(1))
        raise IOError(f"AT+USOWR did not confirm socket {socket_id} write")

    @staticmethod
    def _parse_udp_written(lines: tuple[str, ...], socket_id: int) -> int:
        pattern = rf"\+USOST:\s*{socket_id},(\d+)"
        for line in lines:
            match = re.search(pattern, line)
            if match:
                return int(match.group(1))
        raise IOError(f"AT+USOST did not confirm socket {socket_id} write")

    def _send_udp(self, conn: UBloxConnection, data: bytes) -> None:
        if len(data) > UDP_MAX_PAYLOAD:
            raise ValueError(
                f"[UBLOX {conn.sock_id}] UDP datagram {len(data)} bytes exceeds "
                f"configured maximum {UDP_MAX_PAYLOAD}"
            )
        with conn.send_lock:
            encoded = data.hex().upper()
            result = self._send_at(
                f'AT+USOST={conn.sock_id},"{conn.resolved_host}",'
                f'{conn.remote_port},{len(data)},"{encoded}"',
                timeout=max(COMMAND_TIMEOUT, 30.0),
            )
            written = self._parse_udp_written(result.lines, conn.sock_id)
            if written != len(data):
                raise IOError(
                    f"[UBLOX {conn.sock_id}] UDP write confirmation "
                    f"{written}/{len(data)}"
                )

    @staticmethod
    def _parse_udp_read(
        lines: tuple[str, ...],
        socket_id: int,
    ) -> tuple[str, int, bytes] | None:
        pattern = (
            rf'^\+USORF:\s*{socket_id},"([^"]+)",(\d+),(\d+),'
            rf'"([0-9A-Fa-f]*)"$'
        )
        for line in lines:
            match = re.search(pattern, line)
            if not match:
                continue
            host = match.group(1)
            port = int(match.group(2))
            length = int(match.group(3))
            encoded = match.group(4)
            if len(encoded) != length * 2:
                raise IOError(
                    f"[UBLOX {socket_id}] malformed UDP HEX read "
                    f"({len(encoded)} chars for {length} bytes)"
                )
            return host, port, bytes.fromhex(encoded)
        return None

    def _schedule_udp_read(self, conn: UBloxConnection) -> None:
        with conn.read_lock:
            if conn.closed or conn.read_state.scheduled:
                return
            conn.read_state.scheduled = True
        threading.Thread(
            target=self._read_udp,
            args=(conn,),
            daemon=True,
            name=f"ublox-udp-read-{conn.sock_id}",
        ).start()

    def _read_udp(self, conn: UBloxConnection) -> None:
        try:
            while not conn.closed:
                result = self._send_at(
                    f"AT+USORF={conn.sock_id},{UDP_READ_CHUNK}",
                    timeout=COMMAND_TIMEOUT,
                )
                parsed = self._parse_udp_read(result.lines, conn.sock_id)
                if parsed is None:
                    break
                source_host, source_port, payload = parsed
                if not payload:
                    break
                if (
                    source_host != conn.resolved_host
                    or source_port != conn.remote_port
                ):
                    logging.debug(
                        "[UBLOX %s] UDP datagram source %s:%s differs from "
                        "configured flow %s:%s",
                        conn.sock_id,
                        source_host,
                        source_port,
                        conn.resolved_host,
                        conn.remote_port,
                    )
                conn.recv_q.put(payload)
                logging.debug(
                    "[UBLOX %s] UDP RX %s bytes from %s:%s",
                    conn.sock_id,
                    len(payload),
                    source_host,
                    source_port,
                )
                # UUSORF is edge-triggered. Read one complete datagram for each
                # notification; another queued datagram will generate another
                # notification or be detected by a subsequent read thread.
                break
        except Exception as exc:
            if not conn.closed:
                logging.warning(
                    "[UBLOX %s] UDP receive failed: %s",
                    conn.sock_id,
                    exc,
                )
        finally:
            with conn.read_lock:
                conn.read_state.scheduled = False

    def _send_tcp(self, conn: UBloxConnection, data: bytes) -> None:
        with conn.send_lock:
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + TCP_WRITE_CHUNK]
                encoded = chunk.hex().upper()
                result = self._send_at(
                    f'AT+USOWR={conn.sock_id},{len(chunk)},"{encoded}"',
                    timeout=max(COMMAND_TIMEOUT, 30.0),
                )
                written = self._parse_written(result.lines, conn.sock_id)
                if written <= 0 or written > len(chunk):
                    raise IOError(
                        f"[UBLOX {conn.sock_id}] invalid write confirmation {written}"
                    )
                offset += written

    @staticmethod
    def _parse_unread(lines: tuple[str, ...], socket_id: int) -> int:
        pattern = rf"\+USORD:\s*{socket_id},(\d+)\s*$"
        for line in lines:
            match = re.search(pattern, line)
            if match:
                return int(match.group(1))
            # Firmware may report an empty quoted response when no bytes exist.
            if re.search(rf"\+USORD:\s*{socket_id},\s*\"\"", line):
                return 0
        return 0

    @staticmethod
    def _parse_read(lines: tuple[str, ...], socket_id: int) -> bytes:
        pattern = rf'^\+USORD:\s*{socket_id},(\d+),\"([0-9A-Fa-f]*)\"$'
        for line in lines:
            match = re.search(pattern, line)
            if not match:
                continue
            length = int(match.group(1))
            encoded = match.group(2)
            if len(encoded) != length * 2:
                raise IOError(
                    f"[UBLOX {socket_id}] malformed HEX read "
                    f"({len(encoded)} chars for {length} bytes)"
                )
            return bytes.fromhex(encoded)
        return b""

    def _schedule_read(self, conn: UBloxConnection) -> None:
        with conn.read_lock:
            if conn.closed or conn.read_state.scheduled:
                return
            conn.read_state.scheduled = True

        threading.Thread(
            target=self._drain_tcp,
            args=(conn,),
            daemon=True,
            name=f"ublox-read-{conn.sock_id}",
        ).start()

    def _drain_tcp(self, conn: UBloxConnection) -> None:
        drain_ok = False
        try:
            while not conn.closed:
                query = self._send_at(f"AT+USORD={conn.sock_id},0", timeout=COMMAND_TIMEOUT)
                unread = self._parse_unread(query.lines, conn.sock_id)
                if unread <= 0:
                    drain_ok = True
                    break

                # SARA-R410M-02B firmware L0.0.00.00.05.08 rejects 1024-byte
                # USORD reads with "Operation not allowed". Hardware testing
                # confirms 512-byte reads are accepted and can be repeated until
                # the modem's buffered count reaches zero.
                to_read = min(unread, TCP_READ_CHUNK)
                result = self._send_at(
                    f"AT+USORD={conn.sock_id},{to_read}",
                    timeout=COMMAND_TIMEOUT,
                )
                payload = self._parse_read(result.lines, conn.sock_id)
                if not payload:
                    drain_ok = True
                    break
                conn.recv_q.put(payload)
                logging.debug("[UBLOX %s] RX %s bytes", conn.sock_id, len(payload))
        except Exception as exc:
            if not conn.closed:
                logging.warning("[UBLOX %s] receive failed: %s", conn.sock_id, exc)
        finally:
            with conn.read_lock:
                conn.read_state.scheduled = False

            # Only perform the edge-trigger recovery query after a successful
            # drain. Re-querying and rescheduling after a read failure caused a
            # tight retry loop that flooded the AT channel while unread data
            # remained buffered.
            if drain_ok and not conn.closed and not conn.remote_closed:
                try:
                    query = self._send_at(f"AT+USORD={conn.sock_id},0", timeout=COMMAND_TIMEOUT)
                    if self._parse_unread(query.lines, conn.sock_id) > 0:
                        self._schedule_read(conn)
                except Exception:
                    pass
            elif conn.remote_closed and not conn.closed:
                conn.recv_q.put(None)

    def _handle_line(self, line: str) -> None:
        match = re.match(r"\+UUSORD:\s*(\d+),(\d+)", line)
        if match:
            conn = self._get(int(match.group(1)))
            if conn is not None and not conn.closed:
                self._schedule_read(conn)
            return

        match = re.match(r"\+UUSORF:\s*(\d+),(\d+)", line)
        if match:
            conn = self._get(int(match.group(1)))
            if (
                conn is not None
                and conn.protocol == "UDP"
                and not conn.closed
            ):
                self._schedule_udp_read(conn)
            return

        match = re.match(r"\+UUSOCL:\s*(\d+)", line)
        if match:
            socket_id = int(match.group(1))
            conn = self._get(socket_id)
            if conn is not None:
                conn.remote_closed = True

                # UUSOCL is the authoritative modem-side release event. The
                # preceding OK from USOCL=<id>,1 only acknowledges that an
                # asynchronous close was requested.
                self._finalize_release(conn)

                # For a remotely initiated close while the SOCKS client is
                # still active, deliver EOF. If local close already occurred,
                # the client handler has already exited.
                if not conn.closed:
                    conn.recv_q.put(None)
            else:
                logging.debug(
                    "[UBLOX %s] late or duplicate socket release confirmation",
                    socket_id,
                )
            return

    def _request_close(self, conn: UBloxConnection) -> None:
        with conn.close_lock:
            if conn.released or conn.close_pending:
                return
            if conn.remote_closed:
                self._finalize_release(conn)
                return
            conn.close_pending = True

        if conn.protocol == "UDP":
            try:
                # SARA-R410M firmware L0.0.00.00.05.08 rejects the
                # asynchronous UDP form AT+USOCL=<id>,1 with
                # "Operation not allowed". Use synchronous close for UDP and
                # release capacity only after the command returns OK.
                self._send_at(f"AT+USOCL={conn.sock_id}", timeout=30.0)
                self._finalize_release(conn)
            except Exception as exc:
                # Keep the connection registered and capacity reserved because
                # modem-side state is uncertain after a failed close.
                logging.warning(
                    "[UBLOX %s] UDP close failed; socket remains reserved: %s",
                    conn.sock_id,
                    exc,
                )
            return

        try:
            self._send_at(f"AT+USOCL={conn.sock_id},1", timeout=5.0)
            logging.info(
                "[UBLOX %s] TCP close requested %s:%s; awaiting UUSOCL",
                conn.sock_id,
                conn.remote_host,
                conn.remote_port,
            )
        except Exception as exc:
            # Preserve capacity and registration because modem-side state is
            # uncertain. A later UUSOCL can still complete the release.
            logging.warning(
                "[UBLOX %s] TCP close request failed; awaiting modem release: %s",
                conn.sock_id,
                exc,
            )

    def _finalize_release(self, conn: UBloxConnection) -> None:
        with conn.release_lock:
            if conn.released:
                return
            removed = self._unregister(conn.sock_id, conn)
            if removed is None:
                return
            conn.released = True
            conn.close_pending = False
            self._capacity.release()

        logging.info(
            "[UBLOX %s] %s socket released %s:%s",
            conn.sock_id,
            conn.protocol,
            conn.remote_host,
            conn.remote_port,
        )

    def _close_connection(self, conn: UBloxConnection) -> None:
        self._request_close(conn)

    def shutdown(self) -> None:
        self._shutdown = True
        with self._connection_lock:
            connections = list(self._connections.values())
        for conn in connections:
            try:
                conn.close()
            except Exception:
                pass
        self.transport.set_line_handler(None)
