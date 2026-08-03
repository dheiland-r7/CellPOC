"""Cinterion PLS83-W non-transparent multi-profile modem driver.

The Cinterion driver intentionally does not use AT^SIST transparent mode.
The UART remains in AT command mode while Internet service profiles 0..8 are
multiplexed with AT^SISS/AT^SISO/AT^SISW/AT^SISR/AT^SISC.

This design targets embedded/IoT research where one spare AT serial channel is
used to reach multiple services through the cellular module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import queue
import threading
import time

from .config import (
    ACK_TIMEOUT,
    COMMAND_TIMEOUT,
    CONNECTION_PROFILE,
    MAX_PARALLEL_OPENS,
    OPEN_TIMEOUT,
    PROFILE_IDS,
    TCP_READ_CHUNK,
    TCP_WRITE_CHUNK,
    UDP_MAX_PAYLOAD,
)
from core.profile_pool import ProfilePool
from modems.base import (
    CellularModemDriver,
    DriverInfo,
    ModemCapabilities,
    ModemIdentity,
    TestedModule,
)


DRIVER_INFO = DriverInfo(
    driver_id="cinterion",
    display_name="Cinterion AT Socket Driver",
    driver_version="1.0.0",
    manufacturer_patterns=(r"\bcinterion\b",),
    model_patterns=(),
    tested_modules=(
        TestedModule(
            model="PLS83-W",
            firmware="REVISION 01.202",
            status="hardware validated; non-transparent multi-profile TCP + UDP",
        ),
        TestedModule(
           model="EXS82-W",
           firmware="REVISION 01.200",
           status="hardware validated; non-transparent multi-profile TCP + UDP",
        ),
    ),
    features=(
        "TCP",
        "UDP",
        "IPv4",
        "non-transparent Internet services",
        "9 service profiles (0-8)",
    ),
)


@dataclass
class _PendingSend:
    profile_id: int
    requested: bytes
    grant_event: threading.Event = field(default_factory=threading.Event)
    done_event: threading.Event = field(default_factory=threading.Event)
    confirmed: int = 0
    ok: bool = False
    error: str | None = None


class CinterionConnection:
    """One non-transparent Cinterion Internet service profile."""

    def __init__(self, modem, profile_id: int, protocol: str, host: str, port: int):
        self.modem = modem
        self.sock_id = profile_id  # vendor-neutral CatSocks connection identifier
        self.profile_id = profile_id
        self.protocol = protocol
        self.remote_host = host
        self.remote_port = port
        self.recv_q: queue.Queue[bytes | None] = queue.Queue()
        self.ready_event = threading.Event()
        self.closed = False
        self.close_lock = threading.Lock()
        self.read_lock = threading.Lock()
        self.read_scheduled = False
        self.udp_rx = bytearray()

    def send(self, data: bytes) -> None:
        if self.closed:
            raise IOError(f"[PROFILE {self.profile_id}] connection is closed")
        if not data:
            return
        if self.protocol == "UDP":
            self.modem._send_udp_datagram(self, data)
        else:
            self.modem._send_profile_data(self, data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        return self.recv_q.get(timeout=timeout)

    def close(self) -> None:
        with self.close_lock:
            if self.closed:
                return
            self.closed = True
        self.modem._close_connection(self)


class CinterionDriver(CellularModemDriver):
    """PLS83-W non-transparent Internet Service driver."""

    def __init__(self, transport, identity: ModemIdentity | None = None):
        self.transport = transport
        self.identity = identity
        self.profile_pool = ProfilePool(PROFILE_IDS)
        self._conns: dict[int, CinterionConnection] = {}
        self._conn_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._pending_send: _PendingSend | None = None
        self._open_sem = threading.Semaphore(MAX_PARALLEL_OPENS)
        self._shutdown = False

        self.transport.set_line_handler(self._handle_line)

        # URC mode is the key to multiplexing profiles efficiently on one UART.
        # Keep this best-effort during construction; a failed command will be
        # surfaced during the first profile open as well.
        try:
            self._send_at('AT^SCFG="Tcp/WithURCs","on"', timeout=COMMAND_TIMEOUT)
        except Exception as exc:
            logging.warning("[CINTERION] could not enable Internet service URCs: %s", exc)

        logging.info(
            "Cinterion PLS83-W non-transparent driver loaded; profiles=%s",
            list(PROFILE_IDS),
        )

    @property
    def capabilities(self) -> ModemCapabilities:
        return ModemCapabilities(
            max_sockets=len(PROFILE_IDS),
            max_tcp_chunk=TCP_WRITE_CHUNK,
            max_udp_payload=UDP_MAX_PAYLOAD,
            supports_tcp=True,
            supports_udp=True,
            supports_ipv6=False,
            max_active_connections=len(PROFILE_IDS),
            max_parallel_opens=MAX_PARALLEL_OPENS,
        )

    def _send_at(self, cmd: str, timeout: float = COMMAND_TIMEOUT):
        return self.transport.execute(cmd, timeout=timeout)

    def _register(self, conn: CinterionConnection) -> None:
        with self._conn_lock:
            self._conns[conn.profile_id] = conn

    def _unregister(self, profile_id: int, expected=None):
        with self._conn_lock:
            current = self._conns.get(profile_id)
            if expected is None or current is expected:
                return self._conns.pop(profile_id, None)
            return None

    def _get(self, profile_id: int):
        with self._conn_lock:
            return self._conns.get(profile_id)

    def _service_up(self, profile_id: int) -> bool:
        result = self._send_at(f"AT^SISI={profile_id}", timeout=min(COMMAND_TIMEOUT, 5))
        a = f"^SISI: {profile_id},4,"
        b = f"^SISI:{profile_id},4,"
        return any(a in line or b in line for line in result.lines)

    def _wait_for_open(self, conn: CinterionConnection) -> bool:
        deadline = time.monotonic() + OPEN_TIMEOUT
        while time.monotonic() < deadline:
            if conn.ready_event.wait(timeout=0.20):
                return True
            try:
                if self._service_up(conn.profile_id):
                    return True
            except Exception:
                pass
        return False

    def _acquire_open_slot(self) -> bool:
        started = time.monotonic()
        acquired = self._open_sem.acquire(timeout=OPEN_TIMEOUT)
        waited = time.monotonic() - started
        if waited >= 0.01:
            logging.debug("[CINTERION] waited %.3fs for open slot", waited)
        return acquired

    def _open_profile_connection(self, host: str, port: int, protocol: str):
        protocol = protocol.upper()
        if self._shutdown:
            return None

        started = time.monotonic()
        acquired = self._open_sem.acquire(timeout=OPEN_TIMEOUT)
        waited = time.monotonic() - started
        if waited >= 0.01:
            logging.debug(
                "[CINTERION] waited %.3fs for %s open slot",
                waited,
                protocol,
            )
        if not acquired:
            logging.info(
                "[CINTERION] open concurrency gate timed out for %s %s:%s",
                protocol,
                host,
                port,
            )
            return None

        try:
            try:
                profile = self.profile_pool.acquire()
            except RuntimeError:
                logging.info(
                    "[CINTERION] no free service profiles for %s %s:%s",
                    protocol,
                    host,
                    port,
                )
                return None

            conn = CinterionConnection(self, profile, protocol, host, port)
            self._register(conn)

            try:
                self._send_at(
                    f"AT^SICA=1,{CONNECTION_PROFILE}",
                    timeout=20.0,
                )
                self._send_at(f'AT^SISS={profile},"srvType","Socket"')
                self._send_at(
                    f'AT^SISS={profile},"conId","{CONNECTION_PROFILE}"'
                )
                scheme = "sockudp" if protocol == "UDP" else "socktcp"
                self._send_at(
                    f'AT^SISS={profile},"address","{scheme}://{host}:{port}"'
                )
                self._send_at(f"AT^SISO={profile}", timeout=15.0)

                if not self._wait_for_open(conn):
                    raise TimeoutError(
                        f"{protocol} profile {profile} did not become ready"
                    )

                logging.info(
                    "[PROFILE %s] %s open %s:%s (non-transparent)",
                    profile,
                    protocol,
                    host,
                    port,
                )
                return conn
            except Exception as exc:
                logging.warning(
                    "[PROFILE %s] %s open failed %s:%s: %s",
                    profile,
                    protocol,
                    host,
                    port,
                    exc,
                )
                self._unregister(profile, conn)
                try:
                    self._send_at(f"AT^SISC={profile}", timeout=5.0)
                except Exception:
                    pass
                self.profile_pool.release(profile)
                return None
        finally:
            self._open_sem.release()

    def open_tcp_connection(self, host: str, port: int):
        return self._open_profile_connection(host, port, "TCP")

    def open_udp_connection(self, host: str, port: int):
        return self._open_profile_connection(host, port, "UDP")


    def _send_udp_datagram(self, conn: CinterionConnection, data: bytes) -> None:
        """Send exactly one UDP datagram with one SISW transaction.

        UDP packet boundaries matter. The PLS83 supports up to 1500 bytes per
        SISW operation, and CatSocks currently caps UDP payloads at 1024 bytes.
        If the modem grants less than the whole datagram, fail rather than split
        one SOCKS datagram into multiple UDP datagrams.
        """
        if len(data) > UDP_MAX_PAYLOAD:
            raise ValueError(
                f"[PROFILE {conn.profile_id}] UDP payload {len(data)} exceeds max {UDP_MAX_PAYLOAD}"
            )
        sent = self._send_write_cycle(conn, data)
        if sent != len(data):
            raise IOError(
                f"[PROFILE {conn.profile_id}] UDP grant {sent}/{len(data)} would split datagram"
            )

    def _send_profile_data(self, conn: CinterionConnection, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            request = data[offset:offset + TCP_WRITE_CHUNK]
            sent = self._send_write_cycle(conn, request)
            if sent <= 0:
                raise IOError(f"[PROFILE {conn.profile_id}] modem accepted zero bytes")
            offset += sent

    def _send_write_cycle(self, conn: CinterionConnection, data: bytes) -> int:
        """Run one SISW request -> grant -> raw payload -> OK transaction."""
        pending = _PendingSend(conn.profile_id, data)

        with self._send_lock:
            with self.transport.exclusive_transaction():
                self._pending_send = pending
                try:
                    self.transport.write_raw(
                        f"AT^SISW={conn.profile_id},{len(data)}\r".encode()
                    )

                    if not pending.grant_event.wait(ACK_TIMEOUT):
                        raise TimeoutError(
                            f"[PROFILE {conn.profile_id}] no ^SISW grant"
                        )
                    if pending.error:
                        raise IOError(pending.error)
                    if pending.confirmed <= 0:
                        return 0

                    payload = data[:pending.confirmed]
                    self.transport.write_raw(payload)

                    if not pending.done_event.wait(ACK_TIMEOUT):
                        raise TimeoutError(
                            f"[PROFILE {conn.profile_id}] no OK after SISW payload"
                        )
                    if not pending.ok:
                        raise IOError(
                            pending.error or f"[PROFILE {conn.profile_id}] SISW failed"
                        )
                    return pending.confirmed
                finally:
                    self._pending_send = None

    def _schedule_read(self, conn: CinterionConnection) -> None:
        with conn.read_lock:
            if conn.read_scheduled or conn.closed:
                return
            conn.read_scheduled = True

        threading.Thread(
            target=self._read_worker,
            args=(conn,),
            daemon=True,
            name=f"cinterion-read-{conn.profile_id}",
        ).start()

    def _read_worker(self, conn: CinterionConnection) -> None:
        try:
            while not conn.closed:
                # The line handler consumes the exact raw payload immediately
                # after the ^SISR response and queues it on conn.recv_q.
                result = self._send_at(
                    f"AT^SISR={conn.profile_id},{TCP_READ_CHUNK}",
                    timeout=COMMAND_TIMEOUT,
                )
                confirmed = None
                for line in result.lines:
                    parsed = self._parse_sisr(line)
                    if parsed and parsed[0] == conn.profile_id:
                        confirmed = parsed[1]
                        break
                if confirmed is None or confirmed <= 0:
                    break

                if conn.protocol == "UDP":
                    # The line handler reassembles a UDP datagram using the
                    # optional remainUdpPacketLength field. Keep draining while
                    # data is available; a 0 response ends this worker.
                    continue

                if confirmed < TCP_READ_CHUNK:
                    break
        except Exception as exc:
            if not conn.closed:
                logging.debug("[PROFILE %s] SISR read worker stopped: %s", conn.profile_id, exc)
        finally:
            with conn.read_lock:
                conn.read_scheduled = False

    @staticmethod
    def _parse_sisr(line: str):
        if not line.startswith("^SISR:"):
            return None
        try:
            fields = [x.strip() for x in line.split(":", 1)[1].split(",")]
            return int(fields[0]), int(fields[1]), fields[2:]
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _parse_sisw(line: str):
        if not line.startswith("^SISW:"):
            return None
        try:
            fields = [x.strip() for x in line.split(":", 1)[1].split(",")]
            return int(fields[0]), [int(x) for x in fields[1:]]
        except (ValueError, IndexError):
            return None

    def _handle_line(self, line: str) -> None:
        if not line:
            return

        sisw = self._parse_sisw(line)
        if sisw:
            profile, values = sisw
            pending = self._pending_send

            # Two-field ^SISW:<profile>,1 is the URC "ready for user data".
            if len(values) == 1:
                if values[0] == 1:
                    conn = self._get(profile)
                    if conn:
                        conn.ready_event.set()
                return

            # Three-field response to AT^SISW: confirmed length, unacknowledged.
            if len(values) >= 2 and pending and pending.profile_id == profile:
                pending.confirmed = values[0]
                pending.grant_event.set()
                return

        sisr = self._parse_sisr(line)
        if sisr:
            profile, value, _extra = sisr
            conn = self._get(profile)
            if not conn:
                return

            # If this profile has an AT^SISR command in flight, the response's
            # confirmed byte count is followed immediately by exactly that many
            # raw bytes before the final OK. Consume them in the reader thread.
            # A response of -2 means end-of-data.
            if value == -2:
                conn.recv_q.put(None)
                return

            # ^SISR:<profile>,1 as an unsolicited line means data is available.
            # We cannot distinguish a 1-byte command response by syntax alone,
            # so only treat it as a URC when no reader is currently scheduled.
            with conn.read_lock:
                read_scheduled = conn.read_scheduled

            if not read_scheduled:
                if value == 1:
                    self._schedule_read(conn)
                elif value == 2:
                    conn.recv_q.put(None)
                return

            if value > 0:
                payload = self.transport.read_exact(value)

                if conn.protocol == "UDP":
                    conn.udp_rx.extend(payload)

                    # For UDP, the optional third field is the number of bytes
                    # remaining in the current datagram. It is omitted when the
                    # complete datagram fits in this read. Queue only complete
                    # datagrams so SOCKS packet boundaries are preserved.
                    remaining = 0
                    if _extra:
                        try:
                            remaining = int(_extra[0])
                        except ValueError:
                            remaining = 0

                    if remaining == 0:
                        conn.recv_q.put(bytes(conn.udp_rx))
                        conn.udp_rx.clear()
                else:
                    conn.recv_q.put(payload)
            return

        # Internet service event/error. Cause 0 carries service events. Keep the
        # Conservative handling: if the profile reports an event after
        # being open, wake the SOCKS pump with EOF and let close() reclaim it.
        if line.startswith("^SIS:"):
            try:
                fields = [x.strip() for x in line.split(":", 1)[1].split(",")]
                profile = int(fields[0])
                cause = int(fields[1])
            except (ValueError, IndexError):
                return
            conn = self._get(profile)
            if conn and cause == 0 and any("closed" in x.lower() for x in fields[2:]):
                conn.recv_q.put(None)
            return

        pending = self._pending_send
        if pending:
            if line == "OK" and pending.grant_event.is_set():
                pending.ok = True
                pending.done_event.set()
                return
            if line == "ERROR" or line.startswith("+CME ERROR"):
                pending.error = line
                pending.grant_event.set()
                pending.done_event.set()
                return

    def _close_connection(self, conn: CinterionConnection) -> None:
        profile = conn.profile_id
        self._unregister(profile, conn)
        try:
            self._send_at(f"AT^SISC={profile}", timeout=5.0)
        except Exception as exc:
            logging.debug("[PROFILE %s] SISC close error: %s", profile, exc)
        finally:
            self.profile_pool.release(profile)
            logging.info("[PROFILE %s] %s closed %s:%s", profile, conn.protocol, conn.remote_host, conn.remote_port)

    def shutdown(self) -> None:
        self._shutdown = True
        with self._conn_lock:
            conns = list(self._conns.values())
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass
        self.transport.set_line_handler(None)
