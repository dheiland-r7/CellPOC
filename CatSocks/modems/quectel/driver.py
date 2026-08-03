"""Quectel modem driver for CatSocks.

Everything vendor-specific for Quectel AT socket operation lives here.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from .config import (
    ACK_TIMEOUT,
    COMMAND_TIMEOUT,
    MAX_PARALLEL_OPENS,
    OPEN_TIMEOUT,
    PROMPT_TIMEOUT,
    SOCKET_IDS,
    TCP_WRITE_CHUNK,
    UDP_MAX_PAYLOAD,
)
from core.sid_pool import SidPool
from modems.base import CellularModemDriver, DriverInfo, ModemCapabilities, ModemIdentity, TestedModule

DRIVER_INFO = DriverInfo(
    driver_id="quectel",
    display_name="Quectel AT Socket Driver",
    driver_version="0.1.0",
    manufacturer_patterns=(r"\bquectel\b",),
    model_patterns=(),
    tested_modules=(
        TestedModule(
            model="EG91-NAXD",
            firmware="Not recorded",
            status="hardware validated",
        ),
        TestedModule(
            model="BG95M3",
            firmware="BG95M3LAR02A02",
            status="hardware validated",
        ),
        TestedModule(
            model="BG96",
            firmware="BG96MAR04A03M1G",
            status="hardware validated",
        ),
    ),
    features=("TCP", "UDP", "IPv4", "buffered receive"),
)

class QuectelConnection:
    """
    Represents one opened modem socket (sid). Provides:
      • send(data): serialized QISEND with prompt/ack handling
      • recv(timeout): gets payload queued via +QIURC:"recv"
      • close(): issues QICLOSE and returns SID to the pool
    """
    def __init__(self, modem, sock_id, protocol="TCP", remote_host=None, remote_port=None):
        self.modem      = modem
        self.sock_id    = sock_id
        self.protocol   = protocol
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.closed     = False
        self.close_lock = threading.Lock()
        self.recv_q     = queue.Queue()     # payloads from URC "recv"
        self.prompt_evt = threading.Event() # set by reader upon seeing '>'
        self.ack_evt    = threading.Event() # set by reader upon SEND OK/FAIL
        self.ack_ok     = False             # latched result after ack_evt
        self.open_evt   = threading.Event() # signaled when +QIOPEN arrives
        self.open_ok    = False             # +QIOPEN err==0
        self.open_err   = None              # raw error code

    def send(self, data: bytes):
        """
        Write data to the modem socket:
          1) AT+QISEND=<sid>,<len>
          2) Wait for '>' prompt
          3) Write payload
          4) Write 0x1A (CTRL-Z)
          5) Wait for SEND OK/FAIL
        The modem’s reader thread coordinates prompt/ack based on the
        currently pending_send_sid.
        """
        with self.modem.send_lock:  # serialize QISEND across the entire modem
            # Reserve the transport command channel for the complete prompt /
            # payload / acknowledgement exchange so QIOPEN or QICLOSE cannot
            # interleave with the raw payload.
            with self.modem.transport.exclusive_transaction():
                at = f"AT+QISEND={self.sock_id},{len(data)}\r".encode()
                self.modem.pending_send_sid = self.sock_id
                self.modem.transport.write_raw(at)

                if not self.prompt_evt.wait(PROMPT_TIMEOUT):
                    self.modem.pending_send_sid = None
                    raise TimeoutError(f"[SID {self.sock_id}] No '>' prompt for QISEND")
                self.prompt_evt.clear()

                self.modem.transport.write_raw(data + b'\x1A')

                if not self.ack_evt.wait(ACK_TIMEOUT):
                    self.modem.pending_send_sid = None
                    raise TimeoutError(f"[SID {self.sock_id}] No SEND OK/ERROR")
                self.ack_evt.clear()
                self.modem.pending_send_sid = None

                if not self.ack_ok:
                    raise IOError(f"[SID {self.sock_id}] SEND ERROR")

    def recv(self, timeout=None):
        """
        Blocks for URC-fed payload parts. Returns:
          • bytes(...) when data arrives
          • None when the modem signals the socket closed
        """
        return self.recv_q.get(timeout=timeout)

    def close(self):
        """Close once; quarantine the SID if close state is uncertain."""
        with self.close_lock:
            if self.closed:
                return
            self.closed = True

        self.modem.unregister_connection(self.sock_id, self)
        close_started = time.monotonic()
        try:
            self.modem._send_at(
                f"AT+QICLOSE={self.sock_id},10",
                timeout=COMMAND_TIMEOUT,
            )
            logging.debug(
                "[SID %s] QICLOSE completed in %.3fs",
                self.sock_id, time.monotonic() - close_started,
            )
        except TimeoutError as exc:
            self.modem.quarantine_id(
                self.sock_id,
                f"uncertain QICLOSE state: {exc}",
            )
            self.modem._schedule_sid_recovery(
                self.sock_id,
                "QICLOSE command timeout",
            )
            return
        except Exception as exc:
            # An explicit ERROR generally means no close operation is pending.
            # Preserve the prior behavior while recording its duration.
            logging.debug(
                "[SID %s] QICLOSE error after %.3fs: %s",
                self.sock_id, time.monotonic() - close_started, exc,
            )
        self.modem.release_id(self.sock_id)



class QuectelDriver(CellularModemDriver):
    """
    Encapsulates serial I/O and URC parsing for a Quectel Cell Module.

    Responsibilities:
      • Own the serial port and a single reader thread.
      • Provide an AT command API with request/response matching (CmdWaiter).
      • Manage a pool of socket IDs and live QuectelConnection objects.
      • Gate concurrent AT+QIOPEN via semaphore (admission control).
      • Observe PDP activation state to short-circuit futile opens.
    """
    def __init__(self, transport, identity: ModemIdentity | None = None):
        # Socket ID pool & live connections
        self.sid_pool = SidPool(SOCKET_IDS)
        self._conns    = {}                        # sid -> QuectelConnection
        self.sid_lock  = threading.Lock()
        self.conn_lock = threading.Lock()

        # QISEND coordination
        self.send_lock        = threading.Lock()  # serialize all QISENDs
        self.pending_send_sid = None              # which SID is mid-QISEND

        # Admission control for opens
        self.open_sem = threading.Semaphore(MAX_PARALLEL_OPENS)

        # Network state
        self.pdp_active = True

        self.transport = transport
        self.identity = identity
        self.transport.set_line_handler(self._handle_line)
        self.transport.set_prompt_handler(self._handle_prompt)

    # --- SID pool management -------------------------------------------------
    def allocate_id(self):
        """Allocate the next SID using the extracted FIFO pool."""
        return self.sid_pool.acquire()

    def release_id(self, sid):
        """Return a confirmed-closed SID to the FIFO queue exactly once."""
        self.sid_pool.release(sid)

    def quarantine_id(self, sid, reason):
        """Remove a SID from service while modem state is uncertain."""
        self.sid_pool.quarantine(sid, reason)

    def recover_id(self, sid):
        """Return a recovered SID to the FIFO queue."""
        self.sid_pool.recover(sid)

    def register_connection(self, conn):
        with self.conn_lock:
            self._conns[conn.sock_id] = conn

    def unregister_connection(self, sid, expected=None):
        with self.conn_lock:
            current = self._conns.get(sid)
            if expected is None or current is expected:
                return self._conns.pop(sid, None)
            return None

    def get_connection(self, sid):
        with self.conn_lock:
            return self._conns.get(sid)

    # --- Open a TCP or UDP connection through the modem ----------------------
    def open_connection(self, host, port, protocol="TCP"):
        """Open a connected Quectel TCP or UDP socket in direct-push mode."""
        protocol = protocol.upper()
        if protocol not in ("TCP", "UDP"):
            raise ValueError(f"Unsupported modem protocol: {protocol}")

        if not self.pdp_active:
            logging.info(f"[OPEN] PDP inactive; refusing {protocol} {host}:{port}")
            return None

        try:
            sid = self.allocate_id()
        except RuntimeError:
            logging.debug(f"[OPEN] No socket IDs available for {protocol} {host}:{port}")
            return None

        sem_wait_started = time.monotonic()
        got_sem = self.open_sem.acquire(timeout=OPEN_TIMEOUT)
        sem_wait = time.monotonic() - sem_wait_started
        if sem_wait >= 0.01:
            logging.debug("[SID %s] waited %.3fs for open slot", sid, sem_wait)
        if not got_sem:
            logging.debug("[OPEN] Open concurrency gate timed out")
            self.release_id(sid)
            return None

        conn = QuectelConnection(self, sid, protocol, host, port)
        self.register_connection(conn)

        try:
            cmd = f'AT+QIOPEN=1,{sid},"{protocol}","{host}",{port},0,1'
            try:
                self._send_at(cmd, timeout=COMMAND_TIMEOUT)
            except TimeoutError as exc:
                self.unregister_connection(sid, conn)
                self.quarantine_id(sid, f"uncertain QIOPEN command state: {exc}")
                self._schedule_sid_recovery(sid, "QIOPEN command timeout")
                return None

            result_wait_started = time.monotonic()
            if not conn.open_evt.wait(OPEN_TIMEOUT):
                elapsed = time.monotonic() - result_wait_started
                logging.warning(
                    "[SID %s] %s QIOPEN result timeout after %.3fs",
                    sid, protocol, elapsed,
                )
                self.unregister_connection(sid, conn)
                self.quarantine_id(sid, "missing asynchronous QIOPEN result")
                self._schedule_sid_recovery(sid, "QIOPEN result timeout")
                return None

            if not conn.open_ok:
                logging.info(f"[SID {sid}] {protocol} QIOPEN failed err={conn.open_err}")
                self.unregister_connection(sid, conn)
                self.release_id(sid)
                return None

            logging.info(
                "[SID %s] %s open %s:%s; async result %.3fs",
                sid, protocol, host, port, time.monotonic() - result_wait_started,
            )
            return conn
        except Exception:
            self.unregister_connection(sid, conn)
            if not self.sid_pool.is_quarantined(sid):
                self.release_id(sid)
            raise
        finally:
            self.open_sem.release()

    def open_tcp_connection(self, host, port):
        return self.open_connection(host, port, protocol="TCP")

    def open_udp_connection(self, host, port):
        return self.open_connection(host, port, protocol="UDP")

    # --- Vendor-neutral transport delegation --------------------------------
    def _send_at(self, cmd: str, timeout=5):
        """Delegate one serialized AT transaction to the transport layer."""
        return self.transport.execute(cmd, timeout=timeout).text

    def _handle_prompt(self):
        """Route a transport-detected QISEND prompt to the active SID."""
        sid = self.pending_send_sid
        if sid is None:
            return
        conn = self.get_connection(sid)
        if conn and not conn.prompt_evt.is_set():
            conn.prompt_evt.set()

    # --- Quectel URC dispatcher ---------------------------------------------
    def _handle_line(self, line: str):
        """
        Routes a completed CRLF-terminated line to:
          • pending command waiter (if any), and
          • specific URC handlers.
        Note: order matters; responses to current AT command are appended
        onto the head waiter’s buffer until OK/ERROR completes it.
        """
        logging.debug(f"URC: {line}")

        # RDY is informational only; generic AT probing establishes readiness.
        if line == "RDY":
            logging.debug("[MODEM] informational RDY received")
            return

        # Network dropped PDP
        if line.startswith('+QIURC: "pdpdeact"'):
            self.pdp_active = False
            logging.warning("[NET] PDP deactivated by network")
            return

        # Connection result: +QIOPEN: <sid>,<err>
        if line.startswith("+QIOPEN:"):
            try:
                rest = line.split(":", 1)[1].strip()
                p = [x.strip() for x in rest.split(",")]
                sid = int(p[0]); err = int(p[1])
                conn = self.get_connection(sid)
                if conn:
                    conn.open_ok  = (err == 0)
                    conn.open_err = err
                    conn.open_evt.set()
                elif self.sid_pool.is_quarantined(sid):
                    logging.warning("[SID %s] late QIOPEN result err=%s", sid, err)
                    if err == 0:
                        self._schedule_sid_recovery(sid, "late successful QIOPEN")
                    else:
                        self.recover_id(sid)
            except Exception:
                pass
            return

        # Data received: +QIURC:"recv",<sid>,<len>  then <len> raw bytes
        if line.startswith('+QIURC: "recv"'):
            try:
                parts = line.split(",")
                sid = int(parts[1]); length = int(parts[2])
            except Exception:
                return

            payload = b""
            while len(payload) < length:
                payload += self.transport.read_exact(length - len(payload))

            conn = self.get_connection(sid)
            if conn:
                conn.recv_q.put(payload)
            return

        # Remote closed: +QIURC:"closed",<sid>
        if line.startswith('+QIURC: "closed"'):
            try:
                sid = int(line.split(",")[1])
            except Exception:
                return
            conn = self.get_connection(sid)
            if conn:
                # None marks closure to the pump loop
                conn.recv_q.put(None)
            return

        # QISEND terminal results (map to current sending SID)
        if line in ("SEND OK", "SEND FAIL", "ERROR"):
            sid = self.pending_send_sid
            if sid is not None:
                conn = self.get_connection(sid)
                if conn:
                    conn.ack_ok = (line == "SEND OK")
                    conn.ack_evt.set()
            return

    def _schedule_sid_recovery(self, sid: int, reason: str):
        """Recover an uncertain SID outside reader/client execution paths."""
        logging.warning("[SID %s] scheduling recovery: %s", sid, reason)
        threading.Thread(
            target=self._recover_quarantined_sid,
            args=(sid,),
            daemon=True,
            name=f"sid-recovery-{sid}",
        ).start()

    def _recover_quarantined_sid(self, sid: int):
        if not self.sid_pool.is_quarantined(sid):
            return
        try:
            self._send_at(f"AT+QICLOSE={sid},10", timeout=COMMAND_TIMEOUT)
        except Exception as exc:
            logging.warning(
                "[SID %s] recovery close failed; remaining quarantined: %s",
                sid, exc,
            )
            return
        self.unregister_connection(sid)
        self.recover_id(sid)

    @property
    def capabilities(self):
        return ModemCapabilities(
            max_sockets=len(SOCKET_IDS),
            max_tcp_chunk=TCP_WRITE_CHUNK,
            max_udp_payload=UDP_MAX_PAYLOAD,
            supports_tcp=True,
            supports_udp=True,
            max_active_connections=len(SOCKET_IDS),
            max_parallel_opens=MAX_PARALLEL_OPENS,
        )

    def shutdown(self):
        """Release driver callbacks; the application owns the transport."""
        self.transport.set_line_handler(None)
        self.transport.set_prompt_handler(None)

