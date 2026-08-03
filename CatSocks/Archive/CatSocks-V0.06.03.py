#!/usr/bin/env python3
####################################################
#                                                  #
# _____       _   _____            _         _____ # 
#/  __ \     | | /  ___|          | |       |  ___|# 
#| /  \/ __ _| |_\ `--.  ___   ___| | _____ |___ \ # 
#| |    / _` | __|`--. \/ _ \ / __| |/ / __|    \ \# 
#| \__/\ (_| | |_/\__/ / (_) | (__|   <\__ \/\__/ /# 
# \____/\__,_|\__\____/ \___/ \___|_|\_\___/\____/ #                                             
#                                                  #
####################################################
#     Proof of concept code for establishing       #
#     a socks5 proxy that will route comms.        #
#     thru a cellular module in an IoT device      #
#     via UART connection using AT commands        #
#                                                  #
#       tested on Quectel Cellular modules.        #
#                                                  #
#              Deral Heiland 2025                  #
#   Code was created with assistance from AI       #
#               Version 0.06.03		           #
####################################################
# Filename: Catsocks_V0.06.03.py
# Functioning multisocket version
#
# Quectel SOCKS5 proxy with admission control & robust URC parsing
# ----------------------------------------------------------------
# This program exposes a local SOCKS5 proxy (default 0.0.0.0:1080) that
# forwards TCP connections through a Quectel Cell Module using AT sockets
# (AT+QIOPEN/QISEND/QICLOSE). It is designed for environments where only a
# very small number of concurrent modem sockets are available and the radio
# network may penalize bursty connection attempts.
#
# Key design points:
#   • Single dedicated serial reader thread parses *all* URCs and responses.
#   • Strict serialization of QISEND per socket ID (avoid interleaving).
#   • Admission control via semaphore: caps concurrent AT+QIOPEN attempts to
#     prevent socket-table exhaustion and RAN irritation.
#   • Fast-fail behavior: if no socket IDs are available or gate is saturated,
#     we immediately return a SOCKS5 failure to the client (don’t backlog).
#   • Defensive cleanup: on +QIOPEN errors/timeouts, release socket IDs
#     promptly to avoid “No socket IDs available” deadlocks.
#   • PDP deactivation awareness: when we see +QIURC:"pdpdeact", refuse new
#     opens (don’t try to re-activate; host system is responsible).
#
# Assumptions (per your environment):
#   • PDP context and SSL (if used by the application later) are configured by
#     the host via USB; this proxy does not issue QICSGP/QIACT/QSSLCFG/etc.
#   • We focus on TCP; UDP is out of scope.
#   • Default serial port is /dev/ttyUSB0.
#
# Notes on Quectel URCs used here:
#   • +QIOPEN: <sid>,<err>
#       err==0  -> opened successfully
#       err!=0  -> failure (e.g., 566, 563,…), we close/release SID
#   • +QIURC: "recv",<sid>,<len> followed by <len> raw bytes
#   • +QIURC: "closed",<sid>
#   • "SEND OK"/"SEND FAIL" after QISEND ‘>’ prompt and payload termination (^Z)
#   • +QIURC: "pdpdeact",<context_id> => network deactivated PDP
#
# ---------------------------------------------------------------------------

import serial
import socket
import struct
import threading
import time
import select
import queue
import logging

# ==== Configuration ==========================================================
SERIAL_PORT        = "/dev/ttyUSB0"   # Default Quectel Cell Module serial TTY
BAUD_RATE          = 115200           # Safe baseline; adjust as needed
DEBUG              = True             # Verbose logs with URC echoing
MAX_CHUNK_SIZE     = 1024             # Split client writes into <= this size for QISEND
PROMPT_TIMEOUT     = 5                # Wait for '>' after QISEND
ACK_TIMEOUT        = 8                # Wait for SEND OK/FAIL
OPEN_TIMEOUT       = 12               # Wait for +QIOPEN URC
CMD_TIMEOUT        = 6                # Wait for OK/ERROR after sending an AT line
MAX_SOCKETS        = 10                # Size of SID pool we’ll use (0..MAX_SOCKETS-1)
MAX_PARALLEL_OPENS = 3                # Admission control (cap in-flight QIOPENs)
LISTEN_ADDR        = ("0.0.0.0", 1080)# SOCKS5 bind address

# SOCKS5 canned replies (IPv4 0.0.0.0:0 bound address in response)
SOCKS_GENERAL_FAIL = b"\x05\x01\x00\x01" + b"\x00"*6
SOCKS_CMD_NOT_SUP  = b"\x05\x07\x00\x01" + b"\x00"*6
SOCKS_ADDR_NOT_SUP = b"\x05\x08\x00\x01" + b"\x00"*6
SOCKS_SUCCEEDED    = b"\x05\x00\x00\x01" + b"\x00"*6

# ==== Logging ================================================================
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)


# ==== Internal helpers / data structures ====================================

class CmdWaiter:
    """
    Tracks the lifecycle of a single AT command until it reaches a terminal
    response (OK/SEND OK/SEND FAIL/ERROR). The serial reader thread appends
    lines to `buf` and finally sets `ok` + signals `evt`.
    """
    def __init__(self, cmd: str):
        self.cmd = cmd
        self.evt = threading.Event()
        self.ok  = False
        self.buf = []


class QuectelConnection:
    """
    Represents one opened modem socket (sid). Provides:
      • send(data): serialized QISEND with prompt/ack handling
      • recv(timeout): gets payload queued via +QIURC:"recv"
      • close(): issues QICLOSE and returns SID to the pool
    """
    def __init__(self, modem, sock_id):
        self.modem      = modem
        self.sock_id    = sock_id
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
            at = f"AT+QISEND={self.sock_id},{len(data)}\r".encode()
            with self.modem.lock:
                # Mark which SID expects the prompt/ack lines
                self.modem.pending_send_sid = self.sock_id
                self.modem.ser.write(at)

            # Wait for '>' prompt (modem ready for payload)
            if not self.prompt_evt.wait(PROMPT_TIMEOUT):
                self.modem.pending_send_sid = None
                raise TimeoutError(f"[SID {self.sock_id}] No '>' prompt for QISEND")
            self.prompt_evt.clear()

            # Write payload and ^Z terminator; the ACK will follow
            with self.modem.lock:
                self.modem.ser.write(data)
                self.modem.ser.write(b'\x1A')

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
        """
        Close the modem socket gracefully and return its SID to the pool.
        Errors during QICLOSE are logged but not fatal.
        """
        try:
            self.modem._send_at(f"AT+QICLOSE={self.sock_id},10", timeout=CMD_TIMEOUT)
        except Exception as e:
            logging.debug(f"[SID {self.sock_id}] QICLOSE error: {e}")
        self.modem.release_id(self.sock_id)


class QuectelModem:
    """
    Encapsulates serial I/O and URC parsing for a Quectel Cell Module.

    Responsibilities:
      • Own the serial port and a single reader thread.
      • Provide an AT command API with request/response matching (CmdWaiter).
      • Manage a pool of socket IDs and live QuectelConnection objects.
      • Gate concurrent AT+QIOPEN via semaphore (admission control).
      • Observe PDP activation state to short-circuit futile opens.
    """
    def __init__(self, port, baud):
        # Serial port + fundamental locks
        self.ser  = serial.Serial(port, baud, timeout=None, write_timeout=0)
        self.lock = threading.Lock()      # serialize writes/reads as needed

        # Socket ID pool & live connections
        self._free_ids = list(range(MAX_SOCKETS))  # simple FIFO pool
        self._conns    = {}                        # sid -> QuectelConnection

        # Reader coordination
        self.reader_thread = None
        self.reader_stop   = False
        self.line_buf      = b""                  # accumulates until CRLF
        self.cmd_lock      = threading.Lock()
        self.pending_cmds  = []                   # FIFO of CmdWaiter
        self.rdy_evt       = threading.Event()

        # QISEND coordination
        self.send_lock        = threading.Lock()  # serialize all QISENDs
        self.pending_send_sid = None              # which SID is mid-QISEND

        # Admission control for opens
        self.open_sem = threading.Semaphore(MAX_PARALLEL_OPENS)

        # Network state
        self.pdp_active = True

        # Start reader thread first so we can catch early 'RDY'
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()

        logging.info("Waiting for RDY…")
        self._wait_for_line_exact("RDY")
        logging.info("RDY received.")

        # Quiet the echo
        self._send_at("ATE0", timeout=CMD_TIMEOUT)

    # --- SID pool management -------------------------------------------------
    def allocate_id(self):
        """
        Pulls the next free SID from the pool.
        Raises RuntimeError if none are available (fast-fail path).
        """
        if not self._free_ids:
            raise RuntimeError("No socket IDs available")
        return self._free_ids.pop(0)

    def release_id(self, sid):
        """
        Returns a SID to the free pool (idempotent-ish: avoids duplicates).
        """
        if sid not in self._free_ids:
            self._free_ids.append(sid)

    # --- Open a TCP connection through the modem -----------------------------
    def open_connection(self, host, port):
        """
        Attempts AT+QIOPEN flow for host:port. Enforces:
          • PDP must be active.
          • SID must be available now (else fast-fail).
          • Number of in-flight opens limited by open_sem.
        On success: returns a QuectelConnection.
        On failure/timeouts: cleans up SID and returns None.
        """
        # If PDP is down, don't even try (let caller return SOCKS failure)
        if not self.pdp_active:
            logging.info(f"[OPEN] PDP inactive; refusing {host}:{port}")
            return None

        # Try to obtain a SID immediately; otherwise, fast-fail.
        try:
            sid = self.allocate_id()
        except RuntimeError:
            logging.debug("[OPEN] No socket IDs available")
            return None

        # Admission control: don’t overwhelm the module with opens.
        got_sem = self.open_sem.acquire(timeout=OPEN_TIMEOUT)
        if not got_sem:
            logging.debug("[OPEN] Open concurrency gate timed out")
            self.release_id(sid)
            return None

        conn = QuectelConnection(self, sid)
        self._conns[sid] = conn

        try:
            # Issue the QIOPEN command and wait for immediate "OK"/"ERROR"
            cmd = f'AT+QIOPEN=1,{sid},"TCP","{host}",{port},0,1'
            self._send_at(cmd, timeout=CMD_TIMEOUT)

            # Now wait for the asynchronous +QIOPEN: sid,err URC
            if not conn.open_evt.wait(OPEN_TIMEOUT):
                logging.info(f"[SID {sid}] QIOPEN timeout")
                self._conns.pop(sid, None)
                self.release_id(sid)
                return None

            if not conn.open_ok:
                logging.info(f"[SID {sid}] QIOPEN failed err={conn.open_err}")
                self._conns.pop(sid, None)
                self.release_id(sid)
                return None

            return conn
        finally:
            # Always release the admission gate
            self.open_sem.release()

    # --- Low-level AT send with waiter matching ------------------------------
    def _send_at(self, cmd: str, timeout=5):
        """
        Sends an AT line and blocks for its terminal response (OK/ERROR).
        Intermediate lines are collected on the CmdWaiter and logged at DEBUG.
        Raises TimeoutError or IOError on failure.
        """
        waiter = CmdWaiter(cmd)
        with self.cmd_lock:
            self.pending_cmds.append(waiter)

        logging.debug(f"→ AT {cmd}")
        with self.lock:
            self.ser.write((cmd + "\r").encode())

        if not waiter.evt.wait(timeout):
            with self.cmd_lock:
                if waiter in self.pending_cmds:
                    self.pending_cmds.remove(waiter)
            raise TimeoutError(f"AT cmd timeout: {cmd}")

        for l in waiter.buf:
            logging.debug(f"← {l}")
        if not waiter.ok:
            raise IOError(f"AT cmd error: {cmd}")
        return "\n".join(waiter.buf)

    # --- Reader loop & URC dispatcher ---------------------------------------
    def _reader_loop(self):
        """
        Continuous byte-wise reader that:
          • Detects the single-character '>' prompt for QISEND.
          • Collects CRLF-terminated lines and routes them to:
              - pending CmdWaiter (for command completion), and/or
              - URC handlers (+QIOPEN/QIURC etc).
          • Pulls raw payload bytes after +QIURC:"recv",sid,len.
        This thread is the *only* place that reads from the serial port.
        """
        try:
            while not self.reader_stop:
                b = self.ser.read(1)
                if not b:
                    continue

                # QISEND prompt is a single '>' (no CRLF)
                if b == b'>':
                    sid = self.pending_send_sid
                    if sid is not None:
                        conn = self._conns.get(sid)
                        if conn and not conn.prompt_evt.is_set():
                            conn.prompt_evt.set()
                    continue

                # Accumulate line until CRLF
                self.line_buf += b
                if self.line_buf.endswith(b"\r\n"):
                    line = self.line_buf.decode(errors='ignore').strip()
                    self.line_buf = b""
                    self._handle_line(line)

        except serial.SerialException as e:
            logging.error(f"[READER] SerialException: {e}")
        except Exception as e:
            logging.error(f"[READER] Unexpected: {e}")

    def _handle_line(self, line: str):
        """
        Routes a completed CRLF-terminated line to:
          • pending command waiter (if any), and
          • specific URC handlers.
        Note: order matters; responses to current AT command are appended
        onto the head waiter’s buffer until OK/ERROR completes it.
        """
        logging.debug(f"URC: {line}")

        # Boot ready (used once at init)
        if line == "RDY":
            self.rdy_evt.set()
            return

        # First pass: if a command is pending, feed its waiter’s buffer.
        # When an "OK"/"ERROR"/"SEND FAIL" appears, we complete the waiter.
        with self.cmd_lock:
            if self.pending_cmds:
                waiter = self.pending_cmds[0]
                if line == "OK":
                    waiter.buf.append("OK")
                    waiter.ok = True
                    waiter.evt.set()
                    self.pending_cmds.pop(0)
                elif line.startswith("ERROR") or line == "SEND FAIL":
                    waiter.buf.append(line)
                    waiter.ok = False
                    waiter.evt.set()
                    self.pending_cmds.pop(0)
                else:
                    waiter.buf.append(line)

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
                conn = self._conns.get(sid)
                if conn:
                    conn.open_ok  = (err == 0)
                    conn.open_err = err
                    conn.open_evt.set()
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
                chunk = self.ser.read(length - len(payload))
                if not chunk:
                    continue
                payload += chunk

            conn = self._conns.get(sid)
            if conn:
                conn.recv_q.put(payload)
            return

        # Remote closed: +QIURC:"closed",<sid>
        if line.startswith('+QIURC: "closed"'):
            try:
                sid = int(line.split(",")[1])
            except Exception:
                return
            conn = self._conns.get(sid)
            if conn:
                # None marks closure to the pump loop
                conn.recv_q.put(None)
            return

        # QISEND terminal results (map to current sending SID)
        if line in ("SEND OK", "SEND FAIL", "ERROR"):
            sid = self.pending_send_sid
            if sid is not None:
                conn = self._conns.get(sid)
                if conn:
                    conn.ack_ok = (line == "SEND OK")
                    conn.ack_evt.set()
            return

    def _wait_for_line_exact(self, text: str, timeout: float = 30.0):
        """
        Wait for a specific bootstrap marker. Currently only used for 'RDY'.
        """
        if text == "RDY":
            self.rdy_evt.wait(timeout)


# ==== SOCKS5 handling ========================================================

def _socks_read_exact(sock, n):
    """
    Read exactly n bytes from a blocking TCP socket; raise if peer closes early.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("SOCKS peer closed")
        buf += chunk
    return buf


def handle_client(client_sock, modem: QuectelModem):
    """
    Serve a single SOCKS5 CONNECT session:
      1) Negotiate no-auth method.
      2) Parse the CONNECT request (IPv4/IPv6/FQDN).
      3) Attempt to open a modem TCP connection with admission control.
      4) If opened, start bi-directional relay until client closes or modem
         reports closure; otherwise immediately return a failure reply.
    Resources (modem SID and client socket) are cleaned up in all paths.
    """
    conn = None
    try:
        # ---- SOCKS5 handshake: greeting ----
        head = _socks_read_exact(client_sock, 2)
        ver, nmethods = struct.unpack("!BB", head)
        if ver != 5:
            return
        _ = _socks_read_exact(client_sock, nmethods)  # discard methods
        client_sock.sendall(b"\x05\x00")              # choose: no authentication

        # ---- SOCKS5 request: CONNECT only ----
        hdr = _socks_read_exact(client_sock, 4)
        _, cmd, _, atyp = struct.unpack("!BBBB", hdr)
        if cmd != 1:  # only CONNECT is supported
            client_sock.sendall(SOCKS_CMD_NOT_SUP); return

        if atyp == 1:  # IPv4
            host = socket.inet_ntoa(_socks_read_exact(client_sock, 4))
        elif atyp == 3:  # FQDN
            alen = _socks_read_exact(client_sock, 1)[0]
            host = _socks_read_exact(client_sock, alen).decode()
        elif atyp == 4:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, _socks_read_exact(client_sock, 16))
        else:
            client_sock.sendall(SOCKS_ADDR_NOT_SUP); return

        port = struct.unpack("!H", _socks_read_exact(client_sock, 2))[0]
        logging.info(f"CONNECT {host}:{port}")

        # ---- Attempt to open through the modem (may fast-fail) ----
        conn = modem.open_connection(host, port)
        if not conn:
            client_sock.sendall(SOCKS_GENERAL_FAIL)
            return

        # Report success to the SOCKS client (we don’t provide real bind addr)
        client_sock.sendall(SOCKS_SUCCEEDED)
        client_sock.setblocking(False)

        # ---- Bidirectional relay loop ----
        while True:
            # Client -> Modem (non-blocking)
            r, _, _ = select.select([client_sock], [], [], 0.02)
            if client_sock in r:
                data = client_sock.recv(4096)
                if not data:
                    break  # client closed
                # Split into smaller QISEND writes so the modem stays happy
                off = 0
                while off < len(data):
                    chunk = data[off:off+MAX_CHUNK_SIZE]; off += len(chunk)
                    conn.send(chunk)

            # Modem -> Client (drain queued URC payload parts)
            try:
                payload = conn.recv(timeout=0.02)
            except queue.Empty:
                payload = b""
            if payload is None:
                break  # modem closed
            if payload:
                try:
                    client_sock.sendall(payload)
                except Exception:
                    break

    except Exception as e:
        logging.debug(f"[SOCKS] client handler error: {e}")
    finally:
        # Cleanup modem socket and client regardless of exit path
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


# ==== Main entry =============================================================

def main():
    """
    Program entry:
      • Initialize the modem and quiet echo.
      • Start a TCP server socket for SOCKS5.
      • Spawn a thread per client to serve concurrently.
    """
    modem = QuectelModem(SERIAL_PORT, BAUD_RATE)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN_ADDR)
    srv.listen(64)

    logging.info(
        f"P6-3 proxy listening on {LISTEN_ADDR[0]}:{LISTEN_ADDR[1]} "
        f"(max_sockets={MAX_SOCKETS}, parallel_opens={MAX_PARALLEL_OPENS})"
    )

    while True:
        client, addr = srv.accept()
        logging.info(f"Client from {addr}")
        threading.Thread(target=handle_client, args=(client, modem), daemon=True).start()


if __name__ == "__main__":
    main()

