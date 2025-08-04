#!/usr/bin/env python3
# Filename: CatSocks.py

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
####################################################

import serial
import socket
import struct
import threading
import time
import select
import logging

# --- Configuration ---
SERIAL_PORT     = "/dev/ttyUSB0"
BAUD_RATE       = 115200
DEBUG           = True
MAX_CHUNK_SIZE  = 1024   # bytes per QISEND chunk
PROMPT_TIMEOUT  = 5      # seconds to wait for '>' prompt
ACK_TIMEOUT     = 5      # seconds to wait for SEND OK

# --- Logging setup ---
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)

def main():
    modem = QuectelModem(SERIAL_PORT, BAUD_RATE)
    srv   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", 1080))
    srv.listen(5)
    logging.info("CatSocks proxy listening on 0.0.0.0:1080")

    while True:
        client, addr = srv.accept()
        logging.info(f"Client connected from {addr}")
        threading.Thread(
            target=handle_client,
            args=(client, modem),
            daemon=True
        ).start()

class QuectelModem:
    def __init__(self, port, baud, cid=1, sock_id=0):
        self.ser     = serial.Serial(port, baud, timeout=None, write_timeout=0)
        self.cid     = cid
        self.sock_id = sock_id

        # Wait for module to boot
        self._wait_for_rdy()
        # Disable echo
        self._send_at("ATE0")

    def _wait_for_rdy(self):
        logging.info("Waiting for RDY…")
        while True:
            line = self.ser.readline().decode(errors='ignore').strip()
            if line == "RDY":
                logging.info("RDY received.")
                return

    def _send_at(self, cmd, timeout=2):
        """Send AT command and wait for OK/ERROR."""
        logging.debug(f"→ AT {cmd}")
        self.ser.reset_input_buffer()
        self.ser.write((cmd + "\r").encode())
        deadline = time.time() + timeout
        resp = ""
        while time.time() < deadline:
            part = self.ser.read(self.ser.in_waiting or 1).decode(errors='ignore')
            if part:
                resp += part
                if "OK" in resp or "ERROR" in resp:
                    break
        # Log only the AT response lines
        for l in resp.splitlines():
            logging.debug(f"← {l}")
        return resp

    def open_tcp_direct_push(self, host, port):
        """Open a TCP socket in direct‑push mode."""
        cmd = f'AT+QIOPEN={self.cid},{self.sock_id},"TCP","{host}",{port},0,1'
        self._send_at(cmd)
        deadline = time.time() + 10
        buffer = ""
        while time.time() < deadline:
            if self.ser.in_waiting:
                buffer += self.ser.read(self.ser.in_waiting).decode(errors='ignore')
                for line in buffer.splitlines():
                    logging.debug(f"← {line}")
                    if f"+QIOPEN: {self.sock_id},0" in line or line == "CONNECT":
                        logging.info("Socket opened.")
                        return True
                    if f"+QIOPEN: {self.sock_id}," in line:
                        logging.error("Socket open failed.")
                        return False
            time.sleep(0.1)
        logging.error("Timeout waiting for socket open.")
        return False

    def _wait_for_prompt(self):
        """Block until we see the single-byte '>' prompt."""
        deadline = time.time() + PROMPT_TIMEOUT
        while time.time() < deadline:
            if self.ser.read(1) == b'>':
                return True
        return False

    def send_raw(self, data):
        """
        Send a binary chunk via QISEND:
         1) issue QISEND
         2) wait for '>' prompt
         3) write payload + Ctrl‑Z
         4) read and drop exactly one response line (SEND OK or ERROR)
        """
        # 1) issue QISEND
        at = f"AT+QISEND={self.sock_id},{len(data)}\r"
        self.ser.write(at.encode())

        # 2) wait for '>' prompt
        if not self._wait_for_prompt():
            raise TimeoutError("No '>' prompt")

        # 3) write data
        self.ser.write(data)
        self.ser.write(b'\x1A')

        # 4) consume one response line
        deadline = time.time() + ACK_TIMEOUT
        line = b""
        while time.time() < deadline:
            ch = self.ser.read(1)
            if not ch:
                continue
            line += ch
            if line.endswith(b"\r\n"):
                # drop it silently
                return
        raise TimeoutError("Timeout waiting for QISEND response")

    def close_tcp(self):
        self._send_at(f"AT+QICLOSE={self.sock_id},10")

def handle_client(client_sock, modem):
    try:
        # --- SOCKS5 handshake ---
        ver, nmethods = struct.unpack("!BB", client_sock.recv(2))
        client_sock.recv(nmethods)
        client_sock.sendall(b"\x05\x00")

        # --- CONNECT request ---
        hdr = client_sock.recv(4)
        _, cmd, _, atyp = struct.unpack("!BBBB", hdr)
        if cmd != 1:
            return
        if atyp == 1:      # IPv4
            addr = socket.inet_ntoa(client_sock.recv(4))
        elif atyp == 3:    # Domain
            alen = client_sock.recv(1)[0]
            addr = client_sock.recv(alen).decode()
        else:
            return
        port = struct.unpack("!H", client_sock.recv(2))[0]
        logging.info(f"CONNECT {addr}:{port}")

        # --- Open TCP socket ---
        if not modem.open_tcp_direct_push(addr, port):
            client_sock.sendall(b"\x05\x01\x00\x01" + b"\x00"*6)
            return
        client_sock.sendall(b"\x05\x00\x00\x01" + b"\x00"*6)

        # --- Relay loop ---
        client_fd  = client_sock.fileno()
        serial_fd  = modem.ser.fileno()
        client_sock.setblocking(False)

        while True:
            rlist, _, _ = select.select([client_fd, serial_fd], [], [])

            # a) Client → Modem
            if client_fd in rlist:
                data = client_sock.recv(4096)
                if not data:
                    break
                # send in MAX_CHUNK_SIZE slices
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset+MAX_CHUNK_SIZE]
                    offset += len(chunk)
                    logging.info(f"Client→Modem: {len(chunk)} bytes")
                    modem.send_raw(chunk)

            # b) Modem → Client
            if serial_fd in rlist:
                # read URC header line
                line = modem.ser.readline().decode(errors='ignore').strip()
                if line.startswith('+QIURC') and 'recv' in line:
                    # parse length and read exactly that many bytes
                    length = int(line.split(',')[-1])
                    payload = b''
                    while len(payload) < length:
                        payload += modem.ser.read(length - len(payload))
                    logging.info(f"Modem→Client: {len(payload)} bytes")
                    client_sock.sendall(payload)
                elif 'closed' in line:
                    logging.info("Remote closed")
                    break

        modem.close_tcp()

    finally:
        client_sock.close()

if __name__ == "__main__":
    main()

