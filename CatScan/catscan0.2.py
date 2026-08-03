#!/usr/bin/env python3

############################################
#                                          #
#   __|    \ __ __| __|                    #
#  (      _ \   | \__ \   _|   _` |    \   #
# \___| _/  _\ _| ____/ \__| \__,_| _| _|  #
#                                          #
############################################
# Tool for injecting AT socket commands    #
# via serial communication to conduct port #
# scanning via an embedded Cellular module #
#                                          #
#      Tested on Quectel and Telit         #
#            Cellular modules              #
#                                          #
#     Deral (Percent_x) Heiland - Rapid7   #
#                 ---                      #
#            Carlota Bindner               #
#                                          #
#          Copywrite 2025, 2026            #
#          CatSocks Version 0.02           #
#                                          #
############################################

import serial
import time
import argparse
import sys
import re
import ipaddress
import struct

VERBOSE = False


def verbose_tx(data):
    """Print an outbound modem command or payload when verbose mode is on."""
    if VERBOSE:
        print(f"\033[90m[TX] {data}\033[0m")


def verbose_rx(data, label="RX"):
    """Print a modem response without its usually noisy CRLF framing."""
    if not VERBOSE:
        return
    if not data:
        print(f"\033[90m[{label}] <no response>\033[0m")
        return
    for line in data.replace("\r", "").rstrip("\n").split("\n"):
        safe = "".join(c if " " <= c <= "~" else "." for c in line)
        print(f"\033[90m[{label}] {safe}\033[0m")


# Infrastructure-service probes, for making valid protocol request for UDP.

_TFTP = b"\x00\x01" + b"CatScan" + b"\x00" + b"octet" + b"\x00"

_RPC = struct.pack(">10I",
                   0x00000001,
                   0x00000000,
                   0x00000002,
                   0x000186a0,
                   0x00000002,
                   0x00000000,
                   0, 0,
                   0, 0)
_RIP = bytes.fromhex("01010000" "00000000"
                     "00000000" "00000000" "00000000" "00000010")

_SIP = (b"OPTIONS sip:nm SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP nm;branch=z9hG4bKcatscan\r\n"
        b"From: <sip:nm@nm>;tag=catscan\r\n"
        b"To: <sip:nm@nm>\r\n"
        b"Call-ID: catscan@nm\r\n"
        b"CSeq: 1 OPTIONS\r\n"
        b"Max-Forwards: 70\r\n"
        b"Content-Length: 0\r\n\r\n")

_IKE_ATTRS = bytes.fromhex(
    "80010005"
    "80020002"
    "80030001"
    "80040002"
    "800b0001"
    "000c000400007080")
_IKE_XFORM = bytes.fromhex("00000024" "01010000") + _IKE_ATTRS
_IKE_PROP = bytes.fromhex("0000002c" "01010001") + _IKE_XFORM
_IKE_SA = bytes.fromhex("00000038" "00000001" "00000001") + _IKE_PROP
_IKE = (bytes.fromhex("0011223344556677" "0000000000000000" "01100200" "00000000")
        + struct.pack(">I", 28 + len(_IKE_SA)) + _IKE_SA)

UDP_PAYLOADS = {
    # DNS
    53: bytes.fromhex(
        "0006010000010000000000000776657273696f6e0462696e640000100003"),
    # NTP
    123: b"\x1b" + b"\x00" * 47,
    # SNMPv1
    161: bytes.fromhex(
        "302902010004067075626c6963a01c020400000000020100020100"
        "300e300c06082b060102010101000500"),
    # NetBIOS: NBSTAT
    137: bytes.fromhex(
        "80f00010000100000000000020434b" + "41" * 30 + "0000210001"),
    # SSDP: UPnP M-SEARCH.
    1900: lambda ip, port: (
        b"M-SEARCH * HTTP/1.1\r\n"
        + f"HOST: {ip}:{port}\r\n".encode()
        + b'MAN: "ssdp:discover"\r\n'
        + b"ST: ssdp:all\r\n\r\n"),
    69: _TFTP,
    111: _RPC,
    500: _IKE,
    520: _RIP,
    5060: _SIP,
}
DEFAULT_UDP_PAYLOAD = b"\x00\x00\x00\x00"


# Module drivers: Quectel and Telit supported
class QuectelDriver:
    name = "quectel"
    conn = 0
    context = 1
    recv_token = '"recv"'

    def setup(self, ser):
        at_cmd(ser, "AT+CMEE=2", until="OK", timeout=5)

    def check_context(self, ser):
        state = at_cmd(ser, "AT+QIACT?", until="OK", timeout=5)
        if re.search(rf"\+QIACT:\s*{self.context},\s*1", state):
            return True, None
        return False, state.strip() or "no +QIACT: response"

    def open(self, ser, proto, ip, port, timeout=10):
        for _ in range(2):
            resp = at_cmd(
                ser,
                f'AT+QIOPEN={self.context},{self.conn},"{proto}","{ip}",{port},0,0',
                until="+QIOPEN:", timeout=timeout)
            m = re.search(r"\+QIOPEN:\s*\d+,(\d+)", resp)
            if m:
                return m.group(1) == "0", m.group(1)
            self.close(ser)
        return False, None

    def classify_tcp(self, established, code):
        if established:             # +QIOPEN result 0
            return "open"
        if code == "566":           # connection refused
            return "closed"
        return "unknown"            # other code / no response

    def send(self, ser, payload):
        ser.reset_input_buffer()
        cmd = f"AT+QISEND={self.conn},{len(payload)}"
        verbose_tx(cmd)
        ser.write((cmd + "\r\n").encode())
        prompt = read_until(ser, ">", timeout=5)
        verbose_rx(prompt)
        verbose_tx(f"DATA {len(payload)} bytes: {payload.hex()}")
        ser.write(payload)
        response = read_until(ser, "SEND OK", timeout=5)
        verbose_rx(response)
        return response

    def has_pending_data(self, ser):
        return False

    def read_data(self, ser):
        resp = at_cmd(ser, f"AT+QIRD={self.conn},1500",
                      until="\r\nOK\r\n", timeout=5)
        m = re.search(r"\+QIRD:\s*(\d+)\r?\n", resp)
        if not m:
            return None
        n = int(m.group(1))
        return resp[m.end():m.end() + n].encode("latin-1") if n else None

    def is_udp_closed(self, reply):
        return '"closed"' in reply or "ERROR" in reply

    def is_socket_open(self, ser):
        state = at_cmd(ser, "AT+QISTATE?", until="OK", timeout=3)
        return bool(re.search(rf'\+QISTATE:\s*{self.conn},', state))

    def close(self, ser, timeout=10):
        at_cmd(ser, f"AT+QICLOSE={self.conn},10", timeout=timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = at_cmd(ser, "AT+QISTATE?", until="OK", timeout=3)
            if not re.search(rf'\+QISTATE:\s*{self.conn},', state):
                return
            time.sleep(0.2)


class TelitDriver:
    name = "telit"
    conn = 1
    context = 1
    recv_token = "SRING"
    _PROTO = {"TCP": 0, "UDP": 1}
    _LPORT_BASE = 40000
    _LPORT_SPAN = 1000
    _CONN_TO = 5.0
    _LOCAL_ERRS = ("not supported", "not allowed", "invalid", "parameter",
                   "context", "activation", "busy", "already")

    def __init__(self):
        self._probe = 0
        self._elapsed = 0.0
        self._srecv = True

    def setup(self, ser):
        at_cmd(ser, "AT+CMEE=2", until="OK", timeout=5)
        at_cmd(ser, f"AT#SCFG={self.conn},{self.context},300,90,50,50",
               until="OK", timeout=5)
        at_cmd(ser, f"AT#SCFGEXT={self.conn},1,0,0,0,0", until="OK", timeout=5)

    def check_context(self, ser):
        state = at_cmd(ser, "AT#SGACT?", until="OK", timeout=5)
        m = re.search(rf"#SGACT:\s*{self.context},\s*(\d+)", state)
        if m and m.group(1) == "1":
            return True, None
        resp = at_cmd(ser, f"AT#SGACT={self.context},1", until="OK", timeout=30)
        if "OK" in resp and "ERROR" not in resp:
            return True, None
        return False, resp.strip() or "no response to AT#SGACT"

    def open(self, ser, proto, ip, port):
        txprot = self._PROTO[proto]
        if proto == "UDP":
            lport = self._LPORT_BASE + (self._probe % self._LPORT_SPAN)
            self._probe += 1
        else:
            lport = 0
        resp = ""
        for _ in range(2):
            started = time.time()
            resp = at_cmd(ser,
                          f'AT#SD={self.conn},{txprot},{port},"{ip}",0,{lport},1',
                          timeout=15)
            self._elapsed = time.time() - started
            if "OK" in resp:
                return True, "OK"
            if "ERROR" in resp:
                err = re.search(r"\+CM[ES] ERROR:\s*(.+)", resp)
                if err:
                    return False, "CME " + err.group(1).strip()
                cause = at_cmd(ser, f"AT#SLASTCLOSURE={self.conn}",
                               until="OK", timeout=5)
                m = re.search(r"#SLASTCLOSURE:\s*\d+,(\S+)", cause)
                return False, (m.group(1) if m else "ERR")
            self.close(ser)
        return False, None

    def classify_tcp(self, established, code):
        if established:
            return "open"
        if code is None:
            return "unknown"
        if code.startswith("CME"):
            reason = code[4:].lower()
            if any(k in reason for k in self._LOCAL_ERRS):
                return "unknown"
            return "closed" if self._elapsed < self._CONN_TO * 0.6 else "unknown"
        if code == "0":
            return "unknown"
        return "closed"

    def send(self, ser, payload):
        ser.reset_input_buffer()
        cmd = f"AT#SSENDEXT={self.conn},{len(payload)}"
        verbose_tx(cmd)
        ser.write((cmd + "\r\n").encode())
        prompt = read_until(ser, ">", timeout=5)
        verbose_rx(prompt)
        verbose_tx(f"DATA {len(payload)} bytes: {payload.hex()}")
        ser.write(payload)
        response = read_until(ser, "OK", timeout=5)
        verbose_rx(response)
        return response

    def has_pending_data(self, ser):
        state = at_cmd(ser, f"AT#SS={self.conn}", until="OK", timeout=3)
        return bool(re.search(rf"#SS:\s*{self.conn},\s*3", state))

    def read_data(self, ser):
        if not self._srecv:
            return None
        resp = at_cmd(ser, f"AT#SRECV={self.conn},1500",
                      until="\r\nOK\r\n", timeout=5)
        if "#SRECV:" not in resp:
            if "ERROR" in resp:
                self._srecv = False
            return None
        m = re.search(rf"#SRECV:\s*{self.conn},(\d+)\r?\n", resp)
        if not m:
            return None
        n = int(m.group(1))
        return resp[m.end():m.end() + n].encode("latin-1")

    def is_udp_closed(self, reply):
        return False

    def is_socket_open(self, ser):
        state = at_cmd(ser, f"AT#SS={self.conn}", until="OK", timeout=3)
        m = re.search(rf"#SS:\s*{self.conn},(\d+)", state)
        return bool(m) and m.group(1) != "0"

    def close(self, ser):
        at_cmd(ser, f"AT#SH={self.conn}", timeout=10)
        deadline = time.time() + 10
        while time.time() < deadline:
            state = at_cmd(ser, f"AT#SS={self.conn}", until="OK", timeout=3)
            m = re.search(rf"#SS:\s*{self.conn},(\d+)", state)
            if not m or m.group(1) == "0":
                return
            time.sleep(0.2)


DRIVERS = {"quectel": QuectelDriver, "telit": TelitDriver}


# Main: builds IP/port lists, opens serial, and dispatches TCP/UDP scans.
def main():
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose
    ips = build_ips(args)
    ports = build_ports(args)

    protos = ["TCP", "UDP"] if args.proto == "both" else [args.proto.upper()]

    driver = DRIVERS[args.module]()

    try:
        ser = serial.Serial(args.serialport, baudrate=args.baud, timeout=0.2)
    except Exception as e:
        print(f"Error opening serial port: {e}")
        sys.exit(1)

    driver.setup(ser)

    ok, detail = driver.check_context(ser)
    if not ok:
        print(f"\033[91mWARNING: {driver.name} data context {driver.context} is "
              f"not active -- every socket dial will fail no matter what state "
              f"the remote port is in.\033[0m")
        print(f"\033[90m  module said: {detail}\033[0m")
        print('\033[90m  configure the APN first, e.g. AT+CGDCONT=1,"IP","<apn>"'
              ' then AT#SGACT=1,1 (Telit) / AT+QIACT=1 (Quectel)\033[0m')

    try:
        for ip in ips:
            seen_valid = False
            unknowns = 0
            host_down = False
            for port in ports:
                try:
                    port_int = int(port)
                except ValueError:
                    print(f"Skipping invalid port: {port}")
                    continue

                for proto in protos:
                    if proto == "TCP":
                        result = scan_tcp(driver, ser, ip, port_int,
                                          seen_valid, unknowns)
                        if result is None:
                            host_down = True
                            break
                        seen_valid, unknowns = result
                    else:
                        scan_udp(driver, ser, ip, port_int, args.udp_wait)
                    time.sleep(args.delay)

                if host_down:
                    break
    finally:
        ser.close()

def format_result(ip, port, proto, color, state, code, show_code=True):
    raw = code if code is not None else "none"
    line = f"\033[{color}m{ip}:{port}/{proto} - {state}\033[0m"
    if show_code:
        line += f" \033[90m[code {raw}]\033[0m"
    return line

DOWN_AFTER = 3


def scan_tcp(driver, ser, ip, port, seen_valid, unknowns=0):
    established, code = driver.open(ser, "TCP", ip, port)
    driver.close(ser)

    cls = driver.classify_tcp(established, code)
    if cls == "open":
        print(format_result(ip, port, "tcp", "92", "OPEN", code))
        return True, 0
    if cls == "closed":
        print(format_result(ip, port, "tcp", "33", "CLOSED", code))
        return True, 0

    unknowns += 1
    print(format_result(ip, port, "tcp", "93", "UNKNOWN", code))
    if not seen_valid and unknowns >= DOWN_AFTER:
        raw = code if code is not None else "none"
        print(f"\033[91m{ip} - DOWN\033[0m \033[90m[code {raw}]\033[0m")
        return None
    return seen_valid, unknowns


# UDP scan: open a UDP socket, send a probe, and watch for a reply. 
# Port status is inferred by response:
#   reply received                 -> OPEN
#   ICMP port-unreachable surfaced -> CLOSED (module dependent)
#   nothing                        -> OPEN|FILTERED (can't distinguish)
def scan_udp(driver, ser, ip, port, udp_wait):
    payload = UDP_PAYLOADS.get(port, DEFAULT_UDP_PAYLOAD)
    if callable(payload):
        payload = payload(ip, port)

    established, code = driver.open(ser, "UDP", ip, port)
    if not established:
        driver.close(ser)
        state = "SOCKET-FAIL" if code else "SOCKET-FAIL (no response after retry)"
        print(format_result(ip, port, "udp", "90", state, code))
        return

    sent = driver.send(ser, payload) or ""

    if driver.recv_token in sent:
        reply = sent
    else:
        reply = sent + read_until(ser, driver.recv_token, timeout=udp_wait)
        verbose_rx(reply, f"UDP WAIT {udp_wait:g}s")

    if driver.recv_token in reply:
        color, state = "92", "OPEN"
    elif driver.is_udp_closed(reply):
        color, state = "33", "CLOSED"
    elif driver.has_pending_data(ser):
        color, state = "92", "OPEN"
    elif not driver.is_socket_open(ser):
        color, state = "33", "CLOSED"
    else:
        color, state = "93", "OPEN|FILTERED"

    if state == "OPEN" and VERBOSE:
        data = driver.read_data(ser)
        if data:
            print(f"\033[90m[REPLY] {len(data)} bytes: {data.hex()}\033[0m")

    driver.close(ser)
    print(format_result(ip, port, "udp", color, state, code, show_code=False))


# Parses command-line arguments for targets, ports, protocol, and serial port.
def parse_args():
    parser = argparse.ArgumentParser(
        description="Cellular module TCP/UDP port scanner (Quectel / Telit)"
    )

    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument("--ipfile", help="File with IP addresses (one per line)")
    ip_group.add_argument("-IP", dest="ip", help="Single IP to scan (e.g. 192.168.0.1)")
    ip_group.add_argument("-IC", dest="cidr", help="CIDR to scan (e.g. 192.168.0.0/24)")

    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument("--portfile", help="File with ports (one per line)")
    port_group.add_argument("-p", "--ports",
                            help="Ports or ranges (e.g. 80,443 or 1-1000 or 22,80,8000-8100)")

    parser.add_argument("--serialport", required=True,
                        help="Serial port for module (e.g. /dev/ttyUSB0)")
    parser.add_argument("--module", choices=["quectel", "telit"],
                        default="quectel",
                        help="Cellular module family (default: quectel)")
    parser.add_argument("--proto", choices=["tcp", "udp", "both"], default="tcp",
                        help="Protocol(s) to scan (default: tcp)")
    parser.add_argument("--udp-wait", type=float, default=3.0,
                        help="Seconds to wait for a UDP reply (default: 3.0)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between probes in seconds (default: 0.5)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show AT commands, raw module responses, and probe data")
    return parser.parse_args()


# Builds the IP target list from a single IP, CIDR, or file.
def build_ips(args):
    if args.ip:
        return [args.ip]
    if args.cidr:
        try:
            net = ipaddress.ip_network(args.cidr, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            print(f"Invalid CIDR: {args.cidr}")
            sys.exit(1)
    return load_list_from_file(args.ipfile)


# Builds the port list.
def build_ports(args):
    raw = args.ports if args.ports else ",".join(load_list_from_file(args.portfile))
    return expand_ports(raw)


# Expands a port spec into individual port strings.
def expand_ports(spec):
    ports = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            try:
                lo, hi = (int(x) for x in tok.split("-", 1))
            except ValueError:
                print(f"Skipping invalid port range: {tok}")
                continue
            if lo > hi:
                lo, hi = hi, lo
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                print(f"Skipping out-of-bounds port range: {tok}")
                continue
            ports.extend(str(p) for p in range(lo, hi + 1))
        else:
            ports.append(tok)
    return ports

def load_list_from_file(filepath):
    try:
        with open(filepath) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        sys.exit(1)


# Sends an AT command, then reads until `until` appears, OK/ERROR is seen, or `timeout` elapses.
def at_cmd(ser, cmd, until=None, timeout=5):
    ser.reset_input_buffer()
    verbose_tx(cmd)
    ser.write((cmd + "\r\n").encode())
    response = read_until(ser, until, timeout, stop_on_status=(until is None))
    verbose_rx(response)
    return response


# Reads from serial waits for response or until timeout elapses.
def read_until(ser, until, timeout, stop_on_status=False, drain=0.15):
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        n = ser.in_waiting
        chunk = ser.read(n if n else 1).decode("latin-1")
        buf += chunk
        if until and until in buf:
            break
        if stop_on_status and ("OK" in buf or "ERROR" in buf):
            break
    if drain:
        quiet_until = time.time() + drain
        while time.time() < quiet_until:
            n = ser.in_waiting
            if n:
                buf += ser.read(n).decode("latin-1")
                quiet_until = time.time() + drain
            else:
                time.sleep(0.02)
    return buf


if __name__ == "__main__":
    main()
