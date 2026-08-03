#!/usr/bin/env python3
"""
u-blox SARA-R410M TCP/HTTP validation script.

Validation flow:
  1. Open /dev/ttyUSB2
  2. Check registration / attach / PDP state
  3. Resolve httpforever.com with AT+UDNSRN
  4. Create TCP socket with AT+USOCR=6
  5. Connect with AT+USOCO using resolved IPv4
  6. Send HTTP/1.0 request with AT+USOWR
  7. Watch for +UUSORD URCs and read with AT+USORD
  8. Close socket with AT+USOCL

Requirements:
    pip install pyserial

Usage:
    sudo python3 ublox_http_validation.py

Optional:
    sudo python3 ublox_http_validation.py --port /dev/ttyUSB2
"""

import argparse
import re
import serial
import sys
import time

DEFAULT_PORT = "/dev/ttyUSB2"
DEFAULT_BAUD = 115200
HOST = "httpforever.com"
PORT = 80

CMD_TIMEOUT = 10.0
CONNECT_TIMEOUT = 30.0
RX_TIMEOUT = 15.0
POLL_INTERVAL = 0.05
READ_CHUNK = 512


def now():
    return time.strftime("%H:%M:%S")


class UBloxModem:
    def __init__(self, port, baud):
        self.ser = serial.Serial(
            port=port,
            baudrate=baud,
            timeout=0.1,
            write_timeout=5,
        )
        time.sleep(0.2)
        self.ser.reset_input_buffer()

    def close(self):
        if self.ser.is_open:
            self.ser.close()

    def _read_until(self, predicates, timeout, echo=True):
        deadline = time.monotonic() + timeout
        buf = bytearray()

        while time.monotonic() < deadline:
            waiting = self.ser.in_waiting
            if waiting:
                chunk = self.ser.read(waiting)
                buf.extend(chunk)

                if echo:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()

                data = bytes(buf)
                for pred in predicates:
                    if pred(data):
                        return data
            else:
                time.sleep(0.01)

        return bytes(buf)

    def command(self, command, timeout=CMD_TIMEOUT, allow_error=False):
        self.ser.reset_input_buffer()
        print(f"\n[{now()}] >>> {command}")
        self.ser.write((command + "\r").encode("ascii"))
        self.ser.flush()

        def ok(data):
            return b"\r\nOK\r\n" in data

        def error(data):
            return (
                b"\r\nERROR\r\n" in data
                or b"+CME ERROR:" in data
                or b"+CMS ERROR:" in data
            )

        response = self._read_until((ok, error), timeout)

        if not response:
            raise TimeoutError(f"No response to {command}")

        if error(response) and not allow_error:
            raise RuntimeError(
                f"{command} failed: {response.decode(errors='replace').strip()}"
            )

        return response.decode(errors="replace")

    def wait_for_token(self, token, timeout):
        token = token if isinstance(token, bytes) else token.encode()
        print(f"[{now()}] [*] Waiting for {token!r}")

        return self._read_until(
            (lambda data: token in data,),
            timeout,
        )

    def write_raw(self, data):
        self.ser.write(data)
        self.ser.flush()

    def read_urcs(self, timeout):
        deadline = time.monotonic() + timeout
        buf = bytearray()

        while time.monotonic() < deadline:
            waiting = self.ser.in_waiting

            if waiting:
                chunk = self.ser.read(waiting)
                buf.extend(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            else:
                time.sleep(POLL_INTERVAL)

        return bytes(buf)


def extract_socket_id(response):
    match = re.search(r"\+USOCR:\s*(\d+)", response)
    if not match:
        raise RuntimeError("Unable to parse socket ID from AT+USOCR response")
    return int(match.group(1))


def extract_ipv4(response):
    # Handles one or multiple addresses, such as:
    # +UDNSRN: "104.21.4.210", "172.67.132.115"
    addresses = re.findall(
        r'"((?:\d{1,3}\.){3}\d{1,3})"',
        response,
    )

    if not addresses:
        raise RuntimeError("DNS query returned no IPv4 address")

    return addresses[0], addresses


def extract_uusord_lengths(data, socket_id):
    text = data.decode(errors="replace")
    pattern = rf"\+UUSORD:\s*{socket_id},(\d+)"
    return [int(value) for value in re.findall(pattern, text)]


def parse_usord_length(response, socket_id):
    pattern = rf"\+USORD:\s*{socket_id},(\d+)"
    match = re.search(pattern, response)
    if not match:
        return 0
    return int(match.group(1))


def main():
    parser = argparse.ArgumentParser(
        description="Validate u-blox SARA-R410M TCP socket + HTTP operation."
    )
    parser.add_argument("--port", default=DEFAULT_PORT)
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--remote-port", type=int, default=PORT)
    parser.add_argument("--rx-timeout", type=float, default=RX_TIMEOUT)
    args = parser.parse_args()

    modem = None
    socket_id = None

    try:
        print("=== u-blox SARA-R410M HTTP Validation ===")
        print(f"Serial: {args.port} @ {args.baud}")
        print(f"Target: http://{args.host}:{args.remote_port}/")

        modem = UBloxModem(args.port, args.baud)

        print("\n--- Basic modem state ---")
        modem.command("AT")
        modem.command("ATE0")
        modem.command("AT+CMEE=2")

        print("\n--- Network / PDP state ---")
        cereg = modem.command("AT+CEREG?")
        cgatt = modem.command("AT+CGATT?")
        cgact = modem.command("AT+CGACT?")
        cgdcont = modem.command("AT+CGDCONT?")

        if not re.search(r"\+CEREG:\s*\d+,(1|5)\b", cereg):
            print("[!] Warning: modem is not currently registered (CEREG != 1/5)")

        if "+CGATT: 1" not in cgatt:
            print("[!] Warning: packet attach is not active")

        if not re.search(r"\+CGACT:\s*1,1\b", cgact):
            print("[!] Warning: PDP context 1 is not active")

        print("\n--- DNS resolution ---")
        dns = modem.command(f'AT+UDNSRN=0,"{args.host}"', timeout=20.0)
        ipv4, all_ipv4 = extract_ipv4(dns)

        print(f"[+] Resolved {args.host}: {', '.join(all_ipv4)}")
        print(f"[+] Using IPv4: {ipv4}")

        print("\n--- Create TCP socket ---")
        # Best effort cleanup of socket 0 from previous manual testing.
        modem.command("AT+USOCL=0", timeout=5.0, allow_error=True)

        response = modem.command("AT+USOCR=6")
        socket_id = extract_socket_id(response)
        print(f"[+] TCP socket allocated: {socket_id}")

        print("\n--- Connect TCP socket ---")
        modem.command(
            f'AT+USOCO={socket_id},"{ipv4}",{args.remote_port}',
            timeout=CONNECT_TIMEOUT,
        )
        print(f"[+] Connected socket {socket_id} to {ipv4}:{args.remote_port}")

        print("\n--- Send HTTP request ---")
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {args.host}\r\n"
            f"\r\n"
        ).encode("ascii")

        print(f"[*] HTTP request length: {len(request)} bytes")
        print(request.decode("ascii").replace("\r", "\\r").replace("\n", "\\n\n"))

        # Binary USOWR form: command -> @ prompt -> exactly N raw bytes.
        modem.ser.reset_input_buffer()
        command = f"AT+USOWR={socket_id},{len(request)}"
        print(f"[{now()}] >>> {command}")
        modem.ser.write((command + "\r").encode("ascii"))
        modem.ser.flush()

        prompt_data = modem.wait_for_token(b"@", timeout=10.0)
        if b"@" not in prompt_data:
            raise TimeoutError("No @ prompt after AT+USOWR")

        print(f"\n[{now()}] >>> [RAW HTTP REQUEST: {len(request)} bytes]")
        modem.write_raw(request)

        send_result = modem._read_until(
            (
                lambda d: b"\r\nOK\r\n" in d,
                lambda d: b"\r\nERROR\r\n" in d or b"+CME ERROR:" in d,
            ),
            timeout=10.0,
        )

        if b"OK" not in send_result:
            raise RuntimeError(
                "AT+USOWR payload send failed: "
                + send_result.decode(errors="replace")
            )

        print(f"\n[+] HTTP request sent on socket {socket_id}")

        print("\n--- Receive HTTP response ---")
        print(f"[*] Watching for +UUSORD for up to {args.rx_timeout:.1f}s")

        deadline = time.monotonic() + args.rx_timeout
        total_read = 0
        saw_http = False

        while time.monotonic() < deadline:
            urc_data = modem.read_urcs(timeout=0.5)
            lengths = extract_uusord_lengths(urc_data, socket_id)

            if not lengths:
                continue

            # Multiple URCs may accumulate; read available data in chunks.
            for available in lengths:
                remaining = available

                while remaining > 0:
                    to_read = min(READ_CHUNK, remaining)
                    response = modem.command(
                        f"AT+USORD={socket_id},{to_read}",
                        timeout=10.0,
                    )

                    read_len = parse_usord_length(response, socket_id)
                    if read_len <= 0:
                        break

                    total_read += read_len
                    remaining -= read_len

                    if "HTTP/" in response:
                        saw_http = True

            # Once HTTP has been observed, give the modem a little time to
            # surface any final buffered-data notifications.
            if saw_http:
                time.sleep(0.5)
                tail = modem.read_urcs(timeout=0.5)
                tail_lengths = extract_uusord_lengths(tail, socket_id)

                for available in tail_lengths:
                    response = modem.command(
                        f"AT+USORD={socket_id},{min(READ_CHUNK, available)}",
                        timeout=10.0,
                    )
                    total_read += parse_usord_length(response, socket_id)

                break

        if total_read == 0:
            raise TimeoutError("No HTTP response data was read from socket")

        print()
        print(f"[+] HTTP response received: {total_read} bytes read")

        if saw_http:
            print("[+] HTTP status/header data detected")
        else:
            print("[!] Data was received, but no HTTP status line was detected")

        print("\n--- Close TCP socket ---")
        modem.command(f"AT+USOCL={socket_id}", timeout=10.0, allow_error=True)
        socket_id = None

        print()
        print("[+] PASS: u-blox TCP create/connect/write/read/close validation completed")

    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    except Exception as exc:
        print(f"\n[-] Validation failed: {exc}", file=sys.stderr)
        sys.exit_code = 1

    finally:
        if modem is not None:
            if socket_id is not None:
                try:
                    print(f"\n[*] Cleanup: closing socket {socket_id}")
                    modem.command(
                        f"AT+USOCL={socket_id}",
                        timeout=5.0,
                        allow_error=True,
                    )
                except Exception:
                    pass
            modem.close()


if __name__ == "__main__":
    sys.exit_code = 0
    main()
    sys.exit(sys.exit_code)
