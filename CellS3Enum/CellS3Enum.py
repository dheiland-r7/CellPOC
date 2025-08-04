#!/usr/bin/env python3
import time
import re
import json
import os
import argparse
import serial
import sys
from datetime import datetime

stop_event = False

class EG91HTTPSClient:
    def __init__(self, port, baudrate=115200, require_rdy=True, verbose=False):
        self.verbose = verbose
        self.ser = serial.Serial(port, baudrate, timeout=1)
        self.flush()
        if require_rdy:
            self.wait_for_ready()

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def flush(self):
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def wait_for_ready(self, timeout=60):
        print("[MODEM] Waiting for RDY from Quectel Cell Module...")
        start = time.time()
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore").strip()
                if self.verbose:
                    print(f"[MODEM] << {line}")
                if "RDY" in line:
                    print("[MODEM] RDY detected.")
                    return
            time.sleep(0.1)
        print("[MODEM] Warning: RDY not detected within timeout. Trying AT fallback...")
        resp = self.send_at("AT", wait="OK", timeout=5)
        if "OK" not in resp:
            raise RuntimeError("Modem not responsive.")

    def send_at(self, cmd, wait="OK", timeout=10):
        if self.verbose:
            print(f"[MODEM] >> {cmd}")
        self.ser.write((cmd + "\r").encode())
        buffer = ""
        start = time.time()
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore")
                buffer += line
                if self.verbose:
                    print(f"[MODEM] << {line.strip()}")
                if wait in line:
                    break
            time.sleep(0.1)
        return buffer.strip()

    def https_get(self, url):
        print(f"[MODEM] HTTPS GET: {url}")
        resp = self.send_at(f'AT+QHTTPURL={len(url)},30', wait="CONNECT")
        if "CONNECT" not in resp:
            raise Exception(f"Failed at QHTTPURL: {resp}")
        self.ser.write((url + '\x1A').encode())
        time.sleep(2)
        self.send_at("AT+QHTTPGET=60")
        buffer = ""
        start = time.time()
        while time.time() - start < 30:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore").strip()
                buffer += line + "\n"
                if self.verbose:
                    print(f"[MODEM] << {line}")
                if "+QHTTPGET:" in line:
                    break
            time.sleep(0.1)

        code_match = re.search(r'\+QHTTPGET: 0,(\d+)', buffer)
        if not code_match:
            raise Exception(f"No valid +QHTTPGET response: {buffer.strip()}")

        code = int(code_match.group(1))
        body = self.send_at("AT+QHTTPREAD=30", wait="OK", timeout=10)
        if self.verbose:
            print(f"[MODEM] Response Body (truncated):\n{body[:500]}")
        return code, body

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def main():
    if len(sys.argv) == 1:
        print("""
Usage: python3 CellS3Enum.py --bucketnames <bucket or file> --wordlist <object list> [options]

Example:
  python3 CellS3Enum.py \
    --bucketnames bucketnames.txt \
    --wordlist wordlist.txt \
    --extensions txt json html \
    --s3-endpoint s3.us-east-1.amazonaws.com \
    --serial-port /dev/ttyUSB0 \
    --assume-on

This probes URLs like:
  https://<bucket>.s3.us-east-1.amazonaws.com/<object>.<ext>
""")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="S3 Object Enumerator via Quectel AT HTTPS")
    parser.add_argument("--bucketnames", required=True, help="Single bucket or file with bucket names")
    parser.add_argument("--wordlist", required=True, help="List of base object names to try")
    parser.add_argument("--extensions", nargs="+", default=["txt"], help="File extensions to append (e.g. txt json html)")
    parser.add_argument("--s3-endpoint", default="s3.amazonaws.com", help="S3 endpoint (default: s3.amazonaws.com)")
    parser.add_argument("--serial-port", default="/dev/ttyUSB0", help="Modem serial port")
    parser.add_argument("--baudrate", type=int, default=115200, help="Baud rate")
    parser.add_argument("--assume-on", action="store_true", help="Skip RDY wait")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if os.path.isfile(args.bucketnames):
        with open(args.bucketnames, "r") as f:
            buckets = [line.strip() for line in f if line.strip()]
    else:
        buckets = [args.bucketnames.strip()]

    with open(args.wordlist, "r") as f:
        raw_objects = [line.strip() for line in f if line.strip()]

    objects = []
    for base in raw_objects:
        for ext in args.extensions:
            objects.append(f"{base}.{ext}")
    objects = list(dict.fromkeys(objects))  # ordered and unique

    modem = EG91HTTPSClient(args.serial_port, args.baudrate, require_rdy=not args.assume_on, verbose=args.verbose)
    results = []

    for bucket in buckets:
        for obj in objects:
            url = f"https://{bucket}.{args.s3_endpoint}/{obj}"
            try:
                status, response = modem.https_get(url)
                results.append({
                    "bucket": bucket,
                    "object": obj,
                    "url": url,
                    "status": status,
                    "body": response[:200],
                    "timestamp": datetime.utcnow().isoformat()
                })
                if status == 200:
                    print(color_text(f"SUCCESS {url} → HTTP {status}", "32"))  # green
                elif status == 404:
                    print(color_text(f"NOT FOUND {url} → HTTP {status}", "33"))  # yellow
                else:
                    print(color_text(f"RESPONSE {url} → HTTP {status}", "36"))  # cyan
            except Exception as e:
                print(color_text(f"ERROR {url} → {e}", "31"))  # red
                results.append({
                    "bucket": bucket,
                    "object": obj,
                    "url": url,
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })
            time.sleep(1)

    modem.close()

    out_file = "s3_enum_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(color_text(f"[DONE] Results saved to {out_file}", "34"))  # blue

if __name__ == "__main__":
    main()
