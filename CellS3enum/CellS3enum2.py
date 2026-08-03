#!/usr/bin/env python3

############################################
#          CellS3Enum Version 2            #
#                                          #
# AWS S3 bucket enumerator using a Quectel #
# Cellular module using AT commmands via   #
# serial communication.                    #
# Tested on Quectel EG91. Should work with #
# similar Quectel modules.                 #
#                                          #
#            Carlota Bindner               #
#                                          #
#          Copywrite 2025, 2026            #
#                                          #
#                                          #
# Intended for authorized security         #
# assessment and learning purposes only.   #
############################################

import time
import re
import json
import csv
import os
import signal
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import serial
from serial.tools import list_ports

stop_event = False
HTTP_GET_TIMEOUT = 60
HTTP_URC_GRACE = 15


def _handle_sigint(signum, frame):
    global stop_event
    if stop_event:
        print("\n[!] Force exit.")
        sys.exit(1)
    stop_event = True
    print(
        "\n[!] Stop requested - finishing current probe, then saving. "
        "Ctrl+C again to force."
    )


class C:
    GREEN, YELLOW, CYAN, RED, BLUE, MAGENTA, RESET = (
        "\033[32m", "\033[33m", "\033[36m", "\033[31m",
        "\033[34m", "\033[35m", "\033[0m",
    )


def color(text: str, code: str) -> str:
    return f"{code}{text}{C.RESET}"


_BUCKET_RE = re.compile(r"^(?!-)[a-z0-9.-]{3,63}(?<!-)$")


def valid_bucket(name: str) -> bool:
    return bool(_BUCKET_RE.match(name)) and ".." not in name


# Modem HTTP Client
class EG91HTTPSClient:
    def __init__(self, port, baudrate=115200, require_rdy=True, verbose=False):
        self.verbose = verbose
        self.response_headers_enabled = True
        self.ser = serial.Serial(port, baudrate, timeout=1)
        self.flush()
        if require_rdy:
            self.wait_for_ready()
        self.configure()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def flush(self):
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def _log(self, msg):
        if self.verbose:
            print(msg)

    def wait_for_ready(self, timeout=60):
        print("[MODEM] Waiting for RDY from Quectel module...")
        start = time.time()
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore").strip()
                self._log(f"[MODEM] << {line}")
                if "RDY" in line:
                    print("[MODEM] RDY detected.")
                    return
            time.sleep(0.05)
        print("[MODEM] RDY not seen; falling back to AT probe...")
        if "OK" not in self.send_at("AT", wait="OK", timeout=5):
            raise RuntimeError("Modem not responsive.")

    def configure(self):
        for cmd in (
            'AT+QHTTPCFG="contextid",1',
            f'AT+QHTTPCFG="responseheader",{int(self.response_headers_enabled)}',
            'AT+QHTTPCFG="sslctxid",1',
            'AT+QSSLCFG="sslversion",1,4',
            'AT+QSSLCFG="seclevel",1,0',
        ):
            self.send_at(cmd, wait="OK", timeout=5)

    def set_response_headers(self, enabled: bool):
        value = 1 if enabled else 0
        resp = self.send_at(
            f'AT+QHTTPCFG="responseheader",{value}', wait="OK", timeout=5
        )
        if "OK" not in resp or "ERROR" in resp:
            raise RuntimeError(f"Could not configure response headers: {resp}")
        self.response_headers_enabled = enabled

    def send_at(self, cmd, wait="OK", timeout=10):
        self._log(f"[MODEM] >> {cmd}")
        self.ser.write((cmd + "\r").encode())
        return self.read_until(wait=wait, timeout=timeout)

    def read_until(self, wait="OK", timeout=10):
        """Read a modem response without transmitting another AT command."""
        buffer, start = "", time.time()
        while time.time() - start < timeout:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore")
                buffer += line
                self._log(f"[MODEM] << {line.strip()}")
                if wait in line or "ERROR" in line:
                    break
            else:
                time.sleep(0.02)
        return buffer.strip()

    def recover_http(self):
        """Clear a wedged HTTP transaction before the next bucket probe.

        EG91 firmware commonly does not implement QHTTPSTOP, so try it first
        and fall back to recycling PDP context 1. QICSGP configuration is
        persistent on the modem and is therefore not overwritten here.
        """
        self._log("[MODEM] Recovering HTTP state...")
        self.ser.reset_input_buffer()

        stop_resp = self.send_at("AT+QHTTPSTOP", wait="OK", timeout=12)
        if "OK" in stop_resp and "ERROR" not in stop_resp:
            self.ser.reset_input_buffer()
            self._log("[MODEM] HTTP request stopped.")
            return

        self.send_at("AT+QIDEACT=1", wait="OK", timeout=45)
        act_resp = self.send_at("AT+QIACT=1", wait="OK", timeout=150)
        if "OK" not in act_resp or "ERROR" in act_resp:
            raise RuntimeError(f"PDP reactivation failed: {act_resp or 'no response'}")

        self.configure()
        self.ser.reset_input_buffer()
        self._log("[MODEM] PDP/HTTP state recovered.")

    def _recover_or_raise(self, reason):
        """Always raises: recovers HTTP state, then reports how that went."""
        try:
            self.recover_http()
        except Exception as recovery_error:
            raise RuntimeError(
                f"{reason}; recovery failed: {recovery_error}"
            ) from recovery_error
        raise RuntimeError(f"{reason}; HTTP state recovered")

    def https_get(
        self,
        url: str,
        read_body: bool = False,
        retry_dns: bool = True,
        byte_range=None,
    ):
        """Return (status_code, body). Body only read when read_body=True."""
        self.last_content_length = None
        self.ser.reset_input_buffer()

        url_bytes = url.encode()
        resp = self.send_at(f"AT+QHTTPURL={len(url_bytes)},30", wait="CONNECT")
        if "703" in resp:
            self.recover_http()
            resp = self.send_at(f"AT+QHTTPURL={len(url_bytes)},30", wait="CONNECT")
        if "CONNECT" not in resp:
            raise RuntimeError(f"QHTTPURL failed: {resp}")
        self.ser.write(url_bytes)
        url_resp = self.read_until(wait="OK", timeout=5)
        if "OK" not in url_resp or "ERROR" in url_resp:
            raise RuntimeError(f"Modem did not accept URL: {url_resp or 'no response'}")

        if byte_range is None:
            get_cmd = f"AT+QHTTPGET={HTTP_GET_TIMEOUT}"
        else:
            start, length = byte_range
            get_cmd = f"AT+QHTTPGETEX={HTTP_GET_TIMEOUT},{int(start)},{int(length)}"
        get_resp = self.send_at(get_cmd, wait="OK", timeout=10)
        if "OK" not in get_resp or "ERROR" in get_resp:
            self._recover_or_raise(f"QHTTPGET rejected: {get_resp or 'no response'}")

        buffer, start, got = "", time.time(), False
        while time.time() - start < HTTP_GET_TIMEOUT + HTTP_URC_GRACE:
            if self.ser.in_waiting:
                line = self.ser.readline().decode(errors="ignore").strip()
                buffer += line + "\n"
                self._log(f"[MODEM] << {line}")
                if "+QHTTPGET:" in line:
                    got = True
                    break
            else:
                time.sleep(0.02)
        if not got:
            self._recover_or_raise(
                f"No +QHTTPGET response after {HTTP_GET_TIMEOUT + HTTP_URC_GRACE}s; "
                f"modem output: {buffer.strip() or '(none)'}"
            )

        m = re.search(r"\+QHTTPGET:\s*(\d+)(?:,(\d+))?(?:,(\d+))?", buffer)
        if not m:
            raise RuntimeError(f"Unparseable +QHTTPGET: {buffer.strip()}")
        err = int(m.group(1))
        if err != 0 or m.group(2) is None:
            if err == 714 and retry_dns:
                self.recover_http()
                return self.https_get(
                    url, read_body=read_body, retry_dns=False, byte_range=byte_range
                )
            raise RuntimeError(f"QHTTPGET transport error (err={err})")
        code = int(m.group(2))
        self.last_content_length = int(m.group(3)) if m.group(3) else None

        body = ""
        if read_body:
            body = self.send_at("AT+QHTTPREAD=30", wait="OK", timeout=35)
        return code, body

    def save_response_body(self, destination: Path, timeout=180):
        """Stream the pending HTTP response body to a local binary file."""
        length = self.last_content_length
        if length is None:
            raise RuntimeError("HTTP response did not include Content-Length")

        destination.parent.mkdir(parents=True, exist_ok=True)
        candidate = destination
        suffix_number = 1
        while candidate.exists():
            candidate = destination.with_name(
                f"{destination.stem}-{suffix_number}{destination.suffix}"
            )
            suffix_number += 1
        partial = candidate.with_name(candidate.name + ".part")

        self._log("[MODEM] >> AT+QHTTPREAD=60")
        self.ser.write(b"AT+QHTTPREAD=60\r")

        start = time.time()
        connected = False
        preamble = bytearray()
        while time.time() - start < 15:
            line = self.ser.readline()
            if line:
                preamble.extend(line)
                self._log(f"[MODEM] << {line.decode(errors='replace').strip()}")
                if line.strip() == b"CONNECT":
                    connected = True
                    break
                if b"ERROR" in line:
                    break
            else:
                time.sleep(0.02)
        if not connected:
            raise RuntimeError(
                "QHTTPREAD did not enter data mode: "
                + preamble.decode(errors="replace").strip()
            )

        remaining = length
        try:
            with partial.open("wb") as output:
                while remaining:
                    if time.time() - start >= timeout:
                        raise RuntimeError(
                            "Local download timed out with "
                            f"{remaining} byte(s) remaining"
                        )
                    chunk = self.ser.read(min(65536, remaining))
                    if not chunk:
                        continue
                    output.write(chunk)
                    remaining -= len(chunk)

            trailer = self.read_until(wait="+QHTTPREAD:", timeout=15)
            if "+QHTTPREAD: 0" not in trailer:
                raise RuntimeError(
                    f"Modem did not confirm completed read: {trailer or 'no response'}"
                )
            partial.replace(candidate)
            return candidate
        except Exception:
            if partial.exists():
                partial.unlink()
            raise


def load_lines(path_or_value: str):
    if os.path.isfile(path_or_value):
        text = Path(path_or_value).read_text()
        return [line.strip() for line in text.splitlines() if line.strip()]
    return [path_or_value.strip()]


def safe_download_name(bucket: str, obj: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{bucket}_{obj}")
    name = name.strip("._") or "download"
    return name[:220]


def prompt_value(label: str, default=None, required=True) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default not in (None, ""):
            return str(default)
        if not required:
            return ""
        print("Please enter a value.")


def prompt_yes_no(label: str, default=False) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        print("Please answer y or n.")


def prompt_mode() -> str:
    print("\nWhat would you like to do?")
    print("  1) Find buckets")
    print("  2) Find files in buckets")
    while True:
        value = input("Selection [2]: ").strip().lower() or "2"
        if value in ("1", "bucket", "buckets"):
            return "buckets"
        if value in ("2", "file", "files", "objects"):
            return "files"
        print("Please select 1 or 2.")


def prompt_serial_port() -> str:
    detected = [port.device for port in list_ports.comports()]
    if detected:
        print("\nDetected serial ports:")
        for index, device in enumerate(detected, 1):
            print(f"  {index}) {device}")
        while True:
            value = input("Select a number or enter a device path: ").strip()
            if value.isdigit() and 1 <= int(value) <= len(detected):
                return detected[int(value) - 1]
            if value and not value.isdigit():
                return value
            print("Please select a listed number or enter a device path.")
    return prompt_value("Serial port")


def interactive_setup(args):
    print("\nCellS3Enum Setup")
    print("-----------------------")
    mode = prompt_mode()
    args.find_bucket = mode == "buckets"
    args.bucketnames = prompt_value(
        "Bucket name or path to a bucket-name file",
        args.bucketnames,
    )
    args.region = prompt_value("AWS region", args.region)

    if mode == "files":
        args.wordlist = prompt_value(
            "Path to the object-name wordlist",
            args.wordlist,
        )
        current_extensions = ",".join(args.extensions or ["txt"])
        extension_text = prompt_value(
            "Extensions, separated by commas",
            current_extensions,
        )
        args.extensions = [
            item.strip().lstrip(".")
            for item in re.split(r"[,\s]+", extension_text)
            if item.strip()
        ]
        if prompt_yes_no("Save readable files locally?", default=False):
            args.download_dir = prompt_value(
                "Download directory",
                args.download_dir or "./download",
            )
            args.read_body = False
        else:
            args.download_dir = None
            args.read_body = False
    else:
        args.wordlist = None
        args.download_dir = None
        args.read_body = False

    args.serial_port = prompt_serial_port()
    args.assume_on = prompt_yes_no(
        "Is the modem already powered on and ready?",
        default=True,
    )

    print("\nRun summary")
    print(f"  Mode:        {'bucket names' if args.find_bucket else 'files'}")
    print(f"  Buckets:     {args.bucketnames}")
    if not args.find_bucket:
        print(f"  Wordlist:    {args.wordlist}")
        print(f"  Extensions:  {', '.join(args.extensions)}")
        print(f"  Download:    {args.download_dir or 'no (one-byte probes)'}")
    print(f"  Region:      {args.region}")
    print(f"  Serial port: {args.serial_port}")
    if not prompt_yes_no("Start now?", default=True):
        print("Cancelled.")
        raise SystemExit(0)
    print()
    return args


def classify(status):
    if status == 200:
        return "READABLE (200)", C.GREEN
    if status == 206:
        return "READABLE (206 partial)", C.GREEN
    if status == 403:
        return "FORBIDDEN (403)", C.MAGENTA
    if status == 404:
        return "NOT FOUND (404)", C.YELLOW
    return f"OTHER ({status})", C.CYAN


def _find(pattern, text):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def classify_existence(status, body):
    xml_code = _find(r"<Code>([^<]+)</Code>", body)
    region = (
        _find(r"x-amz-bucket-region:\s*([a-z0-9-]+)", body)
        or _find(r"<Region>([^<]+)</Region>", body)
        or _find(r"<Endpoint>([^<]+)</Endpoint>", body)
    )
    redirect_codes = (
        "PermanentRedirect",
        "AuthorizationHeaderMalformed",
        "IllegalLocationConstraintException",
    )
    if xml_code == "NoSuchBucket" or (status == 404 and not xml_code):
        return "MISSING", C.YELLOW, "NoSuchBucket"
    if xml_code in redirect_codes or status in (301, 307):
        return "NAME TAKEN (other region)", C.CYAN, f"region={region or 'unknown'}"
    if xml_code == "AccessDenied":
        return "NAME TAKEN (owner unknown)", C.MAGENTA, "AccessDenied"
    if status == 403:
        return "UNKNOWN (403)", C.MAGENTA, "ownership unconfirmed"
    if status == 200:
        return "EXISTS (public)", C.GREEN, "listable"
    return f"UNKNOWN ({status})", C.CYAN, xml_code or ""


def print_flag_summary(parser):
    actions = [
        action
        for action in parser._actions
        if action.option_strings and "--interactive" not in action.option_strings
    ]
    interactive = next(
        (
            action
            for action in parser._actions
            if "--interactive" in action.option_strings
        ),
        None,
    )
    print("Available flags:")
    for action in actions:
        print(f"  {', '.join(action.option_strings)}")
    if interactive:
        print(f"  {', '.join(interactive.option_strings)}")


def main():
    parser = argparse.ArgumentParser(
        description="S3 object enumerator via Quectel AT+QHTTPS (cellular egress).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--bucketnames",
        help="Bucket name or file of bucket names",
    )
    parser.add_argument(
        "--find-bucket",
        action="store_true",
        help="Only check whether buckets exist (probes the bucket root, no wordlist)",
    )
    parser.add_argument(
        "--wordlist",
        help="File of base object names (required unless --find-bucket)",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=["txt"],
        help="Extensions to append",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region used to build the regional S3 endpoint",
    )
    parser.add_argument(
        "--s3-endpoint",
        help="Optional custom S3 endpoint override",
    )
    parser.add_argument(
        "--serial-port",
        default="/dev/ttyUSB0",
        help="Modem serial port",
    )
    parser.add_argument(
        "--baudrate",
        type=int,
        default=115200,
        help="Baud rate",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds between probes",
    )
    parser.add_argument(
        "--read-body",
        action="store_true",
        help="Retrieve response bodies; default object probes request only one byte",
    )
    parser.add_argument(
        "--download-dir",
        help="Save HTTP 200 object bodies as local binary files in this directory",
    )
    parser.add_argument(
        "--out",
        default="cells3enum_results",
        help="Output prefix; a YYYYMMDD_HHMMSS timestamp is appended",
    )
    parser.add_argument(
        "--assume-on",
        action="store_true",
        help="Skip RDY wait",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose modem logging",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch the guided setup prompts",
    )
    args = parser.parse_args()
    if len(sys.argv) == 1:
        print_flag_summary(parser)
        print("\nTo start in interactive mode use flag --interactive")
        return
    if args.interactive:
        try:
            args = interactive_setup(args)
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
    if not args.bucketnames:
        parser.error("--bucketnames is required unless guided setup is used")
    if args.read_body and args.download_dir:
        parser.error("--read-body and --download-dir cannot be used together")
    if not re.fullmatch(r"[a-z0-9-]+", args.region):
        parser.error(
            "--region may contain only lowercase letters, numbers, and hyphens"
        )
    s3_endpoint = args.s3_endpoint or f"s3.{args.region}.amazonaws.com"
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = f"{args.out}_{run_timestamp}"

    signal.signal(signal.SIGINT, _handle_sigint)

    buckets = load_lines(args.bucketnames)
    skipped = [b for b in buckets if not valid_bucket(b)]
    buckets = [b for b in buckets if valid_bucket(b)]
    if skipped:
        print(color(f"[i] Skipped {len(skipped)} invalid bucket name(s).", C.YELLOW))

    if args.find_bucket:
        print(f"[i] find-bucket: checking existence of {len(buckets)} bucket(s)\n")
        jsonl_path = Path(f"{output_base}.jsonl")
        results, public = [], 0
        with EG91HTTPSClient(
            args.serial_port,
            args.baudrate,
            require_rdy=not args.assume_on,
            verbose=args.verbose,
        ) as modem, jsonl_path.open("w") as jf:
            for i, bucket in enumerate(buckets, 1):
                if stop_event:
                    break
                url = f"https://{bucket}.{s3_endpoint}/"
                row = {
                    "bucket": bucket,
                    "url": url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    status, body = modem.https_get(url, read_body=True)
                    verdict, col, detail = classify_existence(status, body)
                    if verdict == "EXISTS (public)":
                        public += 1
                    row.update(status=status, verdict=verdict, detail=detail)
                    line = f"[{i}/{len(buckets)}] {verdict:22} {bucket}  ({detail})"
                    print(color(line, col))
                except Exception as e:
                    row.update(status="error", verdict="ERROR", detail=str(e))
                    line = f"[{i}/{len(buckets)}] ERROR                  {bucket}  {e}"
                    print(color(line, C.RED))
                results.append(row)
                jf.write(json.dumps(row) + "\n")
                jf.flush()
                if not stop_event:
                    time.sleep(args.delay)

        csv_path = Path(f"{output_base}.csv")
        with csv_path.open("w", newline="") as cf:
            w = csv.DictWriter(
                cf,
                fieldnames=[
                    "timestamp", "bucket", "url", "status", "verdict", "detail",
                ],
            )
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in w.fieldnames})
        print(color(
            f"\n[DONE] {len(results)}/{len(buckets)} checked; "
            f"{public} public/listable.",
            C.BLUE,
        ))
        print(color(f"       stream: {jsonl_path}   summary: {csv_path}", C.BLUE))
        return

    if not args.wordlist:
        parser.error("--wordlist is required unless --find-bucket is used")

    bases = load_lines(args.wordlist)
    objects = list(dict.fromkeys(f"{b}.{e}" for b in bases for e in args.extensions))

    total = len(buckets) * len(objects)
    print(f"[i] {len(buckets)} bucket(s) x {len(objects)} object(s) = {total} probes\n")

    jsonl_path = Path(f"{output_base}.jsonl")
    download_dir = Path(args.download_dir) if args.download_dir else None
    results = []
    hits = 0
    done = 0

    with EG91HTTPSClient(
        args.serial_port,
        args.baudrate,
        require_rdy=not args.assume_on,
        verbose=args.verbose,
    ) as modem, jsonl_path.open("w") as jf:
        if download_dir:
            modem.set_response_headers(False)

        for bucket in buckets:
            for obj in objects:
                if stop_event:
                    break
                done += 1
                url = f"https://{bucket}.{s3_endpoint}/{obj}"
                prefix = f"[{done}/{total}]"
                row = {
                    "bucket": bucket,
                    "object": obj,
                    "url": url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    want_body = args.read_body
                    status, body = modem.https_get(
                        url,
                        read_body=want_body,
                        byte_range=None if (want_body or download_dir) else (0, 1),
                    )
                    label, col = classify(status)
                    if status in (200, 206):
                        hits += 1
                    local_file = ""
                    if download_dir and status == 200:
                        destination = download_dir / safe_download_name(bucket, obj)
                        saved_path = modem.save_response_body(destination)
                        local_file = saved_path.name
                    row.update(
                        status=status,
                        label=label,
                        body=body[:200],
                        local_file=local_file,
                    )
                    message = f"{prefix} {label} {url} -> HTTP {status}"
                    if local_file:
                        message += f"  saved: {local_file}"
                    print(color(message, col))
                except Exception as e:
                    row.update(status="error", error=str(e))
                    print(color(f"{prefix} ERROR {url} -> {e}", C.RED))

                results.append(row)
                jf.write(json.dumps(row) + "\n")
                jf.flush()
                if not stop_event:
                    time.sleep(args.delay)
            if stop_event:
                break

    csv_path = Path(f"{output_base}.csv")
    with csv_path.open("w", newline="") as cf:
        w = csv.DictWriter(
            cf,
            fieldnames=[
                "timestamp", "bucket", "object", "url", "status",
                "label", "local_file", "error",
            ],
        )
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in w.fieldnames})

    print(color(f"\n[DONE] {done}/{total} probed, {hits} hit(s).", C.BLUE))
    print(color(f"       stream: {jsonl_path}   summary: {csv_path}", C.BLUE))


if __name__ == "__main__":
    main()

