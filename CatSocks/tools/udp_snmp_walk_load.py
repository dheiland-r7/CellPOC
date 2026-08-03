#!/usr/bin/env python3
"""CatSocks SOCKS5 UDP SNMP walk tool.

Performs an SNMPv1 or SNMPv2c GETNEXT walk through a SOCKS5 UDP
ASSOCIATE relay. Default walk root: 1.3.6.1.2.1.1 (system group).

Use only against systems you own or are authorized to assess.
"""

import argparse
import concurrent.futures
import random
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Tuple


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("SOCKS control connection closed")
        data += chunk
    return data


def read_address(sock: socket.socket, atyp: int) -> str:
    if atyp == 1:
        return socket.inet_ntoa(recv_exact(sock, 4))
    if atyp == 3:
        length = recv_exact(sock, 1)[0]
        return recv_exact(sock, length).decode("idna")
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    raise ValueError(f"Unsupported SOCKS ATYP {atyp}")


def encode_address(host: str) -> bytes:
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ValueError("SOCKS hostname is too long")
        return b"\x03" + bytes([len(encoded)]) + encoded


def parse_socks_udp_packet(packet: bytes) -> Tuple[str, int, bytes]:
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise ValueError("Invalid SOCKS5 UDP response header")

    atyp = packet[3]
    offset = 4

    if atyp == 1:
        if len(packet) < offset + 4:
            raise ValueError("Truncated IPv4 SOCKS header")
        host = socket.inet_ntoa(packet[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        if len(packet) < offset + 1:
            raise ValueError("Truncated hostname SOCKS header")
        length = packet[offset]
        offset += 1
        if len(packet) < offset + length:
            raise ValueError("Truncated hostname SOCKS header")
        host = packet[offset:offset + length].decode("idna")
        offset += length
    elif atyp == 4:
        if len(packet) < offset + 16:
            raise ValueError("Truncated IPv6 SOCKS header")
        host = socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16])
        offset += 16
    else:
        raise ValueError(f"Unsupported response ATYP {atyp}")

    if len(packet) < offset + 2:
        raise ValueError("Truncated SOCKS destination port")

    port = struct.unpack("!H", packet[offset:offset + 2])[0]
    return host, port, packet[offset + 2:]


def ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(value)) + value


def ber_integer(value: int) -> bytes:
    if value == 0:
        encoded = b"\x00"
    elif value > 0:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    else:
        size = max(1, (value.bit_length() + 8) // 8)
        encoded = value.to_bytes(size, "big", signed=True)
        while len(encoded) > 1 and encoded[0] == 0xFF and encoded[1] & 0x80:
            encoded = encoded[1:]
    return ber_tlv(0x02, encoded)


def ber_octet_string(value: bytes) -> bytes:
    return ber_tlv(0x04, value)


def oid_to_tuple(oid: str, *, allow_single_arc: bool = False) -> Tuple[int, ...]:
    text = oid.strip().strip(".")
    if not text:
        raise ValueError(f"Invalid OID: {oid}")

    try:
        parts = tuple(int(part) for part in text.split("."))
    except ValueError as exc:
        raise ValueError(f"Invalid OID: {oid}") from exc

    minimum_parts = 1 if allow_single_arc else 2
    if len(parts) < minimum_parts or parts[0] not in (0, 1, 2):
        raise ValueError(f"Invalid OID: {oid}")
    if len(parts) >= 2 and parts[0] < 2 and parts[1] > 39:
        raise ValueError(f"Invalid OID: {oid}")
    if any(part < 0 for part in parts):
        raise ValueError(f"Invalid OID: {oid}")
    return parts


def normalize_walk_root(oid: str) -> Tuple[str, str]:
    """Return (display_root, initial_request_oid).

    ASN.1 BER requires at least two OID arcs. A user-supplied walk root such
    as ``1`` is therefore displayed and matched as subtree ``1``, while the
    first GETNEXT request is encoded as ``1.0``.
    """
    parts = oid_to_tuple(oid, allow_single_arc=True)
    display_root = ".".join(str(part) for part in parts)
    if len(parts) == 1:
        request_oid = f"{parts[0]}.0"
    else:
        request_oid = display_root
    return display_root, request_oid


def ber_oid(oid: str) -> bytes:
    parts = oid_to_tuple(oid)
    encoded = bytearray([40 * parts[0] + parts[1]])

    for value in parts[2:]:
        chunks = [value & 0x7F]
        value >>= 7
        while value:
            chunks.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(chunks))

    return ber_tlv(0x06, bytes(encoded))


def build_getnext_request(
    community: str, oid: str, request_id: int, snmp_version: int
) -> bytes:
    varbind = ber_tlv(0x30, ber_oid(oid) + ber_tlv(0x05, b""))
    varbind_list = ber_tlv(0x30, varbind)
    pdu = ber_tlv(
        0xA1,
        ber_integer(request_id)
        + ber_integer(0)
        + ber_integer(0)
        + varbind_list,
    )
    return ber_tlv(
        0x30,
        ber_integer(snmp_version)
        + ber_octet_string(community.encode("utf-8"))
        + pdu,
    )


def read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Truncated BER length")

    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset

    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ValueError("Invalid BER length")

    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Truncated BER object")

    tag = data[offset]
    length, value_offset = read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("Truncated BER value")

    return tag, data[value_offset:end], end


def decode_integer(value: bytes, signed: bool = True) -> int:
    if not value:
        raise ValueError("Empty BER integer")
    return int.from_bytes(value, "big", signed=signed)


def decode_oid(value: bytes) -> str:
    if not value:
        raise ValueError("Empty OID")

    first = value[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]

    current = 0
    in_component = False
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        in_component = True
        if not byte & 0x80:
            parts.append(current)
            current = 0
            in_component = False

    if in_component:
        raise ValueError("Truncated OID component")

    return ".".join(str(part) for part in parts)


def decode_snmp_value(tag: int, value: bytes) -> str:
    if tag == 0x02:
        return str(decode_integer(value))
    if tag == 0x04:
        try:
            text = value.decode("utf-8")
            if text.isprintable():
                return repr(text)
        except UnicodeDecodeError:
            pass
        return "0x" + value.hex()
    if tag == 0x05:
        return "NULL"
    if tag == 0x06:
        return decode_oid(value)
    if tag == 0x40 and len(value) == 4:
        return socket.inet_ntoa(value)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(value, "big", signed=False))
    if tag == 0x44:
        try:
            return repr(value.decode("utf-8"))
        except UnicodeDecodeError:
            return "0x" + value.hex()
    if tag == 0x80:
        return "noSuchObject"
    if tag == 0x81:
        return "noSuchInstance"
    if tag == 0x82:
        return "endOfMibView"
    return f"tag=0x{tag:02x} value=0x{value.hex()}"


def parse_snmp_response(packet: bytes, expected_request_id: int) -> Tuple[str, str, int, int]:
    tag, message, end = read_tlv(packet, 0)
    if tag != 0x30 or end != len(packet):
        raise ValueError("Invalid SNMP message")

    offset = 0
    tag, version_bytes, offset = read_tlv(message, offset)
    if tag != 0x02:
        raise ValueError("Missing SNMP version")

    tag, _, offset = read_tlv(message, offset)
    if tag != 0x04:
        raise ValueError("Missing SNMP community")

    pdu_tag, pdu, offset = read_tlv(message, offset)
    if pdu_tag != 0xA2:
        raise ValueError(f"Unexpected SNMP PDU tag 0x{pdu_tag:02x}")

    pdu_offset = 0
    tag, request_id_bytes, pdu_offset = read_tlv(pdu, pdu_offset)
    if tag != 0x02:
        raise ValueError("Missing request ID")

    request_id = decode_integer(request_id_bytes)
    if request_id != expected_request_id:
        raise ValueError(
            f"SNMP request ID mismatch: expected {expected_request_id}, got {request_id}"
        )

    tag, error_status_bytes, pdu_offset = read_tlv(pdu, pdu_offset)
    if tag != 0x02:
        raise ValueError("Missing SNMP error status")
    error_status = decode_integer(error_status_bytes)

    tag, error_index_bytes, pdu_offset = read_tlv(pdu, pdu_offset)
    if tag != 0x02:
        raise ValueError("Missing SNMP error index")
    error_index = decode_integer(error_index_bytes)

    tag, varbind_list, pdu_offset = read_tlv(pdu, pdu_offset)
    if tag != 0x30:
        raise ValueError("Missing SNMP varbind list")

    tag, varbind, _ = read_tlv(varbind_list, 0)
    if tag != 0x30:
        raise ValueError("Missing SNMP varbind")

    var_offset = 0
    tag, oid_bytes, var_offset = read_tlv(varbind, var_offset)
    if tag != 0x06:
        raise ValueError("Missing response OID")
    response_oid = decode_oid(oid_bytes)

    value_tag, value_bytes, _ = read_tlv(varbind, var_offset)
    return response_oid, decode_snmp_value(value_tag, value_bytes), error_status, error_index


def oid_in_subtree(oid: str, root: str) -> bool:
    oid_parts = oid_to_tuple(oid)
    root_parts = oid_to_tuple(root, allow_single_arc=True)
    return oid_parts[:len(root_parts)] == root_parts


def open_socks_udp_association(
    proxy_host: str,
    proxy_port: int,
    timeout: float,
) -> Tuple[socket.socket, socket.socket, str, int]:
    control = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    control.settimeout(timeout)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)

    control.sendall(b"\x05\x01\x00")
    if recv_exact(control, 2) != b"\x05\x00":
        control.close()
        udp.close()
        raise RuntimeError("Proxy rejected no-auth SOCKS5 negotiation")

    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    header = recv_exact(control, 4)
    version, reply, _, atyp = struct.unpack("!BBBB", header)
    if version != 5 or reply != 0:
        control.close()
        udp.close()
        raise RuntimeError(f"UDP ASSOCIATE failed with SOCKS reply {reply}")

    relay_host = read_address(control, atyp)
    relay_port = struct.unpack("!H", recv_exact(control, 2))[0]

    if relay_host == "0.0.0.0":
        relay_host = proxy_host

    return control, udp, relay_host, relay_port



PRINT_LOCK = threading.Lock()


def safe_print(message: str, *, error: bool = False) -> None:
    with PRINT_LOCK:
        print(message, file=sys.stderr if error else sys.stdout, flush=True)


def load_targets(single_target: str | None, targets_file: str | None) -> list[str]:
    targets: list[str] = []

    if single_target:
        targets.append(single_target.strip())

    if targets_file:
        path = Path(targets_file)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"Could not read targets file {targets_file!r}: {exc}") from exc

        for line_number, line in enumerate(lines, 1):
            target = line.strip()
            if not target or target.startswith("#"):
                continue
            # Permit simple files containing either one target per line or
            # whitespace-separated target/comment text.
            target = target.split()[0]
            if target:
                targets.append(target)

    # Preserve order while removing duplicates.
    unique_targets = list(dict.fromkeys(targets))
    if not unique_targets:
        raise ValueError("Provide a target or --targets-file containing at least one target")
    return unique_targets


def walk_target(
    target: str,
    instance: int,
    args: argparse.Namespace,
    root_oid: str,
    initial_oid: str,
    snmp_version: int,
) -> dict[str, object]:
    label = target if args.sockets == 1 else f"{target}#{instance}"
    control = None
    udp = None
    current_oid = initial_oid
    result_count = 0

    try:
        control, udp, relay_host, relay_port = open_socks_udp_association(
            args.proxy_host,
            args.proxy_port,
            args.timeout,
        )

        safe_print(
            f"[{label}] START relay={relay_host}:{relay_port} "
            f"target={target}:{args.port}/udp version={args.version} oid={root_oid}"
        )

        for _ in range(args.max_results):
            request_id = random.randint(1, 0x7FFFFFFF)
            request = build_getnext_request(
                args.community,
                current_oid,
                request_id,
                snmp_version,
            )
            socks_packet = (
                b"\x00\x00\x00"
                + encode_address(target)
                + struct.pack("!H", args.port)
                + request
            )

            response_payload = None
            remote_host = ""
            remote_port = 0
            source = ("", 0)

            for attempt in range(args.retries + 1):
                udp.sendto(socks_packet, (relay_host, relay_port))
                try:
                    response, source = udp.recvfrom(65535)
                    remote_host, remote_port, response_payload = parse_socks_udp_packet(response)
                    break
                except socket.timeout:
                    if attempt >= args.retries:
                        message = (
                            f"timeout querying {current_oid} after "
                            f"{args.retries + 1} attempt(s)"
                        )
                        safe_print(f"[{label}] FAIL {message}", error=True)
                        return {
                            "target": target,
                            "instance": instance,
                            "status": "timeout",
                            "results": result_count,
                            "detail": message,
                        }

            if response_payload is None:
                return {
                    "target": target,
                    "instance": instance,
                    "status": "error",
                    "results": result_count,
                    "detail": "No response payload",
                }

            response_oid, value, error_status, error_index = parse_snmp_response(
                response_payload,
                request_id,
            )

            if error_status != 0:
                if args.version == "1" and error_status == 2:
                    safe_print(f"[{label}] DONE end-of-MIB (SNMPv1 noSuchName)")
                    return {
                        "target": target,
                        "instance": instance,
                        "status": "complete",
                        "results": result_count,
                        "detail": "SNMPv1 noSuchName",
                    }
                message = f"SNMP error status={error_status} index={error_index}"
                safe_print(f"[{label}] FAIL {message}", error=True)
                return {
                    "target": target,
                    "instance": instance,
                    "status": "snmp-error",
                    "results": result_count,
                    "detail": message,
                }

            if not oid_in_subtree(response_oid, root_oid):
                safe_print(f"[{label}] DONE end of requested subtree ({result_count} result(s))")
                return {
                    "target": target,
                    "instance": instance,
                    "status": "complete",
                    "results": result_count,
                    "detail": "End of requested subtree",
                }

            if response_oid == current_oid:
                message = f"agent repeatedly returned OID {response_oid}"
                safe_print(f"[{label}] FAIL {message}", error=True)
                return {
                    "target": target,
                    "instance": instance,
                    "status": "loop",
                    "results": result_count,
                    "detail": message,
                }

            result_count += 1
            if not args.summary_only:
                if args.raw:
                    safe_print(
                        f"[{label}] {response_oid} = {value} "
                        f"[from {remote_host}:{remote_port} via {source[0]}:{source[1]}]"
                    )
                else:
                    safe_print(f"[{label}] {response_oid} = {value}")

            if value == "endOfMibView":
                safe_print(f"[{label}] DONE end of MIB view ({result_count} result(s))")
                return {
                    "target": target,
                    "instance": instance,
                    "status": "complete",
                    "results": result_count,
                    "detail": "endOfMibView",
                }

            current_oid = response_oid

        safe_print(f"[{label}] DONE max-results reached ({result_count} result(s))")
        return {
            "target": target,
            "instance": instance,
            "status": "max-results",
            "results": result_count,
            "detail": f"Stopped at {args.max_results}",
        }

    except Exception as exc:
        safe_print(f"[{label}] FAIL {exc}", error=True)
        return {
            "target": target,
            "instance": instance,
            "status": "error",
            "results": result_count,
            "detail": str(exc),
        }
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run concurrent SNMPv1/SNMPv2c walks through CatSocks SOCKS5 UDP "
            "associations"
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Single authorized SNMP target hostname or IPv4 address",
    )
    parser.add_argument(
        "--targets-file",
        metavar="FILE",
        help="File containing one authorized target per line; blank lines and # comments ignored",
    )
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument(
        "--version",
        choices=("1", "2c"),
        default="2c",
        help="SNMP version (default: 2c)",
    )
    parser.add_argument(
        "--oid",
        default="1.3.6.1.2.1.1",
        help="OID subtree to walk (default: SNMP system group)",
    )
    parser.add_argument("--port", type=int, default=161, help="SNMP UDP port")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=1080)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries per unanswered SNMP request",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=100,
        help="Maximum returned OIDs per walk job",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Maximum concurrent walk workers (default: 4)",
    )
    parser.add_argument(
        "--sockets",
        type=int,
        default=1,
        help=(
            "Independent SOCKS5 UDP associations per target (default: 1). "
            "Total jobs = targets x sockets"
        ),
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Show relayed source information for every response",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress individual OID values and show job status only",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.max_results < 1:
        parser.error("--max-results must be at least 1")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.sockets < 1:
        parser.error("--sockets must be at least 1")

    try:
        targets = load_targets(args.target, args.targets_file)
        root_oid, initial_oid = normalize_walk_root(args.oid)
    except ValueError as exc:
        parser.error(str(exc))

    snmp_version = 0 if args.version == "1" else 1
    jobs = [
        (target, instance)
        for target in targets
        for instance in range(1, args.sockets + 1)
    ]
    worker_count = min(args.threads, len(jobs))

    safe_print(
        f"[*] Loaded {len(targets)} target(s); {len(jobs)} walk job(s); "
        f"threads={worker_count}; sockets-per-target={args.sockets}"
    )
    safe_print(
        f"[*] Proxy={args.proxy_host}:{args.proxy_port}; SNMP={args.version}; "
        f"community={args.community!r}; subtree={root_oid}"
    )

    results: list[dict[str, object]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(
                    walk_target,
                    target,
                    instance,
                    args,
                    root_oid,
                    initial_oid,
                    snmp_version,
                ): (target, instance)
                for target, instance in jobs
            }
            for future in concurrent.futures.as_completed(future_map):
                results.append(future.result())
    except KeyboardInterrupt:
        safe_print("[!] Interrupted", error=True)
        return 130

    successful_statuses = {"complete", "max-results"}
    successful = sum(1 for result in results if result["status"] in successful_statuses)
    timed_out = sum(1 for result in results if result["status"] == "timeout")
    failed = len(results) - successful - timed_out
    total_values = sum(int(result["results"]) for result in results)

    safe_print("\n=== Load-test summary ===")
    safe_print(f"Targets:          {len(targets)}")
    safe_print(f"Sockets/target:   {args.sockets}")
    safe_print(f"Total jobs:       {len(jobs)}")
    safe_print(f"Successful jobs:  {successful}")
    safe_print(f"Timed-out jobs:   {timed_out}")
    safe_print(f"Failed jobs:      {failed}")
    safe_print(f"OID values:       {total_values}")

    return 0 if successful == len(jobs) else 2


if __name__ == "__main__":
    raise SystemExit(main())
