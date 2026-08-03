#!/usr/bin/env python3
"""CatSocks SOCKS5 UDP SNMP walk tool.

Performs an SNMPv1 or SNMPv2c GETNEXT walk through a SOCKS5 UDP
ASSOCIATE relay. Default walk root: 1.3.6.1.2.1.1 (system group).

Use only against systems you own or are authorized to assess.
"""

import argparse
import random
import socket
import struct
import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an SNMPv1/SNMPv2c walk through a CatSocks SOCKS5 UDP relay"
    )
    parser.add_argument("target", help="Authorized SNMP target hostname or IPv4 address")
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
        help="Maximum number of returned OIDs",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Show relayed source information for each response",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.max_results < 1:
        parser.error("--max-results must be at least 1")
    if args.retries < 0:
        parser.error("--retries cannot be negative")

    try:
        root_oid, current_oid = normalize_walk_root(args.oid)
    except ValueError as exc:
        parser.error(str(exc))

    snmp_version = 0 if args.version == "1" else 1

    control = udp = None
    try:
        control, udp, relay_host, relay_port = open_socks_udp_association(
            args.proxy_host,
            args.proxy_port,
            args.timeout,
        )

        print(f"[*] SOCKS5 UDP relay: {relay_host}:{relay_port}")
        print(f"[*] Target: {args.target}:{args.port}/udp")
        print(f"[*] SNMP version: {args.version}")
        print(f"[*] Community: {args.community!r}")
        print(f"[*] Walking subtree: {root_oid}")
        if root_oid != current_oid:
            print(f"[*] Initial GETNEXT request OID: {current_oid}")

        for _ in range(args.max_results):
            request_id = random.randint(1, 0x7FFFFFFF)
            request = build_getnext_request(
                args.community, current_oid, request_id, snmp_version
            )
            socks_packet = (
                b"\x00\x00\x00"
                + encode_address(args.target)
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
                        print(
                            f"[-] Timeout waiting for {args.target}:{args.port} "
                            f"while querying {current_oid}",
                            file=sys.stderr,
                        )
                        return 2

            if response_payload is None:
                return 2

            response_oid, value, error_status, error_index = parse_snmp_response(
                response_payload,
                request_id,
            )

            if error_status != 0:
                # SNMPv1 signals the end of a walk with noSuchName (2), while
                # SNMPv2c normally returns an endOfMibView exception value.
                if args.version == "1" and error_status == 2:
                    print("[*] End of MIB view (SNMPv1 noSuchName)")
                    return 0
                print(
                    f"[-] SNMP error status={error_status} index={error_index}",
                    file=sys.stderr,
                )
                return 3

            if not oid_in_subtree(response_oid, root_oid):
                print("[*] End of requested subtree")
                return 0

            if response_oid == current_oid:
                print(
                    f"[-] Agent returned the same OID repeatedly: {response_oid}",
                    file=sys.stderr,
                )
                return 4

            if args.raw:
                print(
                    f"{response_oid} = {value} "
                    f"[from {remote_host}:{remote_port} via {source[0]}:{source[1]}]"
                )
            else:
                print(f"{response_oid} = {value}")

            if value == "endOfMibView":
                print("[*] End of MIB view")
                return 0

            current_oid = response_oid

        print(f"[*] Stopped after --max-results {args.max_results}")
        return 0

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 130
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    finally:
        if udp is not None:
            udp.close()
        if control is not None:
            control.close()


if __name__ == "__main__":
    raise SystemExit(main())
