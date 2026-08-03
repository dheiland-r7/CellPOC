#!/usr/bin/env python3
"""Minimal SOCKS5 UDP ASSOCIATE DNS test for CatSocks CS07 builds."""

import argparse
import random
import socket
import struct


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("SOCKS control connection closed")
        data += chunk
    return data


def read_address(sock, atyp):
    if atyp == 1:
        return socket.inet_ntoa(recv_exact(sock, 4))
    if atyp == 3:
        length = recv_exact(sock, 1)[0]
        return recv_exact(sock, length).decode("idna")
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    raise ValueError(f"Unsupported ATYP {atyp}")


def encode_address(host):
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        encoded = host.encode("idna")
        return b"\x03" + bytes([len(encoded)]) + encoded


def encode_dns_name(name):
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def build_dns_query(name):
    transaction_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", 1, 1)
    return transaction_id, header + question


def skip_dns_name(packet, offset):
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def extract_ipv4_answers(packet, transaction_id):
    if len(packet) < 12:
        raise ValueError("Truncated DNS response")
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != transaction_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise ValueError("Packet is not a DNS response")

    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(packet, offset) + 4

    addresses = []
    for _ in range(ancount):
        offset = skip_dns_name(packet, offset)
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(rdata))
    return addresses


def main():
    parser = argparse.ArgumentParser(description="Test CatSocks SOCKS5 UDP DNS relay")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=1080)
    parser.add_argument("--dns-server", default="8.8.8.8")
    parser.add_argument("--name", default="example.com")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    control = socket.create_connection((args.proxy_host, args.proxy_port), timeout=args.timeout)
    control.settimeout(args.timeout)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(args.timeout)

    try:
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("Proxy rejected no-auth SOCKS5 negotiation")

        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        header = recv_exact(control, 4)
        version, reply, _, atyp = struct.unpack("!BBBB", header)
        if version != 5 or reply != 0:
            raise RuntimeError(f"UDP ASSOCIATE failed with SOCKS reply {reply}")
        relay_host = read_address(control, atyp)
        relay_port = struct.unpack("!H", recv_exact(control, 2))[0]
        if relay_host == "0.0.0.0":
            relay_host = args.proxy_host

        transaction_id, dns_query = build_dns_query(args.name)
        socks_packet = b"\x00\x00\x00" + encode_address(args.dns_server) + struct.pack("!H", 53) + dns_query

        print(f"[*] UDP relay: {relay_host}:{relay_port}")
        print(f"[*] Querying {args.name} through {args.dns_server}:53")
        udp.sendto(socks_packet, (relay_host, relay_port))

        response, source = udp.recvfrom(65535)
        if response[:3] != b"\x00\x00\x00":
            raise RuntimeError("Invalid SOCKS5 UDP response header")

        atyp = response[3]
        offset = 4
        if atyp == 1:
            remote_host = socket.inet_ntoa(response[offset:offset + 4]); offset += 4
        elif atyp == 3:
            length = response[offset]; offset += 1
            remote_host = response[offset:offset + length].decode("idna"); offset += length
        elif atyp == 4:
            remote_host = socket.inet_ntop(socket.AF_INET6, response[offset:offset + 16]); offset += 16
        else:
            raise RuntimeError(f"Unsupported response ATYP {atyp}")
        remote_port = struct.unpack("!H", response[offset:offset + 2])[0]
        dns_response = response[offset + 2:]
        answers = extract_ipv4_answers(dns_response, transaction_id)

        print(f"[+] Response relayed from {remote_host}:{remote_port} via {source[0]}:{source[1]}")
        if answers:
            print("[+] IPv4 answers: " + ", ".join(answers))
        else:
            print("[+] Valid DNS response received; no IPv4 A answers found")
    finally:
        udp.close()
        control.close()


if __name__ == "__main__":
    main()
