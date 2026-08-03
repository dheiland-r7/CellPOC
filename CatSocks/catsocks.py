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
#tested on Quectel, Cinterion, and u-blox modules. #
#                                                  #
#              Deral Heiland 2026                  #
#   Code was created with assistance from AI       #
#               Version 0.11.07		           #
####################################################
# Filename: catsocks.py
# Vendor-neutral SOCKS5 core for CatSocks V0.11.07.
#
# Startup flow:
#   1. Open the shared serial AT transport.
#   2. Establish readiness with a generic AT/OK probe.
#   3. Query 3GPP identity using CGMI, CGMM, and CGMR.
#   4. Auto-discover and select an installed modem driver.
#   5. Start the unchanged TCP/UDP SOCKS5 service.
#
# Vendor-specific AT commands and URC parsing must remain inside the selected
# package under modems/<vendor>/. The core application does not know how a
# modem implements socket open, send, receive, or close operations.
#
# CGSN is intentionally not queried during discovery because driver selection
# does not require an IMEI or other unique equipment identifier.

import argparse
import socket
import struct
import threading
import time
import select
import queue
import sys
import logging

# ==== Configuration ==========================================================
from config import (
    APP_VERSION,
    AT_PROBE_INTERVAL,
    AT_PROBE_TIMEOUT,
    BAUD_RATE,
    CMD_TIMEOUT,
    DEBUG,
    LISTEN_ADDR,
    MAX_ACTIVE_CLIENTS,
    MAX_UDP_FLOWS,
    MAX_UDP_PAYLOAD,
    MODEM_STARTUP_TIMEOUT,
    SERIAL_PORT,
    UDP_IDLE_TIMEOUT,
    UDP_POLL_INTERVAL,
)
from modems.base import CellularModemDriver
from modems.discovery import identify_modem, wait_until_responsive
from modems.registry import DriverRegistry
from transport.serial_transport import SerialATTransport
from core.terminal import green, red

# SOCKS5 canned replies (IPv4 0.0.0.0:0 bound address in response)
SOCKS_GENERAL_FAIL = b"\x05\x01\x00\x01" + b"\x00"*6
SOCKS_CMD_NOT_SUP  = b"\x05\x07\x00\x01" + b"\x00"*6
SOCKS_ADDR_NOT_SUP = b"\x05\x08\x00\x01" + b"\x00"*6
SOCKS_SUCCEEDED    = b"\x05\x00\x00\x01" + b"\x00"*6

SOCKS_CMD_CONNECT       = 0x01
SOCKS_CMD_UDP_ASSOCIATE = 0x03

# ==== Logging ================================================================
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)


# ==== Internal helpers / data structures ====================================



# ==== SOCKS5 handling ========================================================

def _socks_read_exact(sock, n):
    """Read exactly n bytes from a blocking TCP socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("SOCKS peer closed")
        buf += chunk
    return buf


def _read_socks_address(sock, atyp):
    if atyp == 1:
        return socket.inet_ntoa(_socks_read_exact(sock, 4))
    if atyp == 3:
        length = _socks_read_exact(sock, 1)[0]
        return _socks_read_exact(sock, length).decode("idna")
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, _socks_read_exact(sock, 16))
    raise ValueError("Unsupported SOCKS address type")


def _encode_socks_address(host):
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        pass

    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ValueError("SOCKS domain name too long")
        return b"\x03" + bytes([len(encoded)]) + encoded


def _socks_reply(rep, bind_host="0.0.0.0", bind_port=0):
    return b"\x05" + bytes([rep]) + b"\x00" + _encode_socks_address(bind_host) + struct.pack("!H", bind_port)


def _parse_udp_packet(packet):
    if len(packet) < 4:
        raise ValueError("UDP packet too short")
    if packet[:2] != b"\x00\x00":
        raise ValueError("Invalid SOCKS UDP reserved field")
    if packet[2] != 0:
        raise NotImplementedError("SOCKS UDP fragmentation is not supported")

    atyp = packet[3]
    offset = 4
    if atyp == 1:
        if len(packet) < offset + 4 + 2:
            raise ValueError("Truncated IPv4 UDP header")
        host = socket.inet_ntoa(packet[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        if len(packet) < offset + 1:
            raise ValueError("Truncated domain UDP header")
        length = packet[offset]
        offset += 1
        if len(packet) < offset + length + 2:
            raise ValueError("Truncated domain UDP header")
        host = packet[offset:offset + length].decode("idna")
        offset += length
    elif atyp == 4:
        if len(packet) < offset + 16 + 2:
            raise ValueError("Truncated IPv6 UDP header")
        host = socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16])
        offset += 16
    else:
        raise ValueError("Unsupported UDP destination address type")

    port = struct.unpack("!H", packet[offset:offset + 2])[0]
    return host, port, packet[offset + 2:]


def _build_udp_packet(host, port, payload):
    return b"\x00\x00\x00" + _encode_socks_address(host) + struct.pack("!H", port) + payload


def _handle_tcp_connect(client_sock, modem, host, port):
    conn = modem.open_tcp_connection(host, port)
    if not conn:
        client_sock.sendall(SOCKS_GENERAL_FAIL)
        return

    try:
        client_sock.sendall(SOCKS_SUCCEEDED)
        client_sock.setblocking(False)
        last_activity = time.monotonic()
        idle_timeout = modem.capabilities.tcp_idle_timeout
        tcp_chunk = modem.capabilities.max_tcp_chunk

        while True:
            r, _, _ = select.select([client_sock], [], [], 0.02)
            if client_sock in r:
                data = client_sock.recv(4096)
                if not data:
                    break
                last_activity = time.monotonic()
                off = 0
                while off < len(data):
                    chunk = data[off:off + tcp_chunk]
                    off += len(chunk)
                    conn.send(chunk)

            try:
                payload = conn.recv(timeout=0.02)
            except queue.Empty:
                payload = b""
            if payload is None:
                break
            if payload:
                last_activity = time.monotonic()
                client_sock.sendall(payload)

            if (
                idle_timeout is not None
                and time.monotonic() - last_activity >= idle_timeout
            ):
                logging.info(
                    "[TCP] Idle timeout %.1fs for %s:%s",
                    idle_timeout,
                    host,
                    port,
                )
                break
    finally:
        conn.close()


def _handle_udp_associate(client_sock, modem, client_addr):
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flows = {}
    client_udp_addr = None

    try:
        local_ip = client_sock.getsockname()[0]
        bind_ip = local_ip if local_ip not in ("0.0.0.0", "::") else "0.0.0.0"
        relay.bind((bind_ip, 0))
        relay.setblocking(False)
        relay_port = relay.getsockname()[1]

        reply_ip = local_ip
        if reply_ip in ("0.0.0.0", "::"):
            reply_ip = "127.0.0.1"

        client_sock.sendall(_socks_reply(0x00, reply_ip, relay_port))
        client_sock.setblocking(False)
        logging.info(f"UDP ASSOCIATE relay={reply_ip}:{relay_port} client={client_addr[0]}")

        while True:
            now = time.monotonic()
            readable, _, _ = select.select([client_sock, relay], [], [], UDP_POLL_INTERVAL)

            if client_sock in readable:
                control = client_sock.recv(1)
                if not control:
                    break
                logging.debug("[UDP] Ignoring unexpected data on control connection")

            if relay in readable:
                packet, source = relay.recvfrom(65535)
                if source[0] != client_addr[0]:
                    logging.warning(f"[UDP] Dropping datagram from unexpected host {source}")
                    continue
                if client_udp_addr is None:
                    client_udp_addr = source
                    logging.info(f"[UDP] Client relay endpoint learned as {source}")
                elif source != client_udp_addr:
                    logging.warning(f"[UDP] Dropping datagram from unexpected endpoint {source}")
                    continue

                try:
                    host, port, payload = _parse_udp_packet(packet)
                except NotImplementedError as exc:
                    logging.warning(f"[UDP] {exc}")
                    continue
                except Exception as exc:
                    logging.debug(f"[UDP] Invalid SOCKS datagram: {exc}")
                    continue

                if len(payload) > MAX_UDP_PAYLOAD:
                    logging.warning(f"[UDP] Dropping {len(payload)}-byte datagram; max={MAX_UDP_PAYLOAD}")
                    continue

                key = (host, port)
                flow = flows.get(key)
                if flow is None:
                    if len(flows) >= MAX_UDP_FLOWS:
                        expired_key = min(flows, key=lambda item: flows[item]["last_used"])
                        expired = flows.pop(expired_key)
                        logging.info(f"[UDP] Evicting flow {expired_key[0]}:{expired_key[1]}")
                        expired["conn"].close()

                    conn = modem.open_udp_connection(host, port)
                    if not conn:
                        logging.warning(f"[UDP] Could not open modem flow {host}:{port}")
                        continue
                    flow = {"conn": conn, "last_used": now}
                    flows[key] = flow
                    logging.info(f"[UDP] New flow SID={conn.sock_id} {host}:{port}")

                flow["last_used"] = now
                try:
                    flow["conn"].send(payload)
                except Exception as exc:
                    logging.warning(f"[UDP] Send failed for {host}:{port}: {exc}")
                    flow["conn"].close()
                    flows.pop(key, None)

            for key, flow in list(flows.items()):
                conn = flow["conn"]
                while True:
                    try:
                        payload = conn.recv_q.get_nowait()
                    except queue.Empty:
                        break
                    if payload is None:
                        conn.close()
                        flows.pop(key, None)
                        break
                    if client_udp_addr is not None:
                        relay.sendto(_build_udp_packet(key[0], key[1], payload), client_udp_addr)
                        flow["last_used"] = now
                        logging.debug(f"[UDP] RX {len(payload)} bytes from {key[0]}:{key[1]}")

                if key in flows and now - flow["last_used"] >= UDP_IDLE_TIMEOUT:
                    logging.info(f"[UDP] Idle timeout {key[0]}:{key[1]}")
                    conn.close()
                    flows.pop(key, None)
    finally:
        for flow in list(flows.values()):
            try:
                flow["conn"].close()
            except Exception:
                pass
        relay.close()


def handle_client(client_sock, modem: CellularModemDriver, client_gate):
    """Negotiate SOCKS5 while respecting the cellular concurrency limit."""
    gate_wait_started = time.monotonic()
    client_gate.acquire()
    gate_wait = time.monotonic() - gate_wait_started
    if gate_wait >= 0.01:
        logging.debug("[SOCKS] client waited %.3fs for concurrency slot", gate_wait)
    try:
        client_addr = client_sock.getpeername()
        head = _socks_read_exact(client_sock, 2)
        ver, nmethods = struct.unpack("!BB", head)
        if ver != 5:
            return
        methods = _socks_read_exact(client_sock, nmethods)
        if 0x00 not in methods:
            client_sock.sendall(b"\x05\xff")
            return
        client_sock.sendall(b"\x05\x00")

        hdr = _socks_read_exact(client_sock, 4)
        ver, cmd, reserved, atyp = struct.unpack("!BBBB", hdr)
        if ver != 5 or reserved != 0:
            client_sock.sendall(SOCKS_GENERAL_FAIL)
            return

        try:
            host = _read_socks_address(client_sock, atyp)
        except ValueError:
            client_sock.sendall(SOCKS_ADDR_NOT_SUP)
            return
        port = struct.unpack("!H", _socks_read_exact(client_sock, 2))[0]

        if cmd == SOCKS_CMD_CONNECT:
            logging.info(f"CONNECT {host}:{port}")
            _handle_tcp_connect(client_sock, modem, host, port)
        elif cmd == SOCKS_CMD_UDP_ASSOCIATE:
            if not modem.capabilities.supports_udp:
                logging.info("UDP ASSOCIATE rejected: selected modem driver is TCP-only")
                client_sock.sendall(SOCKS_CMD_NOT_SUP)
                return
            logging.info(f"UDP ASSOCIATE request hint={host}:{port}")
            _handle_udp_associate(client_sock, modem, client_addr)
        else:
            client_sock.sendall(SOCKS_CMD_NOT_SUP)
    except Exception as exc:
        logging.debug(f"[SOCKS] client handler error: {exc}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        client_gate.release()


# ==== Main entry =============================================================

def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Route SOCKS5 TCP/UDP traffic through a supported cellular modem AT interface."
    )
    parser.add_argument(
        "--serial",
        default=SERIAL_PORT,
        metavar="DEVICE",
        help=f"AT serial device (default: {SERIAL_PORT})",
    )
    return parser.parse_args(argv)


def main(argv=None):
    """Discover the modem, load its driver, and start the SOCKS5 service."""
    args = _parse_args(argv)
    logging.info("CatSocks V%s", APP_VERSION)
    logging.info("Serial interface: %s", args.serial)
    transport = SerialATTransport(args.serial, BAUD_RATE)
    driver = None
    srv = None
    try:
        wait_until_responsive(
            transport,
            startup_timeout=MODEM_STARTUP_TIMEOUT,
            probe_timeout=AT_PROBE_TIMEOUT,
            probe_interval=AT_PROBE_INTERVAL,
        )
        transport.execute("ATE0", timeout=CMD_TIMEOUT)

        identity = identify_modem(transport, timeout=CMD_TIMEOUT)
        logging.info("Detected cellular device:")
        logging.info(green(f"  Manufacturer: {identity.manufacturer or 'Unknown'}"))
        logging.info(green(f"  Model: {identity.model or 'Unknown'}"))
        logging.info(green(f"  Firmware: {identity.revision or 'Unknown'}"))

        registry = DriverRegistry.discover()
        match = registry.select(identity)
        if match is None:
            logging.error("This cellular device is not currently supported.")
            if registry.drivers:
                logging.error(
                    "Installed drivers: %s",
                    ", ".join(info.display_name for info, _ in registry.drivers),
                )
            return 2

        info, driver_class = match
        logging.info("Selected modem driver: %s v%s", info.display_name, info.driver_version)
        tested = info.tested_match(identity)
        if tested is not None:
            logging.info("Compatibility: tested module (%s)", tested.status)
        else:
            warning = (
                f"WARNING: {identity.manufacturer or 'Unknown'} "
                f"{identity.model or 'Unknown'} "
                f"{identity.revision or 'Unknown'} has not been hardware validated "
                "with this CatSocks driver. Attempting vendor-compatible operation."
            )
            logging.warning(red(warning))

        driver = driver_class(transport, identity)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(LISTEN_ADDR)
        srv.listen(64)

        driver_active_limit = (
            driver.capabilities.max_active_connections
            or driver.capabilities.max_sockets
        )
        active_client_limit = min(MAX_ACTIVE_CLIENTS, driver_active_limit)
        client_gate = threading.BoundedSemaphore(active_client_limit)
        protocols = ["TCP"]
        if driver.capabilities.supports_udp:
            protocols.append("UDP")
        logging.info(
            f"CatSocks V{APP_VERSION} proxy listening on {LISTEN_ADDR[0]}:{LISTEN_ADDR[1]} "
            f"(protocols={'+'.join(protocols)}, max_sockets={driver.capabilities.max_sockets}, "
            f"parallel_opens={driver.capabilities.max_parallel_opens}, "
            f"active_clients={active_client_limit})"
        )

        while True:
            client, addr = srv.accept()
            logging.info(f"Client from {addr}")
            threading.Thread(
                target=handle_client,
                args=(client, driver, client_gate),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        logging.info("Shutting down CatSocks")
        return 0
    finally:
        if srv is not None:
            srv.close()
        if driver is not None:
            driver.shutdown()
        transport.close()


if __name__ == "__main__":
    sys.exit(main() or 0)

