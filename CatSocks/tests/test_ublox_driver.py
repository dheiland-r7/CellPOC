import queue
import threading
import time
import unittest

from modems.base import ModemIdentity
from modems.ublox.driver import UBloxDriver
from transport.serial_transport import ATCommandResult


class FakeTransport:
    def __init__(self):
        self.line_handler = None
        self.prompt_handler = None
        self.commands = []
        self.responses = {}
        self.unread = {}
        self.udp_unread = {}

    def set_line_handler(self, handler):
        self.line_handler = handler

    def set_prompt_handler(self, handler):
        self.prompt_handler = handler

    def execute(self, command, timeout=5):
        self.commands.append(command)

        if command == "AT+UDCONF=1,1":
            lines = ("OK",)
        elif command.startswith('AT+UDNSRN=0,'):
            lines = ('+UDNSRN: "172.67.132.115", "104.21.4.210"', "OK")
        elif command in ("AT+USOCR=6", "AT+USOCR=17"):
            used = set()
            for item in self.commands:
                match = __import__("re").search(
                    r"AT\+US(?:OCO|OST)=(\d+)",
                    item,
                )
                if match:
                    used.add(int(match.group(1)))
            socket_id = 0
            while socket_id in used:
                socket_id += 1
            lines = (f"+USOCR: {socket_id}", "OK")
        elif command.startswith("AT+USOCO="):
            lines = ("OK",)
        elif command.startswith("AT+USOWR="):
            prefix, encoded = command.rsplit(',"', 1)
            socket_id = int(prefix.split("=")[1].split(",")[0])
            length = int(prefix.split(",")[1])
            self.assert_hex_length(encoded[:-1], length)
            lines = (f"+USOWR: {socket_id},{length}", "OK")
        elif command.startswith("AT+USORD="):
            socket_id, requested = map(int, command.split("=")[1].split(","))
            payload = self.unread.get(socket_id, b"")
            if requested == 0:
                lines = (f"+USORD: {socket_id},{len(payload)}", "OK")
            else:
                if requested > 512:
                    raise RuntimeError("Operation not allowed")
                chunk = payload[:requested]
                self.unread[socket_id] = payload[len(chunk):]
                lines = (f'+USORD: {socket_id},{len(chunk)},"{chunk.hex().upper()}"', "OK")
        elif command.startswith("AT+USOST="):
            prefix, encoded = command.rsplit(',"', 1)
            params = prefix.split("=", 1)[1]
            socket_text, host_text, port_text, length_text = params.split(",")
            socket_id = int(socket_text)
            length = int(length_text)
            self.assert_hex_length(encoded[:-1], length)
            lines = (f"+USOST: {socket_id},{length}", "OK")
        elif command.startswith("AT+USORF="):
            socket_id, requested = map(int, command.split("=")[1].split(","))
            source_host, source_port, payload = self.udp_unread.get(
                socket_id,
                ("8.8.8.8", 53, b""),
            )
            chunk = payload[:requested]
            self.udp_unread[socket_id] = (
                source_host,
                source_port,
                payload[len(chunk):],
            )
            lines = (
                f'+USORF: {socket_id},"{source_host}",{source_port},'
                f'{len(chunk)},"{chunk.hex().upper()}"',
                "OK",
            )
        elif command.startswith("AT+USOCL="):
            lines = ("OK",)
        else:
            raise AssertionError(f"unexpected command {command}")

        return ATCommandResult(command, lines, 0.0, 0.01, 0.01)

    @staticmethod
    def assert_hex_length(encoded, length):
        if len(encoded) != length * 2:
            raise AssertionError("HEX payload length mismatch")


class UBloxDriverTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.driver = UBloxDriver(
            self.transport,
            ModemIdentity(
                "u-blox",
                "SARA-R410M-02B",
                "L0.0.00.00.05.08 [Apr 17 2019 19:34:02]",
            ),
        )

    def tearDown(self):
        self.driver.shutdown()

    def test_capabilities_match_sara_r4_socket_range(self):
        caps = self.driver.capabilities
        self.assertEqual(caps.max_sockets, 7)
        self.assertEqual(caps.max_active_connections, 7)
        self.assertEqual(caps.max_parallel_opens, 2)
        self.assertEqual(caps.max_tcp_chunk, 512)
        self.assertTrue(caps.supports_tcp)
        self.assertTrue(caps.supports_udp)
        self.assertEqual(caps.max_udp_payload, 512)

    def test_domain_is_resolved_before_tcp_connect(self):
        conn = self.driver.open_tcp_connection("httpforever.com", 80)
        self.assertIsNotNone(conn)
        self.assertIn('AT+UDNSRN=0,"httpforever.com"', self.transport.commands)
        self.assertIn('AT+USOCO=0,"172.67.132.115",80', self.transport.commands)
        conn.close()

    def test_literal_ipv4_bypasses_dns(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        self.assertIsNotNone(conn)
        self.assertFalse(any("UDNSRN" in cmd for cmd in self.transport.commands))
        conn.close()

    def test_tcp_send_chunks_in_binary_safe_hex_mode(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        payload = bytes(range(256)) * 3
        conn.send(payload)
        writes = [cmd for cmd in self.transport.commands if cmd.startswith("AT+USOWR=")]
        self.assertEqual(len(writes), 2)
        self.assertIn("AT+USOWR=0,512,", writes[0])
        self.assertIn("AT+USOWR=0,256,", writes[1])
        conn.close()

    def test_uusord_drains_hex_payload_to_connection_queue(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        payload = b"HTTP/1.1 200 OK\r\n\r\n" + bytes([0, 1, 2, 255])
        self.transport.unread[conn.sock_id] = payload
        self.transport.line_handler(f"+UUSORD: {conn.sock_id},{len(payload)}")
        self.assertEqual(conn.recv(timeout=1.0), payload)
        conn.close()


    def test_large_receive_uses_repeated_512_byte_reads(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        payload = bytes(range(256)) * 5  # 1280 bytes
        self.transport.unread[conn.sock_id] = payload
        self.transport.line_handler(f"+UUSORD: {conn.sock_id},{len(payload)}")

        received = bytearray()
        deadline = time.monotonic() + 1.0
        while len(received) < len(payload) and time.monotonic() < deadline:
            received.extend(conn.recv(timeout=1.0))

        self.assertEqual(bytes(received), payload)
        reads = [
            cmd for cmd in self.transport.commands
            if cmd.startswith(f"AT+USORD={conn.sock_id},") and not cmd.endswith(",0")
        ]
        self.assertEqual(reads, [
            f"AT+USORD={conn.sock_id},512",
            f"AT+USORD={conn.sock_id},512",
            f"AT+USORD={conn.sock_id},256",
        ])
        conn.close()

    def test_remote_close_queues_eof(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        self.transport.line_handler(f"+UUSOCL: {conn.sock_id}")
        self.assertIsNone(conn.recv(timeout=1.0))
        conn.close()

    def test_local_close_holds_capacity_until_uusocl(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        self.assertIsNotNone(conn)

        # Consume the six remaining physical capacity tokens so the test can
        # observe whether closing socket 0 incorrectly releases its token.
        for _ in range(6):
            self.assertTrue(self.driver._capacity.acquire(timeout=0.1))

        conn.close()
        self.assertTrue(conn.close_pending)
        self.assertFalse(conn.released)
        self.assertIs(self.driver._get(conn.sock_id), conn)

        acquired = threading.Event()

        def wait_for_capacity():
            if self.driver._capacity.acquire(timeout=1.0):
                acquired.set()

        waiter = threading.Thread(target=wait_for_capacity)
        waiter.start()
        time.sleep(0.05)
        self.assertFalse(
            acquired.is_set(),
            "capacity was released on USOCL OK instead of UUSOCL",
        )

        self.transport.line_handler(f"+UUSOCL: {conn.sock_id}")
        waiter.join(timeout=1.0)

        self.assertTrue(acquired.is_set())
        self.assertTrue(conn.released)
        self.assertIsNone(self.driver._get(conn.sock_id))

        # Return the six tokens consumed directly plus the one acquired by the
        # waiter so tearDown sees a balanced semaphore.
        for _ in range(7):
            self.driver._capacity.release()

    def test_duplicate_uusocl_does_not_double_release_capacity(self):
        conn = self.driver.open_tcp_connection("104.21.4.210", 80)
        conn.close()
        self.transport.line_handler(f"+UUSOCL: {conn.sock_id}")
        self.transport.line_handler(f"+UUSOCL: {conn.sock_id}")

        acquired = 0
        for _ in range(8):
            if self.driver._capacity.acquire(blocking=False):
                acquired += 1
        self.assertEqual(acquired, 7)
        for _ in range(acquired):
            self.driver._capacity.release()

    def test_udp_open_uses_datagram_socket_and_dns(self):
        conn = self.driver.open_udp_connection("dns.google", 53)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.protocol, "UDP")
        self.assertIn('AT+UDNSRN=0,"dns.google"', self.transport.commands)
        self.assertIn("AT+USOCR=17", self.transport.commands)
        conn.close()

    def test_udp_send_uses_usost_hex_mode(self):
        conn = self.driver.open_udp_connection("8.8.8.8", 53)
        payload = b"\x12\x34\x01\x00test"
        conn.send(payload)
        writes = [
            cmd for cmd in self.transport.commands
            if cmd.startswith("AT+USOST=")
        ]
        self.assertEqual(len(writes), 1)
        self.assertIn(
            f'AT+USOST={conn.sock_id},"8.8.8.8",53,{len(payload)},',
            writes[0],
        )
        conn.close()

    def test_uusorf_reads_complete_udp_datagram(self):
        conn = self.driver.open_udp_connection("8.8.8.8", 53)
        payload = b"DNS-RESPONSE"
        self.transport.udp_unread[conn.sock_id] = (
            "8.8.8.8",
            53,
            payload,
        )
        self.transport.line_handler(
            f"+UUSORF: {conn.sock_id},{len(payload)}"
        )
        self.assertEqual(conn.recv(timeout=1.0), payload)
        self.assertIn(
            f"AT+USORF={conn.sock_id},512",
            self.transport.commands,
        )
        conn.close()

    def test_udp_datagram_over_limit_is_rejected(self):
        conn = self.driver.open_udp_connection("8.8.8.8", 53)
        with self.assertRaises(ValueError):
            conn.send(b"A" * 513)
        conn.close()

    def test_udp_close_uses_synchronous_usocl_and_releases_immediately(self):
        conn = self.driver.open_udp_connection("8.8.8.8", 53)
        socket_id = conn.sock_id
        conn.close()

        self.assertIn(f"AT+USOCL={socket_id}", self.transport.commands)
        self.assertNotIn(f"AT+USOCL={socket_id},1", self.transport.commands)
        self.assertTrue(conn.released)
        self.assertIsNone(self.driver._get(socket_id))

    def test_repeated_udp_open_close_does_not_exhaust_capacity(self):
        for _ in range(10):
            conn = self.driver.open_udp_connection("8.8.8.8", 53)
            self.assertIsNotNone(conn)
            conn.close()
            self.assertTrue(conn.released)

        acquired = 0
        for _ in range(8):
            if self.driver._capacity.acquire(blocking=False):
                acquired += 1
        self.assertEqual(acquired, 7)
        for _ in range(acquired):
            self.driver._capacity.release()


if __name__ == "__main__":
    unittest.main()
