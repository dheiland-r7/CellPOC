import contextlib
import queue
import unittest

from modems.base import ModemIdentity
from modems.cinterion.driver import CinterionDriver
from transport.serial_transport import ATCommandResult


class FakeTransport:
    def __init__(self):
        self.line_handler = None
        self.prompt_handler = None
        self.commands = []
        self.raw_writes = []
        self.pending_payload_len = 0
        self.pending_profile = None

    def set_line_handler(self, handler):
        self.line_handler = handler

    def set_prompt_handler(self, handler):
        self.prompt_handler = handler

    def execute(self, cmd, timeout=5):
        self.commands.append(cmd)
        if cmd.startswith('AT^SISI='):
            profile = int(cmd.split('=')[1])
            return ATCommandResult(cmd, (f'^SISI: {profile},4,0,0,0,0', 'OK'), 0, 0, 0)
        if cmd.startswith('AT^SISO='):
            profile = int(cmd.split('=')[1])
            if self.line_handler:
                self.line_handler(f'^SISW: {profile},1')
        if cmd.startswith('AT^SISR='):
            profile = int(cmd.split('=')[1].split(',')[0])
            # no data by default
            return ATCommandResult(cmd, (f'^SISR: {profile},0', 'OK'), 0, 0, 0)
        return ATCommandResult(cmd, ('OK',), 0, 0, 0)

    @contextlib.contextmanager
    def exclusive_transaction(self):
        yield

    def write_raw(self, data):
        self.raw_writes.append(data)
        if data.startswith(b'AT^SISW='):
            text = data.decode().strip()
            profile, length = text.split('=')[1].split(',')[:2]
            self.pending_profile = int(profile)
            self.pending_payload_len = int(length)
            if self.line_handler:
                self.line_handler(f'^SISW: {profile},{length},0')
        elif self.pending_payload_len:
            self.assert_payload(data)
            if self.line_handler:
                self.line_handler('OK')
            self.pending_payload_len = 0
        return len(data)

    def assert_payload(self, data):
        if len(data) > self.pending_payload_len:
            raise AssertionError('payload too large')

    def read_exact(self, length):
        return b'x' * length


class CinterionDriverTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.driver = CinterionDriver(
            self.transport,
            ModemIdentity('Cinterion', 'PLS83-W', 'REVISION 01.202'),
        )

    def test_uses_nine_profiles(self):
        self.assertEqual(self.driver.capabilities.max_sockets, 9)
        self.assertEqual(self.driver.capabilities.max_active_connections, 9)
        self.assertTrue(self.driver.capabilities.supports_tcp)
        self.assertTrue(self.driver.capabilities.supports_udp)
        self.assertEqual(self.driver.capabilities.max_udp_payload, 1024)

    def test_opens_multiple_profiles_without_transparent_mode(self):
        conns = [self.driver.open_tcp_connection(f'host{i}.example', 80) for i in range(3)]
        self.assertEqual([c.profile_id for c in conns], [0, 1, 2])
        self.assertFalse(any('SIST' in cmd for cmd in self.transport.commands))
        for conn in conns:
            conn.close()

    def test_send_uses_sisw_and_raw_payload(self):
        conn = self.driver.open_tcp_connection('example.com', 80)
        conn.send(b'hello')
        self.assertIn(b'AT^SISW=0,5\r', self.transport.raw_writes)
        self.assertIn(b'hello', self.transport.raw_writes)
        conn.close()

    def test_sisr_urc_schedules_payload_read(self):
        conn = self.driver.open_tcp_connection('example.com', 80)
        # Simulate the command-response side directly: mark read in flight then
        # deliver a confirmed-length line; line handler must consume exact bytes.
        conn.read_scheduled = True
        self.driver._handle_line('^SISR: 0,4')
        self.assertEqual(conn.recv_q.get_nowait(), b'xxxx')
        conn.close()


    def test_udp_open_uses_profile_and_sockudp(self):
        conn = self.driver.open_udp_connection('8.8.8.8', 53)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.protocol, 'UDP')
        self.assertEqual(conn.profile_id, 0)
        self.assertIn('AT^SISS=0,"address","sockudp://8.8.8.8:53"', self.transport.commands)
        self.assertFalse(any('SIST' in cmd for cmd in self.transport.commands))
        conn.close()

    def test_udp_send_is_one_sisw_datagram(self):
        conn = self.driver.open_udp_connection('8.8.8.8', 53)
        conn.send(b'123456789')
        self.assertIn(b'AT^SISW=0,9\r', self.transport.raw_writes)
        self.assertIn(b'123456789', self.transport.raw_writes)
        conn.close()

    def test_udp_reassembles_sisr_fragments(self):
        conn = self.driver.open_udp_connection('8.8.8.8', 53)
        conn.read_scheduled = True
        self.driver._handle_line('^SISR: 0,6,4')
        self.assertTrue(conn.recv_q.empty())
        self.driver._handle_line('^SISR: 0,4,0')
        self.assertEqual(conn.recv_q.get_nowait(), b'xxxxxxxxxx')
        conn.close()

    def test_udp_complete_small_datagram_without_remaining_field(self):
        conn = self.driver.open_udp_connection('8.8.8.8', 53)
        conn.read_scheduled = True
        self.driver._handle_line('^SISR: 0,4')
        self.assertEqual(conn.recv_q.get_nowait(), b'xxxx')
        conn.close()

    def test_tcp_and_udp_allocate_distinct_profiles(self):
        tcp = self.driver.open_tcp_connection('example.com', 80)
        udp = self.driver.open_udp_connection('8.8.8.8', 53)
        self.assertEqual(tcp.profile_id, 0)
        self.assertEqual(udp.profile_id, 1)
        tcp.close()
        udp.close()

    def test_close_releases_profile(self):
        conn = self.driver.open_tcp_connection('example.com', 80)
        self.assertEqual(conn.profile_id, 0)
        conn.close()
        self.assertIn(0, self.driver.profile_pool.snapshot())


if __name__ == '__main__':
    unittest.main()
