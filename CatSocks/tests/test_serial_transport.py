import queue
import threading
import time
import unittest

from transport.serial_transport import SerialATTransport, _redact_at_payload


class FakeSerial:
    def __init__(self, *_args, **_kwargs):
        self.rx = queue.Queue()
        self.writes = []
        self.closed = False
        self.write_lock = threading.Lock()

    def read(self, size=1):
        if self.closed:
            return b""
        try:
            first = self.rx.get(timeout=0.05)
        except queue.Empty:
            return b""
        data = bytearray(first)
        while len(data) < size:
            try:
                data.extend(self.rx.get_nowait())
            except queue.Empty:
                break
        if len(data) > size:
            remainder = bytes(data[size:])
            for byte in reversed(remainder):
                self.rx.queue.appendleft(bytes([byte]))
            data = data[:size]
        return bytes(data)

    def write(self, data):
        with self.write_lock:
            self.writes.append(data)
        return len(data)

    def close(self):
        self.closed = True

    def inject(self, data):
        for byte in data:
            self.rx.put(bytes([byte]))


class SerialATTransportTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeSerial()
        self.lines = []
        self.prompts = 0

        def prompt_handler():
            self.prompts += 1

        self.transport = SerialATTransport(
            "fake",
            115200,
            line_handler=self.lines.append,
            prompt_handler=prompt_handler,
            serial_factory=lambda *_args, **_kwargs: self.fake,
        )

    def tearDown(self):
        self.transport.close()

    def test_execute_returns_ok_and_dispatches_lines(self):
        def responder():
            while not self.fake.writes:
                time.sleep(0.001)
            self.fake.inject(b"\r\nOK\r\n")

        threading.Thread(target=responder, daemon=True).start()
        result = self.transport.execute("AT", timeout=1)

        self.assertEqual(self.fake.writes, [b"AT\r"])
        self.assertEqual(result.lines, ("", "OK"))
        self.assertEqual(self.lines, ["", "OK"])

    def test_urc_is_dispatched_while_command_waits(self):
        def responder():
            while not self.fake.writes:
                time.sleep(0.001)
            self.fake.inject(b'+QIOPEN: 3,0\r\nOK\r\n')

        threading.Thread(target=responder, daemon=True).start()
        result = self.transport.execute("AT+TEST", timeout=1)

        self.assertIn("+QIOPEN: 3,0", result.lines)
        self.assertIn("+QIOPEN: 3,0", self.lines)

    def test_prompt_callback_and_raw_write(self):
        self.fake.inject(b">")
        deadline = time.monotonic() + 1
        while self.prompts == 0 and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(self.prompts, 1)

        self.transport.write_raw(b"payload\x1a")
        self.assertIn(b"payload\x1a", self.fake.writes)


    def test_ublox_hex_payloads_are_redacted_for_logs(self):
        command = 'AT+USOWR=0,4,"41424344"'
        response = '+USORD: 0,4,"41424344"'
        self.assertEqual(
            _redact_at_payload(command),
            'AT+USOWR=0,4,"<8 hex chars omitted>"',
        )
        self.assertEqual(
            _redact_at_payload(response),
            '+USORD: 0,4,"<8 hex chars omitted>"',
        )

    def test_non_payload_at_lines_are_unchanged(self):
        self.assertEqual(_redact_at_payload('AT+USORD=0,512'), 'AT+USORD=0,512')
        self.assertEqual(_redact_at_payload('+UUSORD: 0,512'), '+UUSORD: 0,512')

    def test_commands_are_serialized(self):
        results = []

        def run(cmd):
            results.append(self.transport.execute(cmd, timeout=1).command)

        first = threading.Thread(target=run, args=("AT+ONE",))
        second = threading.Thread(target=run, args=("AT+TWO",))
        first.start()
        second.start()

        deadline = time.monotonic() + 1
        while len(self.fake.writes) < 1 and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(self.fake.writes, [b"AT+ONE\r"])

        self.fake.inject(b"OK\r\n")
        deadline = time.monotonic() + 1
        while len(self.fake.writes) < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(self.fake.writes[1], b"AT+TWO\r")
        self.fake.inject(b"OK\r\n")

        first.join(1)
        second.join(1)
        self.assertEqual(results, ["AT+ONE", "AT+TWO"])


if __name__ == "__main__":
    unittest.main()
