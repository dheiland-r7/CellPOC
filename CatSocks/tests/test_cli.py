import unittest

import catsocks


class CLITests(unittest.TestCase):
    def test_default_serial_port(self):
        self.assertEqual(catsocks._parse_args([]).serial, "/dev/ttyUSB0")

    def test_serial_override(self):
        self.assertEqual(
            catsocks._parse_args(["--serial", "/dev/ttyUSB2"]).serial,
            "/dev/ttyUSB2",
        )


if __name__ == "__main__":
    unittest.main()
