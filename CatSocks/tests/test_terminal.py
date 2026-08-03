import os
import unittest
from unittest.mock import patch

from core.terminal import ANSI_GREEN, ANSI_RED, ANSI_RESET, green, red


class FakeStream:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


class TerminalColorTests(unittest.TestCase):
    def test_green_on_tty(self):
        value = green("Manufacturer: Quectel", stream=FakeStream(True))
        self.assertEqual(value, f"{ANSI_GREEN}Manufacturer: Quectel{ANSI_RESET}")


    def test_red_on_tty(self):
        value = red("WARNING: untested model", stream=FakeStream(True))
        self.assertEqual(value, f"{ANSI_RED}WARNING: untested model{ANSI_RESET}")

    def test_red_plain_when_redirected(self):
        self.assertEqual(
            red("WARNING: untested model", stream=FakeStream(False)),
            "WARNING: untested model",
        )

    def test_plain_when_redirected(self):
        self.assertEqual(
            green("Manufacturer: Quectel", stream=FakeStream(False)),
            "Manufacturer: Quectel",
        )

    def test_no_color_environment_variable(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(
                green("Manufacturer: Quectel", stream=FakeStream(True)),
                "Manufacturer: Quectel",
            )


if __name__ == "__main__":
    unittest.main()
