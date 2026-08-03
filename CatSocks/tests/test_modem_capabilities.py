import unittest

from config import MAX_ACTIVE_CLIENTS
from modems.base import ModemIdentity
from modems.cinterion.driver import CinterionDriver
from modems.quectel.driver import QuectelDriver


class MinimalTransport:
    def __init__(self):
        self.line_handler = None
        self.prompt_handler = None

    def set_line_handler(self, handler):
        self.line_handler = handler

    def set_prompt_handler(self, handler):
        self.prompt_handler = handler

    def execute(self, cmd, timeout=5):
        class Result:
            text = "OK"
            lines = ("OK",)
        return Result()


class CapabilityTests(unittest.TestCase):
    def test_global_client_limit_is_ten(self):
        self.assertEqual(MAX_ACTIVE_CLIENTS, 10)

    def test_quectel_limits_are_driver_specific(self):
        driver = QuectelDriver(
            MinimalTransport(),
            ModemIdentity("Quectel", "BG96", "BG96MAR04A03M1G"),
        )
        self.assertEqual(driver.capabilities.max_sockets, 10)
        self.assertEqual(driver.capabilities.max_active_connections, 10)
        self.assertEqual(driver.capabilities.max_parallel_opens, 2)

    def test_cinterion_limits_are_driver_specific(self):
        driver = CinterionDriver(
            MinimalTransport(),
            ModemIdentity("Cinterion", "PLS83-W", "REVISION 01.202"),
        )
        self.assertEqual(driver.capabilities.max_sockets, 9)
        self.assertEqual(driver.capabilities.max_active_connections, 9)
        self.assertEqual(driver.capabilities.max_parallel_opens, 2)

    def test_vendor_settings_are_not_in_root_config(self):
        import config
        vendor_prefixes = ("CINTERION_", "QUECTEL_", "UBLOX_")
        leaked = [
            name for name in vars(config)
            if name.startswith(vendor_prefixes)
        ]
        self.assertEqual(leaked, [])

    def test_only_ublox_has_tcp_idle_timeout(self):
        q = QuectelDriver(
            MinimalTransport(),
            ModemIdentity("Quectel", "BG96", "BG96MAR04A03M1G"),
        )
        c = CinterionDriver(
            MinimalTransport(),
            ModemIdentity("Cinterion", "PLS83-W", "REVISION 01.202"),
        )
        from modems.ublox.driver import UBloxDriver
        u = UBloxDriver(
            MinimalTransport(),
            ModemIdentity(
                "u-blox",
                "SARA-R410M-02B",
                "L0.0.00.00.05.08 [Apr 17 2019 19:34:02]",
            ),
        )
        self.assertIsNone(q.capabilities.tcp_idle_timeout)
        self.assertIsNone(c.capabilities.tcp_idle_timeout)
        self.assertEqual(u.capabilities.tcp_idle_timeout, 10.0)


if __name__ == "__main__":
    unittest.main()
