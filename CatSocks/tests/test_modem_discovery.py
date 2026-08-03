import unittest

from modems.base import DriverInfo, ModemIdentity, TestedModule
from modems.discovery import identify_modem
from modems.registry import DriverRegistry
from transport.serial_transport import ATCommandResult


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def execute(self, command, timeout=5):
        self.commands.append(command)
        value = self.responses[command]
        if isinstance(value, Exception):
            raise value
        return ATCommandResult(command, tuple(value), 0.0, 0.01, 0.01)


class ModemDiscoveryTests(unittest.TestCase):
    def test_queries_standard_identity_without_imei(self):
        transport = FakeTransport({
            "AT+CGMI": ["Quectel", "OK"],
            "AT+CGMM": ["EG91", "OK"],
            "AT+CGMR": ["EG91NAXGAR08A09M1G", "OK"],
        })
        identity = identify_modem(transport)
        self.assertEqual(identity.manufacturer, "Quectel")
        self.assertEqual(identity.model, "EG91")
        self.assertEqual(identity.revision, "EG91NAXGAR08A09M1G")
        self.assertEqual(transport.commands, ["AT+CGMI", "AT+CGMM", "AT+CGMR"])
        self.assertNotIn("AT+CGSN", transport.commands)

    def test_reads_pls83_identity(self):
        transport = FakeTransport({
            "AT+CGMI": ["Cinterion", "OK"],
            "AT+CGMM": ["PLS83-W", "OK"],
            "AT+CGMR": ["REVISION 01.202", "OK"],
        })
        identity = identify_modem(transport)
        self.assertEqual(identity.manufacturer, "Cinterion")
        self.assertEqual(identity.model, "PLS83-W")
        self.assertEqual(identity.revision, "REVISION 01.202")

    def test_failed_identity_field_is_reported_as_unknown_value(self):
        transport = FakeTransport({
            "AT+CGMI": ["Quectel", "OK"],
            "AT+CGMM": IOError("unsupported"),
            "AT+CGMR": ["REV1", "OK"],
        })
        identity = identify_modem(transport)
        self.assertEqual(identity.model, "")


class DriverRegistryTests(unittest.TestCase):
    def test_selects_matching_vendor_driver(self):
        info = DriverInfo(
            driver_id="quectel",
            display_name="Quectel",
            driver_version="1.0",
            manufacturer_patterns=(r"\bquectel\b",),
            tested_modules=(TestedModule("EG91-NAXD"),),
        )
        driver_class = type("FakeDriver", (), {})
        registry = DriverRegistry([(info, driver_class)])
        result = registry.select(ModemIdentity("Quectel", "EG91", "REV"))
        self.assertEqual(result, (info, driver_class))

    def test_returns_none_for_unsupported_device(self):
        registry = DriverRegistry.discover()
        result = registry.select(ModemIdentity("Sierra Wireless", "EM7565", "REV"))
        self.assertIsNone(result)

    def test_discovery_finds_quectel_and_cinterion_packages(self):
        registry = DriverRegistry.discover()
        ids = [info.driver_id for info, _ in registry.drivers]
        self.assertIn("quectel", ids)
        self.assertIn("cinterion", ids)

    def test_selects_pls83_cinterion_driver(self):
        registry = DriverRegistry.discover()
        match = registry.select(ModemIdentity("Cinterion", "PLS83-W", "REVISION 01.202"))
        self.assertIsNotNone(match)
        info, driver_class = match
        self.assertEqual(info.driver_id, "cinterion")
        self.assertEqual(driver_class.__name__, "CinterionDriver")
        tested = info.tested_match(ModemIdentity("Cinterion", "PLS83-W", "REVISION 01.202"))
        self.assertIsNotNone(tested)
        self.assertEqual(tested.firmware, "REVISION 01.202")

    def test_cinterion_untested_model_selects_vendor_driver(self):
        registry = DriverRegistry.discover()
        identity = ModemIdentity("Cinterion", "ELS61-US", "REVISION UNKNOWN")
        result = registry.select(identity)
        self.assertIsNotNone(result)
        info, driver_class = result
        self.assertEqual(info.driver_id, "cinterion")
        self.assertEqual(driver_class.__name__, "CinterionDriver")
        self.assertIsNone(info.tested_match(identity))


    def test_selects_ublox_sara_r410m_driver(self):
        registry = DriverRegistry.discover()
        identity = ModemIdentity(
            "u-blox",
            "SARA-R410M-02B",
            "L0.0.00.00.05.08 [Apr 17 2019 19:34:02]",
        )
        match = registry.select(identity)
        self.assertIsNotNone(match)
        info, driver_class = match
        self.assertEqual(info.driver_id, "ublox")
        self.assertEqual(driver_class.__name__, "UBloxDriver")
        self.assertIsNotNone(info.tested_match(identity))

    def test_selects_known_quectel_models(self):
        registry = DriverRegistry.discover()
        for model, revision in (
            ("EG91", "EG91NAXGAR08A09M1G"),
            ("BG95M3", "BG95M3LAR02A02"),
            ("BG96", "BG96MAR04A03M1G"),
        ):
            with self.subTest(model=model):
                match = registry.select(ModemIdentity("Quectel", model, revision))
                self.assertIsNotNone(match)
                info, driver_class = match
                self.assertEqual(info.driver_id, "quectel")
                self.assertEqual(driver_class.__name__, "QuectelDriver")


if __name__ == "__main__":
    unittest.main()
