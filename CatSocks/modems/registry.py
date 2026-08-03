"""Automatic discovery and selection of installed CatSocks modem drivers."""

from __future__ import annotations

import importlib
import logging
import pkgutil

import modems
from modems.base import DriverInfo, ModemIdentity


class DriverRegistry:
    def __init__(self, drivers=None):
        self.drivers = list(drivers or [])

    @classmethod
    def discover(cls):
        drivers = []
        for module_info in pkgutil.iter_modules(modems.__path__):
            if not module_info.ispkg or module_info.name.startswith("_"):
                continue
            try:
                package = importlib.import_module(f"modems.{module_info.name}")
                info = getattr(package, "DRIVER_INFO")
                driver_class = next(
                    value for name, value in vars(package).items()
                    if name.endswith("Driver") and name != "CellularModemDriver"
                )
                if not isinstance(info, DriverInfo):
                    raise TypeError("DRIVER_INFO is not DriverInfo")
                drivers.append((info, driver_class))
            except Exception as exc:
                logging.warning("Skipping modem driver package %s: %s", module_info.name, exc)
        drivers.sort(key=lambda item: item[0].display_name.lower())
        return cls(drivers)

    def select(self, identity: ModemIdentity):
        matches = [(info, cls) for info, cls in self.drivers if info.matches(identity)]
        if not matches:
            return None
        tested = [item for item in matches if item[0].tested_match(identity) is not None]
        return (tested or matches)[0]
