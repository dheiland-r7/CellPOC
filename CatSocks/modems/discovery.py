"""3GPP modem identity discovery shared by all CatSocks drivers."""

from __future__ import annotations

import logging
import time

from modems.base import ModemIdentity


def wait_until_responsive(transport, *, startup_timeout: float, probe_timeout: float, probe_interval: float) -> None:
    deadline = time.monotonic() + startup_timeout
    attempt = 0
    logging.info("Probing modem AT interface (RDY is not required)…")
    while True:
        attempt += 1
        try:
            transport.execute("AT", timeout=probe_timeout)
            logging.info("Modem AT interface ready after %s probe(s)", attempt)
            return
        except (TimeoutError, IOError) as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Modem did not respond to AT within {startup_timeout}s") from exc
            time.sleep(probe_interval)


def _query_identity_field(transport, command: str, timeout: float) -> str:
    try:
        result = transport.execute(command, timeout=timeout)
    except (TimeoutError, IOError) as exc:
        logging.warning("Identity query %s failed: %s", command, exc)
        return ""

    values = []
    for line in result.lines:
        value = line.strip()
        if not value or value == "OK" or value.upper() == command.upper():
            continue
        values.append(value)
    return " ".join(values).strip()


def identify_modem(transport, timeout: float = 5) -> ModemIdentity:
    """Query non-sensitive 3GPP identity fields; CGSN/IMEI is intentionally omitted."""
    return ModemIdentity(
        manufacturer=_query_identity_field(transport, "AT+CGMI", timeout),
        model=_query_identity_field(transport, "AT+CGMM", timeout),
        revision=_query_identity_field(transport, "AT+CGMR", timeout),
    )
