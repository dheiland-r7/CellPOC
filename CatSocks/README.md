# CatSocks

**CatSocks** is a transparent SOCKS5 proxy and inter-chip communications
research framework for embedded cellular devices. It allows existing
security tools including Metasploit, Nmap, curl, Burp Suite, SNMP
utilities, custom scripts, and other SOCKS5 aware applications to
communicate through a device's native cellular modem over its internal
AT-command interface without requiring any modifications to those tools.

## Project Purpose

CatSocks is **a research platform, not a high-performance SOCKS proxy**.

Its purpose is to transparently exercise the same communications path
used by an embedded CPU when it accesses a cellular modem. Rather than
emulating a network stack, CatSocks intentionally routes traffic through
the target device's existing inter-chip communications channel
(typically USB CDC ACM or UART using AT commands). This allows
researchers to evaluate the complete networking ecosystem---including
modem firmware, socket handling, DNS resolution, carrier behavior, and
application interactions---exactly as the embedded device experiences
them.

Because CatSocks operates through a hardware modem's AT command
interface, users should expect hardware-specific constraints including:

-   Limited physical socket counts
-   Vendor-specific socket allocation and release timing
-   Serialized AT command processing
-   Cellular network latency
-   Firmware-specific socket lifecycle behavior

These characteristics are inherent to the hardware being evaluated and
**are not defects in CatSocks**.

Unlike traditional SOCKS proxies, CatSocks intentionally **does not
emulate unlimited network resources**. When a modem has exhausted its
available socket resources, CatSocks queues new connection requests
until the modem itself confirms that resources have actually been
released. This ensures testing accurately reflects the capabilities and
limitations of the target hardware instead of masking them behind a
software abstraction.

If your testing tool experiences delays while waiting for modem sockets
to become available, that is often revealing an actual characteristic of
the embedded platform under evaluation. Understanding and measuring
those limitations is part of the value CatSocks provides.

------------------------------------------------------------------------

# Features

-   Transparent SOCKS5 proxy supporting existing security tools
-   Multi-vendor cellular modem architecture
-   Automatic modem detection
-   Vendor-isolated driver framework
-   TCP support
-   UDP support
-   DNS proxying
-   Thread-safe socket management
-   Vendor-specific socket lifecycle handling
-   Queueing for exhausted modem socket resources
-   Configurable serial interface (`/dev/ttyUSB0` by default, `--serial`
    override)

# Currently Supported Cellular Modems

## Quectel

Validated:

-   BG95M3
-   BG96

Protocols:

-   TCP
-   UDP
-   DNS

## Cinterion / Thales

Validated:

-   PLS83-W
-   EXS82-W

Protocols:

-   TCP
-   UDP
-   DNS

## u-blox

Validated:

-   SARA-R410M-02B

Protocols:

-   TCP
-   UDP
-   DNS

# Python Requirements

-   Python 3.10 or newer recommended
-   pyserial
-   PySocks (if applicable)
-   Standard Python libraries used throughout the project

# Basic Usage

``` bash
python3 catsocks.py
```

Specify a serial interface:

``` bash
python3 catsocks.py --serial /dev/ttyUSB2
```

# Design Goals

-   Preserve existing security workflows.
-   Exercise the target's real cellular communications stack.
-   Keep vendor-specific behavior isolated from the core framework.
-   Make adding new modem vendors straightforward.
-   Report real modem limitations rather than hiding them.

# Planned Vendors

-   SIMCom
-   Telit
-   Sierra Wireless
-   Fibocom
-   Sequans
-   Nordic Semiconductor (where socket APIs permit)

# License

Refer to the project license for distribution and usage terms.
