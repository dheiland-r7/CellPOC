**CellPPP**

CellPPP.py is a Python script that brings up a PPP connection over a Quectel cell module using your host's pppd daemon.

The script opens the serial port, dials with ATD*99#, and hands the link to pppd so traffic can route through the cellular module.

Tested on a Quectel EG91 on macOS. This has not been tested with all Quectel cell modules or on Linux, and is considered a proof of concept tool.

**Usage:** sudo python3 CellPPP.py --device <serial device> --baud <baud rate>

**Example:**
  sudo python3 CellPPP.py --device /dev/tty.usbserial-XXXXXXXX --baud 115200

**Before running**

A pppd options file must exist at /etc/ppp/options. See options.example, copy it to /etc/ppp/options and edit the device, baud rate, and other configurations for your setup. The device and baud in that file should match the ones passed to the script.

Note, pppd requires sudoer privileges.

**What the script does**

The current default route is saved to /tmp/original_default_route.txt before anything else, so normal networking can be restored after terminating the script.

The modem is sent AT, ATE0, and ATD*99#. If no CONNECT is returned the script restores the default route and exits.

pppd is launched and the script waits 10 seconds, then checks whether ppp0 became the default route and prints the result.

Press Ctrl+C to tear down. The script kills pppd and restores the saved default route before exiting.

options:

  -h, --help              Show this help message and exit
  
  --device DEVICE         Serial device (e.g. /dev/tty.usbserial-XXXXXXXX)
  
  --baud BAUD             Serial baud rate (e.g. 115200)

Intended for authorized security assessment and learning purposes only.
