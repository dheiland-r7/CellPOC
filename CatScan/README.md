**CatScan**

CatScan0.2.py is an update to the original CatScan0.1py TCP port scanner

CatScan0.2.py is designed to work with Quectel and Telit cellular modules by leveraging their AT socket commands over a serial connection

Quectel uses QIOPEN, QISEND, QIRD, QICLOSE and Telit uses SD, SSENDEXT, SRECV, SH

TCP ports are reported as OPEN, CLOSED, or UNKNOWN. If a host returns 3 UNKNOWN results in a row and nothing valid before that, the host is marked DOWN and the rest of its ports are skipped.

UDP ports are reported as OPEN or OPEN|FILTERED. A reply means OPEN, no reply means the port cannot be told apart from a closed or filtered one. Service probes are sent for DNS, NTP, SNMP, NetBIOS, SSDP, TFTP, RPC, IKE, RIP, and SIP, and a small null probe is sent for everything else.

The data context must be active before scanning. If it is not, the tool prints a warning and every socket will fail

This has not been tested with all Quectel and Telit cell modules and is considered a proof of concept tool and should be used with caution



options:

  -h, --help              Show this help message and exit
  
  --ipfile IPFILE         File with IP addresses (one per line)
  
  -IP IP                  Single IP to scan (e.g. 192.168.0.1)
  
  -IC CIDR                CIDR to scan (e.g. 192.168.0.0/24)
  
  --portfile PORTFILE     File with ports (one per line)
  
  -p, --ports PORTS       Ports or ranges (e.g. 80,443 or 1-1000 or 22,80,8000-8100)
  
  --serialport SERIALPORT Serial port for module (e.g. /dev/ttyUSB0)
  
  --module MODULE         Cellular module family, quectel or telit (default: quectel)
  
  --proto PROTO           Protocol(s) to scan, tcp udp or both (default: tcp)
  
  --udp-wait UDP_WAIT     Seconds to wait for a UDP reply (default: 3.0)
  
  --delay DELAY           Delay between probes in seconds (default: 0.5)
  
  --baud BAUD             Serial baud rate (default: 115200)
  
  -v, --verbose           Show AT commands, raw module responses, and probe data
