**CatScan**

CatScan.py is TCP port scanner

This scanner is currently designed to work with Quectel cellular modules by leveraging QIOPEN QICLOSE AT commands over a serial connection

This has not been tested with all Quectel cell modules and is considered a proof of concept tool and should be used with caution



options:

  -h, --help              Show this help message and exit
  
  --ipfile IPFILE         File with IP addresses (one per line)
  
  -IP IP                  Single IP to scan (e.g. 192.168.0.1)
  
  -IC CIDR                CIDR to scan (e.g. 192.168.0.0/24)
  
  --portfile PORTFILE     File with ports (one per line)
  
  -p, --ports PORTS       Comma-separated ports (e.g. 80,443,22)
  
  --serialport SERIALPORT Serial port for module (e.g. /dev/ttyUSB0)

