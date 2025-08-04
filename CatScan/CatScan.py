#!/usr/bin/env python3

############################################
#                                          #
#   __|    \ __ __| __|                    #
#  (      _ \   | \__ \   _|   _` |    \   #
# \___| _/  _\ _| ____/ \__| \__,_| _| _|  #
#                                          #
############################################
# tool for injecting AT socket commands    #
# via serial communication to conduct port #
# scanning via an embedded Cellular module #
#                                          #
# tested on Quectel Cellular modules       #
#                                          #
#          Deral Heiland 2025              #
# Code was created with assistance from AI #
############################################

import serial
import time
import argparse
import sys
import re
import ipaddress

# Main: builds IP/port lists, opens serial, issues QIOPEN, interprets response codes, and print results
def main():
    args = parse_args()

    # Build IP list
    if args.ip:
        ips = [args.ip]
    elif args.cidr:
        try:
            net = ipaddress.ip_network(args.cidr, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        except ValueError:
            print(f"Invalid CIDR: {args.cidr}")
            sys.exit(1)
    else:
        ips = load_list_from_file(args.ipfile)

    # Build ports list
    if args.ports:
        ports = [p.strip() for p in args.ports.split(',') if p.strip()]
    else:
        ports = load_list_from_file(args.portfile)

    # Open serial
    try:
        ser = serial.Serial(args.serialport, baudrate=115200, timeout=5)
    except Exception as e:
        print(f"Error opening serial port: {e}")
        sys.exit(1)

    for ip in ips:
        seen_valid = False
        for port in ports:
            try:
                port_int = int(port)
            except ValueError:
                print(f"Skipping invalid port: {port}")
                continue

            # Attempt connection
            resp = send_at_command(ser,
                                   f'AT+QIOPEN=1,0,"TCP","{ip}",{port_int},0,0')
            send_at_command(ser, 'AT+QICLOSE=0,10')

            # Parse code2
            m = re.search(r'\+QIOPEN:\s*\d+,(\d+)', resp)
            code2 = m.group(1) if m else None

            # Evaluate
            if code2 == '0':
                print(f"\033[92m{ip}:{port_int} - OPEN\033[0m")
                seen_valid = True
            elif code2 == '566':
                print(f"\033[33m{ip}:{port_int} - CLOSED\033[0m")
                seen_valid = True
            else:
                # if no valid seen yet, tag host down
                if not seen_valid:
                    print(f"\033[91m{ip} - DOWN\033[0m")
                    break
                # else just unknown for this port
                print(f"\033[93m{ip}:{port_int} - UNKNOWN\033[0m")

            time.sleep(1)

        # next IP
    ser.close()

# Parses command-line arguments for target IPs (file, single, or CIDR), ports (file or list), and serial port
def parse_args():
    parser = argparse.ArgumentParser(
        description="Cellular module TCP port scanner using AT+QIOPEN"
    )

    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument("--ipfile", help="File with IP addresses (one per line)")
    ip_group.add_argument("-IP", dest="ip", help="Single IP to scan (e.g. 192.168.0.1)")
    ip_group.add_argument("-IC", dest="cidr", help="CIDR to scan (e.g. 192.168.0.0/24)")

    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument("--portfile", help="File with ports (one per line)")
    port_group.add_argument("-p", "--ports",
                            help="Comma-separated ports (e.g. 80,443,22)")

    parser.add_argument("--serialport", required=True,
                        help="Serial port for module (e.g. /dev/ttyUSB0)")
    return parser.parse_args()


# Loads a list of strings from a file, stripping whitespace and skipping empty lines
def load_list_from_file(filepath):
    try:
        with open(filepath) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        sys.exit(1)

# Sends an AT command over serial, waits for a response, and returns the decoded string
def send_at_command(ser, cmd, delay=2):
    ser.write((cmd + '\r\n').encode())
    time.sleep(delay)
    return ser.read_all().decode()


if __name__ == "__main__":
    main()

