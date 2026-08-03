#!/usr/bin/env python3

############################################
#                 CellPPP                  #
#                                          #
# Creates a PPP using a celllular module   #
# using a Quectel module and the pppd      #
# daemon on MacOS or Linux (note only      #
# tested on MacOS).                        #
# Tested on Quectel EG91. Should work with #
#         similar Quectel modules.         #
#                                          #
#     Requires a pppd options file at      #
#  /etc/ppp/options. See options.example.  #
#                                          #
#             Carlota Bindner              #
#                                          #
#           Copywrite 2025, 2026           #
#                                          #
#                                          #
#     Intended for authorized security     #
#  assessment and learning purposes only.  #
############################################

import serial
import subprocess
import time
import argparse
import sys
import os
import re
import signal

DEFAULT_ROUTE_FILE = "/tmp/original_default_route.txt"

def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def backup_default_route():
    print("Backing up current default route...")
    result = run(["route", "get", "default"])
    match = re.search(r"gateway: (\S+)", result.stdout)
    if match:
        gateway = match.group(1)
        with open(DEFAULT_ROUTE_FILE, "w") as f:
            f.write(gateway)
        print(f"Saved default route gateway: {gateway}")
    else:
        print("Could not determine current default gateway")

def restore_default_route():
    if os.path.exists(DEFAULT_ROUTE_FILE):
        with open(DEFAULT_ROUTE_FILE) as f:
            gateway = f.read().strip()
        print(f"Restoring default route to {gateway}...")
        run(["sudo", "route", "change", "default", gateway])
        print("Route restored")
    else:
        print("No saved default route found")

def check_ppp0_default():
    result = run(["netstat", "-rn"])
    for line in result.stdout.splitlines():
        if line.startswith("default") and "ppp0" in line:
            print("Default route is now through ppp0:")
            print(line)
            return True
    print("ppp0 is not the default route")
    return False

def send_at(ser, command, delay=2):
    ser.write((command + '\r').encode())
    time.sleep(delay)
    response = ser.read_all().decode(errors='ignore').strip()
    print(f"> {command}")
    print(f"< {response}")
    return response

def main():
    parser = argparse.ArgumentParser(description="Start PPP connection via modem")
    parser.add_argument("--device", required=True, help="Serial device (e.g. /dev/tty.usbserial-XXXXXXXX)")
    parser.add_argument("--baud", required=True, type=int, default=115200)
    args = parser.parse_args()

    # Backup default route
    backup_default_route()

    print(f"\nOpening {args.device} @ {args.baud}")
    try:
        ser = serial.Serial(args.device, args.baud, timeout=1)
    except serial.SerialException as e:
        restore_default_route()
        sys.exit(f"Could not open serial port: {e}")

    # Send AT setup
    send_at(ser, "AT")
    send_at(ser, "ATE0")
    resp = send_at(ser, "ATD*99#", delay=3)

    if "CONNECT" not in resp:
        restore_default_route()
        sys.exit("Modem failed to connect, no CONNECT received")

    print("\nLaunching pppd...\n")

    def teardown(signum=None, frame=None):
        print("\nCleaning up PPP connection...")
        run(["sudo", "killall", "pppd"])
        restore_default_route()
        sys.exit(0)

    signal.signal(signal.SIGINT, teardown)
    signal.signal(signal.SIGTERM, teardown)

    try:
        proc = subprocess.Popen([
            "sudo", "pppd", "connect", "true"
        ])
        # Wait 10s and check if ppp0 became the default
        time.sleep(10)
        check_ppp0_default()

        # Wait for user interrupt
        proc.wait()
    except Exception as e:
        print(f"Failed to start PPPD: {e}")
        teardown()

if __name__ == "__main__":
    main()

