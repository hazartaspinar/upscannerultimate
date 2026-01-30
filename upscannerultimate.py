#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import argparse
import re
from datetime import datetime

# --- COLORS ---
ORANGE = '\033[38;5;208m' # Özel Turuncu
GREEN = '\033[92m'
RED = '\033[91m'
GREY = '\033[90m'
BOLD = '\033[1m'
RESET = '\033[0m'
CLEAR_LINE = '\033[K'

total_found = 0

def banner():
    # Gönderdiğin görseldeki stil (ANSI Shadow)
    ascii_art = r"""
 ██╗   ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██║   ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║   ██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║   ██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    print(f"{ORANGE}{BOLD}{ascii_art}{RESET}")
    print(f"{GREY}           Multi-Protocol Live Host Detection (Zero-Miss){RESET}\n")

def check_dependency():
    """Checks if Nmap is installed."""
    rc = subprocess.call(['which', 'nmap'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc != 0:
        print(f"{RED}[!] Error: 'nmap' is not installed.{RESET}")
        print(f"{GREY}    Please install: sudo apt install nmap{RESET}")
        sys.exit(1)

def scan_subnet(subnet, output_file):
    global total_found
    try:
        # --- ULTIMATE DISCOVERY FLAGS ---
        # The goal is to trigger ANY response from the target.
        
        discovery_flags = [
            "-sn",                          # No Port Scan (Host Discovery Only)
            "-n",                           # No DNS Resolution (Speed)
            
            # 1. ICMP PROBES (Ping Variations)
            "-PE",                          # Standard Echo Request
            "-PP",                          # Timestamp Request (Bypasses some firewalls)
            "-PM",                          # Netmask Request
            
            # 2. TCP SYN PROBES (Common Services)
            # FTP, SSH, Telnet, Web, RPC, NetBIOS, HTTPS, SMB, RDP, VNC, Alt-Web
            "-PS21,22,23,80,135,139,443,445,3389,5900,8080,8443",
            
            # 3. TCP ACK PROBES (Firewall Evasion)
            # Tricks stateless firewalls by sending ACK packets to common ports
            "-PA80,443,3389",
            
            # 4. UDP PROBES (The "Secret Weapon" for Clients/IoT)
            # DNS(53), DHCP(67), NTP(123), RPC(135), NetBIOS(137 - Critical for Windows),
            # SNMP(161 - Critical for Printers), SMB(445), IPP(631), MSSQL(1434),
            # SSDP(1900 - IoT/UPnP), IPsec(4500), mDNS(5353 - Apple/Linux)
            "-PU53,67,123,135,137,161,445,631,1434,1900,4500,5353",
            
            # 5. PERFORMANCE
            "--min-rate", "200",            # Minimum packet rate (Adjusted for reliability)
            "--max-retries", "2"            # Retry twice to be sure
        ]
        
        # Construct command
        cmd = ["nmap"] + discovery_flags + ["-oG", "-", subnet]

        # Execute
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        current_subnet_count = 0
        
        for line in process.stdout:
            # We only care if Nmap says "Status: Up"
            if "Status: Up" in line:
                ip_match = re.search(r"Host: ([0-9\.]+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    total_found += 1
                    current_subnet_count += 1
                    
                    # Write to file instantly
                    with open(output_file, "a") as f:
                        f.write(ip + "\n")
                    
                    # Visual Feedback
                    print(f"\r{CLEAR_LINE}{GREEN}[+] Found: {ip:<15} {GREY}(Total: {total_found}){RESET}")

        process.wait()
        return current_subnet_count

    except Exception:
        return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Input file with subnets (CIDR)", required=True)
    parser.add_argument("-o", "--output", help="Output file for live IPs", required=True)
    args = parser.parse_args()

    os.system('clear')
    banner()
    check_dependency()

    if not os.path.exists(args.file):
        print(f"{RED}[!] Input file not found: {args.file}{RESET}")
        sys.exit(1)

    # Initialize/Clear output file
    with open(args.output, "w") as f:
        pass

    with open(args.file, "r") as f:
        subnets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    total_subnets = len(subnets)
    print(f"{GREY}[*] Loaded {total_subnets} subnets.{RESET}")
    print(f"{GREY}[*] Discovery Mode: Paranoid (ICMP + TCP SYN/ACK + UDP){RESET}")
    print(f"{ORANGE}[*] Scan started... Results -> {args.output}{RESET}\n")

    start_time = datetime.now()

    for i, subnet in enumerate(subnets):
        # Progress Info
        print(f"{ORANGE}[*] Scanning Subnet [{i+1}/{total_subnets}]: {BOLD}{subnet}{RESET}")
        scan_subnet(subnet, args.output)

    duration = datetime.now() - start_time
    
    print(f"\n{ORANGE}" + "="*55 + f"{RESET}")
    print(f"{GREEN}[✔] Comprehensive Scan Completed in {duration}!{RESET}")
    print(f"{BOLD}[*] Total Live Hosts Discovered: {total_found}{RESET}")
    print(f"{BOLD}[*] Clean List Saved To: {args.output}{RESET}")
    print(f"{ORANGE}" + "="*55 + f"{RESET}")

if __name__ == "__main__":
    main()
