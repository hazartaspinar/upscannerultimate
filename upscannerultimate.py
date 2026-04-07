#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import argparse
import re
from datetime import datetime

# --- Colors ---
ORANGE = '\033[38;5;208m'
GREEN = '\033[92m'
RED = '\033[91m'
GREY = '\033[90m'
BOLD = '\033[1m'
RESET = '\033[0m'
CLEAR_LINE = '\033[K'

total_found = 0

def banner():
    ascii_art = r"""
 ██╗   ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██║   ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║   ██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║   ██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    print(f"{ORANGE}{BOLD}{ascii_art}{RESET}")
    print(f"{GREY}           Multi-Protocol Live Host Detection{RESET}\n")

def check_dependency():
    rc = subprocess.call(['which', 'nmap'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc != 0:
        print(f"{RED}[!] Error: 'nmap' is not installed.{RESET}")
        print(f"{GREY}    Please install: sudo apt install nmap{RESET}")
        sys.exit(1)

def scan_subnet(subnet, output_file):
    global total_found
    try:
        discovery_flags = [
            "-sn", 
            "-n",  
            "--reason", 
            "-PE", "-PP", "-PM", 
            "-PS21,22,23,80,135,139,443,445,3389,5900,8080,8443",
            "-PA80,443,3389",
            "-PU53,67,123,135,137,161,445,631,1434,1900,4500,5353"
        ]
        
        cmd = ["nmap"] + discovery_flags + ["-oG", "-", subnet]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        current_subnet_count = 0
        
        for line in process.stdout:
            if "Status: Up" in line:
                ip_match = re.search(r"Host:\s+([0-9\.]+)", line)
                reason_match = re.search(r"Reason:\s+([^\s]+)", line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    reason = reason_match.group(1) if reason_match else "unknown"
                    
                    total_found += 1
                    current_subnet_count += 1
                    
                    with open(output_file, "a") as f:
                        f.write(ip + "\n")
                    
                    print(f"\r{CLEAR_LINE}{GREEN}[+] Found: {ip:<15} {GREY}[{reason}] (Total: {total_found}){RESET}")

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

    with open(args.output, "w") as f:
        pass

    with open(args.file, "r") as f:
        subnets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    total_subnets = len(subnets)
    print(f"{GREY}[*] Loaded {total_subnets} subnets.{RESET}")
    print(f"{GREY}[*] Discovery Mode: ICMP + TCP SYN/ACK + UDP{RESET}")
    print(f"{ORANGE}[*] Scan started... Results -> {args.output}{RESET}\n")

    start_time = datetime.now()

    for i, subnet in enumerate(subnets):
        print(f"{ORANGE}[*] Scanning Subnet [{i+1}/{total_subnets}]: {BOLD}{subnet}{RESET}")
        scan_subnet(subnet, args.output)

    duration = datetime.now() - start_time
    
    print(f"\n{ORANGE}" + "="*55 + f"{RESET}")
    print(f"{GREEN}[✔] Scan Completed in {duration}{RESET}")
    print(f"{BOLD}[*] Total Live Hosts Discovered: {total_found}{RESET}")
    print(f"{BOLD}[*] Clean List Saved To: {args.output}{RESET}")
    print(f"{ORANGE}" + "="*55 + f"{RESET}")

if __name__ == "__main__":
    main()
