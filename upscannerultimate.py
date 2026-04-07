#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import argparse
import re
import threading
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Colors ---
ORANGE = '\033[38;5;208m'
GREEN  = '\033[92m'
RED    = '\033[91m'
GREY   = '\033[90m'
YELLOW = '\033[93m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
CLEAR_LINE = '\033[K'

# --- Globals ---
total_found   = 0
found_ips     = set()
print_lock    = threading.Lock()
file_lock     = threading.Lock()
counter_lock  = threading.Lock()

# --- Discovery Flags ---
DISCOVERY_FLAGS = [
    "-sn",
    "-n",
    "--reason",
    "-T4",
    "-PE", "-PP", "-PM",
    "-PS21,22,23,25,80,110,135,139,443,445,1433,3306,3389,5900,8080,8443,9100",
    "-PA80,443,3389,8080",
    "-PU53,67,123,135,137,161,445,631,1434,1900,4500,5353",
]

def setup_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("upscanner")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

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
    print(f"{GREY}           Multi-Protocol Live Host Detection  |  v2.0{RESET}\n")

def check_dependency():
    rc = subprocess.call(['which', 'nmap'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc != 0:
        print(f"{RED}[!] Error: 'nmap' is not installed.{RESET}")
        print(f"{GREY}    Install via: sudo apt install nmap{RESET}")
        sys.exit(1)

def print_progress(current: int, total: int, subnet: str):
    """Subnet scanning progress bar."""
    bar_len = 30
    filled  = int(bar_len * current / total) if total else 0
    bar     = "█" * filled + "░" * (bar_len - filled)
    pct     = int(100 * current / total) if total else 0
    with print_lock:
        print(
            f"\r{CLEAR_LINE}{ORANGE}[{bar}] {pct:3d}%  "
            f"[{current}/{total}]  {GREY}{subnet[:40]}{RESET}",
            end="",
            flush=True,
        )

def scan_subnet(subnet: str, output_file: str, logger: logging.Logger) -> int:
    """Scan a single subnet; return the number of UP hosts found."""
    global total_found

    cmd = ["nmap"] + DISCOVERY_FLAGS + ["-oG", "-", subnet]
    subnet_count = 0

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        for line in process.stdout:
            if "Status: Up" not in line:
                continue

            ip_match     = re.search(r"Host:\s+([0-9\.]+)", line)
            reason_match = re.search(r"Reason:\s+(\S+)", line)

            if not ip_match:
                continue

            ip     = ip_match.group(1)
            reason = reason_match.group(1) if reason_match else "unknown"

            # --- Duplicate check ---
            with counter_lock:
                if ip in found_ips:
                    logger.debug(f"Skipped duplicate: {ip}")
                    continue
                found_ips.add(ip)
                total_found += 1
                current_total = total_found

            subnet_count += 1

            # --- Write to file ---
            with file_lock:
                with open(output_file, "a") as f:
                    f.write(ip + "\n")

            logger.info(f"UP host: {ip}  reason={reason}")

            with print_lock:
                print(
                    f"\r{CLEAR_LINE}{GREEN}[+] {ip:<17}"
                    f"{GREY}[{reason:<20}]  Total: {current_total}{RESET}"
                )

        process.wait()

        stderr_out = process.stderr.read().strip()
        if process.returncode != 0 and stderr_out:
            logger.warning(f"nmap warning ({subnet}): {stderr_out}")

    except FileNotFoundError:
        with print_lock:
            print(f"\n{RED}[!] nmap not found!{RESET}")
        logger.error("nmap not found.")
    except PermissionError:
        with print_lock:
            print(f"\n{RED}[!] Permission error: root/sudo may be required.{RESET}")
        logger.error(f"Permission error: {subnet}")
    except Exception as e:
        with print_lock:
            print(f"\n{YELLOW}[!] Error while scanning {subnet}: {e}{RESET}")
        logger.error(f"Unexpected error ({subnet}): {e}", exc_info=True)

    return subnet_count

def main():
    parser = argparse.ArgumentParser(
        description="UP Scanner v2.0 — Multi-Protocol Live Host Detection",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-f", "--file",    required=True,  help="Subnet list (CIDR, line by line)")
    parser.add_argument("-o", "--output",  required=True,  help="Output file (live IPs)")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Number of parallel subnet scans (default: 5)")
    args = parser.parse_args()

    os.system('clear')
    banner()
    check_dependency()

    # --- Input file check ---
    if not os.path.exists(args.file):
        print(f"{RED}[!] File not found: {args.file}{RESET}")
        sys.exit(1)

    # --- Time-stamped log file ---
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = f"upscanner_{timestamp}.log"
    logger    = setup_logger(log_file)
    logger.info(f"Scan started. Input: {args.file} | Output: {args.output} | Workers: {args.workers}")

    # --- Initialize output file (Clean start, no header) ---
    open(args.output, "w").close()

    # --- Load subnets ---
    with open(args.file, "r") as f:
        subnets = [
            line.strip() for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    total_subnets = len(subnets)
    print(f"{GREY}[*] Loaded subnets        : {total_subnets}{RESET}")
    print(f"{GREY}[*] Parallel workers      : {args.workers}{RESET}")
    print(f"{GREY}[*] Discovery mode        : ICMP + TCP SYN/ACK + UDP{RESET}")
    print(f"{GREY}[*] Timing parameters     : -T4{RESET}")
    print(f"{ORANGE}[*] Log file              : {log_file}{RESET}")
    print(f"{ORANGE}[*] Scan starting... Results -> {args.output}{RESET}\n")

    start_time = datetime.now()

    # --- Parallel scanning ---
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_subnet = {
            executor.submit(scan_subnet, subnet, args.output, logger): subnet
            for subnet in subnets
        }

        for future in as_completed(future_to_subnet):
            subnet = future_to_subnet[future]
            completed += 1
            print_progress(completed, total_subnets, subnet)

            try:
                count = future.result()
                logger.info(f"Subnet completed: {subnet} — {count} hosts found.")
            except Exception as e:
                logger.error(f"Future error ({subnet}): {e}", exc_info=True)

    duration         = datetime.now() - start_time
    total_secs       = int(duration.total_seconds())
    hours, rem       = divmod(total_secs, 3600)
    minutes, seconds = divmod(rem, 60)

    parts = []
    if hours:
        parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
    human_duration = ", ".join(parts)

    print(f"\n\n{ORANGE}" + "═" * 58 + f"{RESET}")
    print(f"{GREEN}{BOLD}[✔] Scan finished in {human_duration}{RESET}")
    print(f"{BOLD}[*] Total live hosts      : {total_found}{RESET}")
    print(f"{BOLD}[*] Clean list saved to   : {args.output}{RESET}")
    print(f"{BOLD}[*] Detailed log          : {log_file}{RESET}")
    print(f"{ORANGE}" + "═" * 58 + f"{RESET}")

    logger.info(f"Scan finished. Total UP: {total_found} | Duration: {human_duration}")

if __name__ == "__main__":
    main()
