import subprocess
import sys
import os
import argparse
import re
import shutil
import threading
import logging
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Colors ---
ORANGE = '\033[38;5;208m'
GREEN  = '\033[92m'
RED    = '\033[91m'
GREY   = '\033[90m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BLUE   = '\033[94m'
BOLD   = '\033[1m'
RESET  = '\033[0m'
CLEAR_LINE = '\033[K'

# --- Globals ---
total_found  = 0
found_ips    = set()
print_lock   = threading.Lock()
file_lock    = threading.Lock()
counter_lock = threading.Lock()

# Interface-name hints that mean "this is a VPN / tunnel"
VPN_IFACE_RE = re.compile(
    r"^(tun|tap|wg|ppp|utun|ipsec|nordlynx|proton|gpd|vpn|zt|wt)", re.IGNORECASE)

# Base discovery probes (ICMP + TCP + UDP). ARP is added per-profile.
BASE_DISCOVERY = [
    "-sn", "-n", "--reason",
    "-PE", "-PP", "-PM",  # ICMP echo / timestamp / netmask
    "-PS21,22,23,25,80,110,135,139,443,445,1433,3306,3389,5900,8080,8443",
    "-PA80,443,3389,8080",
    "-PU53,67,123,135,137,161,445,631,1434,1900,4500,5353",
]

# Per-profile tuning. rate=0 means no cap.
PROFILES = {
    "lan":    {"timing": "-T4", "rate": 0,   "retries": 2, "arp": True,  "color": GREEN},
    "vpn":    {"timing": "-T3", "rate": 300, "retries": 3, "arp": False, "color": CYAN},
    "routed": {"timing": "-T3", "rate": 0,   "retries": 3, "arp": False, "color": BLUE},
}

IP_RE     = re.compile(r"Host:\s+([0-9.]+)")
REASON_RE = re.compile(r"Reason:\s+(\S+)")


def setup_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("upscanner")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
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
    print(f"{GREY}   Multi-Protocol Live Host Detection  |  v5.0 (auto-profile){RESET}\n")


def check_dependency():
    if shutil.which("nmap") is None:
        print(f"{RED}[!] Error: 'nmap' is not installed.{RESET}")
        print(f"{GREY}    Install via: sudo apt install nmap{RESET}")
        sys.exit(1)


def is_privileged() -> bool:
    """Raw sockets (ARP + SYN/ICMP probes) need root/admin. Without it nmap
    falls back to TCP-connect and skips ARP, which misses firewalled hosts."""
    try:
        return os.geteuid() == 0          # Linux / macOS
    except AttributeError:
        try:
            import ctypes                  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def _probe_ip(subnet: str) -> str:
    """Representative IP for a subnet, used to query the routing table."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        if net.num_addresses > 2:
            return str(next(net.hosts()))
        return str(net.network_address)
    except ValueError:
        return subnet  # hostname / range nmap understands


def detect_profile(subnet: str, forced: str, logger: logging.Logger) -> str:
    """Decide lan / vpn / routed by asking the OS how the subnet is reached.
    `forced` (other than 'auto') short-circuits detection."""
    if forced != "auto":
        return forced

    ip = _probe_ip(subnet)

    # --- Linux / macOS: `ip route get` ---
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "route", "get", ip],
                                 capture_output=True, text=True, timeout=5).stdout
            dev = re.search(r"\bdev\s+(\S+)", out)
            via = "via" in out
            if dev:
                iface = dev.group(1)
                if VPN_IFACE_RE.match(iface):
                    logger.info(f"{subnet}: profile=vpn (dev {iface})")
                    return "vpn"
                if not via:  # directly connected on a physical NIC
                    logger.info(f"{subnet}: profile=lan (dev {iface}, on-link)")
                    return "lan"
                logger.info(f"{subnet}: profile=routed (via gw, dev {iface})")
                return "routed"
        except Exception as e:
            logger.warning(f"ip route get failed for {subnet}: {e}")

    # --- macOS fallback: `route -n get` ---
    if shutil.which("route") and sys.platform == "darwin":
        try:
            out = subprocess.run(["route", "-n", "get", ip],
                                 capture_output=True, text=True, timeout=5).stdout
            dev = re.search(r"interface:\s+(\S+)", out)
            gw  = re.search(r"gateway:\s+(\S+)", out)
            if dev:
                if VPN_IFACE_RE.match(dev.group(1)):
                    return "vpn"
                return "routed" if gw else "lan"
        except Exception as e:
            logger.warning(f"route get failed for {subnet}: {e}")

    # --- Windows fallback: Find-NetRoute ---
    if os.name == "nt":
        try:
            ps = (f"(Find-NetRoute -RemoteIPAddress {ip} | "
                  f"Select-Object -First 1 -ExpandProperty InterfaceAlias)")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=8).stdout.strip()
            if out:
                if VPN_IFACE_RE.search(out) or "vpn" in out.lower():
                    return "vpn"
                return "routed"
        except Exception as e:
            logger.warning(f"Find-NetRoute failed for {subnet}: {e}")

    logger.info(f"{subnet}: profile=routed (default, detection unavailable)")
    return "routed"


def record_host(ip, reason, output_file, logger):
    """Thread-safe dedup + write + print. Returns True if newly added."""
    global total_found
    with counter_lock:
        if ip in found_ips:
            logger.debug(f"Skipped duplicate: {ip}")
            return False
        found_ips.add(ip)
        total_found += 1
        current_total = total_found

    with file_lock:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(ip + "\n")

    logger.info(f"UP host: {ip}  reason={reason}")
    with print_lock:
        print(f"\r{CLEAR_LINE}{GREEN}[+] {ip:<17}{GREY}"
              f"[{reason:<18}]  Total: {current_total}{RESET}")
    return True


def run_nmap(cmd, subnet, output_file, logger) -> int:
    """Run one nmap invocation, stream grepable output, record UP hosts."""
    count = 0
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stderr_lines = []
        def _drain():
            for l in process.stderr:
                stderr_lines.append(l)
        t = threading.Thread(target=_drain, daemon=True)
        t.start()

        for line in process.stdout:
            if "Status: Up" not in line:
                continue
            ip_m = IP_RE.search(line)
            if not ip_m:
                continue
            r_m = REASON_RE.search(line)
            reason = r_m.group(1) if r_m else "unknown"
            if record_host(ip_m.group(1), reason, output_file, logger):
                count += 1

        process.wait()
        t.join(timeout=2)
        err = "".join(stderr_lines).strip()
        if process.returncode != 0 and err:
            logger.warning(f"nmap warning ({subnet}): {err}")

    except FileNotFoundError:
        with print_lock:
            print(f"\n{RED}[!] nmap not found!{RESET}")
        logger.error("nmap not found.")
    except PermissionError:
        with print_lock:
            print(f"\n{RED}[!] Permission error: root/sudo required.{RESET}")
        logger.error(f"Permission error: {subnet}")
    except Exception as e:
        with print_lock:
            print(f"\n{YELLOW}[!] Error scanning {subnet}: {e}{RESET}")
        logger.error(f"Unexpected error ({subnet}): {e}", exc_info=True)
    return count


def scan_discovery(subnet, output_file, logger, prof) -> int:
    p = PROFILES[prof]
    cmd = ["nmap"] + list(BASE_DISCOVERY)
    if p["arp"]:
        cmd.append("-PR")          # ARP ping (local L2 only; ignored off-link)
    else:
        cmd.append("--disable-arp-ping")
    cmd += [p["timing"], "--max-retries", str(p["retries"])]
    if p["rate"]:
        cmd += ["--max-rate", str(p["rate"])]
    cmd += ["-oG", "-", subnet]
    return run_nmap(cmd, subnet, output_file, logger)


def main():
    parser = argparse.ArgumentParser(
        description="UP Scanner v5.0 — auto-profile live host detection",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file",   required=True, help="Subnet list (CIDR, line by line)")
    parser.add_argument("-o", "--output", required=True, help="Output file (live IPs)")
    # Everything below is optional; defaults auto-tune.
    parser.add_argument("-w", "--workers", type=int, default=0,
                        help="Parallel subnet scans (0=auto based on profiles)")
    parser.add_argument("--profile", default="auto",
                        choices=["auto", "lan", "vpn", "routed"],
                        help="Force a profile instead of auto-detecting (default: auto)")
    args = parser.parse_args()

    os.system("cls" if os.name == "nt" else "clear")
    banner()
    check_dependency()

    priv = is_privileged()
    if not priv:
        print(f"{YELLOW}[!] Not root/admin — ARP + raw ICMP/SYN disabled; nmap")
        print(f"    falls back to TCP-connect and WILL miss firewalled hosts.")
        print(f"    Re-run with sudo for full coverage.{RESET}\n")

    if not os.path.exists(args.file):
        print(f"{RED}[!] File not found: {args.file}{RESET}")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = f"upscanner_{timestamp}.log"
    logger    = setup_logger(log_file)
    logger.info(f"Start. in={args.file} out={args.output} "
                f"profile={args.profile} priv={priv}")

    open(args.output, "w", encoding="utf-8").close()

    with open(args.file, "r", encoding="utf-8") as f:
        subnets = [l.strip() for l in f
                   if l.strip() and not l.strip().startswith("#")]

    # --- Auto-detect a profile per subnet ---
    print(f"{GREY}[*] Detecting network profile per subnet...{RESET}")
    profiles = {}
    counts = {"lan": 0, "vpn": 0, "routed": 0}
    for s in subnets:
        prof = detect_profile(s, args.profile, logger)
        profiles[s] = prof
        counts[prof] += 1
        col = PROFILES[prof]["color"]
        print(f"    {col}{prof.upper():<7}{RESET} {GREY}{s}{RESET}")

    # --- Auto workers: gentle if any VPN subnet is in play ---
    if args.workers > 0:
        workers = args.workers
    elif counts["vpn"] > 0:
        workers = 2
    elif counts["lan"] == len(subnets):
        workers = 5
    else:
        workers = 3

    print(f"\n{GREY}[*] Subnets           : {len(subnets)} "
          f"(lan={counts['lan']} vpn={counts['vpn']} routed={counts['routed']}){RESET}")
    print(f"{GREY}[*] Workers (auto)    : {workers}{RESET}")
    print(f"{GREY}[*] Privileged        : {'yes (ARP + raw probes)' if priv else 'NO (TCP-connect only)'}{RESET}")
    print(f"{ORANGE}[*] Log file          : {log_file}{RESET}")
    print(f"{ORANGE}[*] Results -> {args.output}{RESET}\n")

    start_time = datetime.now()
    total_subnets = len(subnets)

    def progress(done):
        bar_len = 24
        filled = int(bar_len * done / total_subnets) if total_subnets else bar_len
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(100 * done / total_subnets) if total_subnets else 100
        with print_lock:
            print(f"\r{CLEAR_LINE}{ORANGE}[{bar}] {pct:3d}%  "
                  f"[{done}/{total_subnets}]  live so far: {total_found}{RESET}",
                  end="", flush=True)

    # --- Discovery (single pass) ---
    print(f"{BOLD}{ORANGE}══ Discovery ══{RESET}")
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_discovery, s, args.output, logger, profiles[s]): s
                for s in subnets}
        for fut in as_completed(futs):
            s = futs[fut]
            try:
                fut.result()
            except Exception as e:
                logger.error(f"Future error ({s}): {e}", exc_info=True)
            done += 1
            progress(done)
    print()  # newline after the progress bar

    # --- Summary ---
    dur = datetime.now() - start_time
    secs = int(dur.total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    human = " ".join(parts)

    print(f"\n{ORANGE}" + "═" * 58 + f"{RESET}")
    print(f"{GREEN}{BOLD}[✔] Scan finished in {human}{RESET}")
    print(f"{BOLD}[*] Total live hosts      : {total_found}{RESET}")
    print(f"{BOLD}[*] Clean list saved to   : {args.output}{RESET}")
    print(f"{BOLD}[*] Detailed log          : {log_file}{RESET}")
    print(f"{ORANGE}" + "═" * 58 + f"{RESET}")
    logger.info(f"Done. total={total_found} dur={human}")


if __name__ == "__main__":
    main()
