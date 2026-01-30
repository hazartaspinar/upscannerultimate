# UpScanner

**UpScanner** is an advanced network discovery tool designed for penetration testers to identify **all live hosts** (clients, servers, printers, IoT devices) within a target network — including systems hidden behind strict firewall rules.

Unlike traditional ping sweeps, UpScanner uses a **paranoid hybrid discovery strategy** combining **ICMP, TCP, and UDP probes** to achieve **zero-miss host detection**.

> **Primary Goal:**  
> Generate a **complete and clean list of live IP addresses** ready for vulnerability scanners such as **Nessus**, **Qualys**, or **OpenVAS**.

---

## Key Features

- **Zero-Miss Detection**
  - Discovers hosts that ignore ICMP ping requests
  - Uses multiple discovery techniques to avoid false negatives

- **Paranoid Hybrid Scanning**
  - ICMP Echo Requests
  - TCP SYN & ACK probes
  - UDP-based discovery packets

- **Windows Firewall Bypass**
  - Detects silent Windows hosts using:
    - **UDP 137** (NetBIOS Name Service)
    - **UDP 1900** (SSDP / UPnP)

- **IoT & Printer Discovery**
  - Identifies:
    - Printers
    - IP cameras
    - Network appliances
    - Apple devices
  - Uses:
    - **SNMP (UDP 161)**
    - **mDNS (UDP 5353)**

- **Nessus / Qualys Ready Output**
  - Generates a clean `.txt` file
  - One IP per line
  - Directly importable into vulnerability scanners

---

## Usage
```bash
sudo python3 UpScanner.py -f scope.txt -o live_hosts.txt
```
