# 👂 Eavesdrop — know what's listening before someone else does.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Audits](https://img.shields.io/badge/recon-stealth-red.svg)](#)

**Eavesdrop** is a fast, concurrent TCP/UDP port scanner with service and banner detection, built on raw sockets and Scapy. Designed for authorized security audits, vulnerability assessment, and network reconnaissance, Eavesdrop provides clean, script-friendly outputs while supporting stealth scanning methodologies.

---

> [!WARNING]
> ## ⚠️ AUTHORIZED USE ONLY (Legal Disclaimer)
> Scanning networks or hosts without explicit, written permission from the owner is illegal in most jurisdictions (such as the Computer Fraud and Abuse Act in the US). This tool is developed strictly for educational purposes, defensive hardening, and authorized penetration testing audits. The author assumes no liability for misuse, collateral damage, or illegal actions performed using this software.

---

## 🎯 Features

- **TCP Connect Scan**: Fast, multi-threaded standard three-way handshake scan (no elevated privileges required).
- **TCP SYN Stealth Scan**: Scapy-based raw packet scanning that does not complete the connection handshake (requires administrative/root privileges).
- **UDP Scan**: Deep Scapy-based packet crafting with ICMP unreachable handling to identify open/filtered/closed UDP ports.
- **Service & Banner Identification**: Exposes service details by grabbing banners on open ports (HTTP, SSH, FTP, SMTP, and TLS-encrypted endpoints) and mapping well-known ports to common services.
- **High Concurrency**: Uses Python's `ThreadPoolExecutor` to perform fast scans across massive port ranges.
- **Rich Formatted Exports**: Output scanning reports in clean human-readable text tables, JSON, or CSV formats.
- **Lazy Imports**: Scapy and other heavy dependencies are imported dynamically only when required, keeping standard scans lightweight and instantaneous.

---

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/H8rsh100/Eavesdrop.git
   cd Eavesdrop
   ```

2. **Set up a Virtual Environment**:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On macOS/Linux:
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

> [!NOTE]
> Scapy packet-crafting functions (SYN and UDP scanning) require raw socket permissions:
> - **Linux/macOS**: Prefix commands with `sudo`.
> - **Windows**: Run your terminal (cmd/PowerShell) as **Administrator**.
> 
> If run without administrative privileges, Eavesdrop will automatically fall back to standard **TCP Connect** scanning and issue a warning.

---

## 🚀 Usage

Eavesdrop is run as a Python module:

```bash
python -m eavesdrop.cli --target <target-ip-or-host> [options]
```

### Command Line Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target` | `-t` | **Required**. Target IP address or hostname. | None |
| `--ports` | `-p` | Ports to scan. Supports single (`80`), range (`1-1000`), or list (`22,80,443`). | Top 100 common ports |
| `--scan-type`| `-s` | Scan mode: `tcp` (Connect), `syn` (Stealth), `udp` (UDP), `all` (TCP + UDP). | `tcp` |
| `--timeout` | | Timeout in seconds per port connection. | `1.0` |
| `--threads` | | Concurrency thread limit. | `100` |
| `--output` | `-o` | Output file path (e.g. `report.json`, `report.csv`). | Stdout |
| `--format` | `-f` | Output format: `txt`, `json`, `csv`. | `txt` |
| `--verbose` | `-v` | Show real-time details of every scanned port. | False |

---

### Examples

#### 1. Basic TCP Connect Scan (No root/admin needed)
Scan the top common ports of a target:
```bash
python -m eavesdrop.cli --target localhost
```

#### 2. Stealth TCP SYN Scan (Requires Admin/Sudo)
Perform stealth scanning on ports 20 to 80 with high verbosity:
```bash
# On Linux/macOS:
sudo .venv/bin/python -m eavesdrop.cli --target scanme.nmap.org --scan-type syn --ports 20-80 -v
```

#### 3. UDP Scan with custom Timeout
Scan specific UDP ports:
```bash
sudo .venv/bin/python -m eavesdrop.cli --target 192.168.1.1 --scan-type udp --ports 53,67,123 --timeout 1.5
```

#### 4. Full Scan and Exporting Reports
Scan a range of ports and output a CSV report:
```bash
python -m eavesdrop.cli --target 127.0.0.1 --ports 1-1024 -o report.csv
```

---

## 🧪 Testing

The repository features comprehensive unit and mock integration testing. You can run all test suites using `pytest`:

```bash
python -m pytest tests/
```
