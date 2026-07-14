import re
import socket
import os
import sys

def is_admin() -> bool:
    """
    Checks if the current process has administrative/root privileges.
    """
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


# A curated list of the top 100 most common ports for quick scans
COMMON_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 2000, 2049, 2121, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5060, 5631,
    5800, 5900, 5985, 5986, 6000, 6001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100,
    9999, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

def validate_ip_or_hostname(target: str) -> str:
    """
    Validates the target input (IP address or hostname).
    Resolves hostnames to IP addresses.
    Returns the resolved IP address.
    Raises ValueError if target is invalid or cannot be resolved.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty")

    # Check if target is a valid IPv4 address
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ipv4_pattern.match(target):
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            raise ValueError(f"Invalid IP address: {target}")

    # Check if target is a valid IPv6 address
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return target
    except socket.error:
        pass

    # Attempt hostname resolution
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        raise ValueError(f"Failed to resolve hostname: {target}")

def parse_ports(ports_str: str) -> list[int]:
    """
    Parses a ports string and returns a sorted list of unique port integers.
    Supports formats:
      - Single port: "80"
      - Port list: "22,80,443"
      - Port range: "1-1024"
      - Combined: "22,80-88,443"
    
    If empty or None, returns COMMON_PORTS.
    Raises ValueError on invalid formats or ports outside 1-65535.
    """
    if not ports_str or not ports_str.strip():
        return sorted(list(set(COMMON_PORTS)))

    ports = set()
    parts = ports_str.strip().split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        # Check range pattern e.g., "1-1024"
        range_match = re.match(r"^(\d+)-(\d+)$", part)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            if start > end:
                raise ValueError(f"Invalid range: {part} (start port must be <= end port)")
            for port in range(start, end + 1):
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} out of range (1-65535)")
                ports.add(port)
        else:
            # Check single port
            if not part.isdigit():
                raise ValueError(f"Invalid port definition: {part}")
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of range (1-65535)")
            ports.add(port)

    if not ports:
        raise ValueError(f"No valid ports parsed from: {ports_str}")

    return sorted(list(ports))
