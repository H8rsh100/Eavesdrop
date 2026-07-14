import socket
import ssl

# Fallback service map for common ports when socket.getservbyport fails
PORT_SERVICE_MAP = {
    7: "echo",
    9: "discard",
    13: "daytime",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "time",
    53: "DNS",
    79: "finger",
    80: "HTTP",
    81: "HTTP-Alt",
    88: "Kerberos",
    110: "POP3",
    111: "sunrpc",
    119: "NNTP",
    135: "msrpc",
    139: "netbios-ssn",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "microsoft-ds",
    465: "SMTPS",
    513: "who",
    514: "syslog",
    515: "printer",
    548: "AFP",
    587: "submission",
    631: "ipp",
    636: "LDAPS",
    873: "rsync",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    3000: "Node.js",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Returns the service name for a given port.
    Uses socket.getservbyport with a fallback to a static dictionary.
    """
    try:
        return socket.getservbyport(port, protocol).upper()
    except (socket.error, OverflowError):
        return PORT_SERVICE_MAP.get(port, "unknown")

def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """
    Attempts to grab a banner from the open TCP port.
    Handles HTTP, HTTPS, and generic protocols.
    """
    service = get_service_name(port, "tcp").lower()
    
    # Handle HTTPS/SSL banners
    if service in ("https", "https-alt", "ldaps", "imaps", "pop3s", "ftps") or port in (443, 8443, 993, 995, 465):
        return _grab_ssl_banner(ip, port, timeout)
    
    # Handle plain HTTP
    if service in ("http", "http-alt") or port in (80, 8080, 8000, 8888, 9000):
        return _grab_http_banner(ip, port, timeout)

    # General TCP banner grab
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Read whatever server sends first (e.g., SSH, FTP, SMTP send banners instantly)
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                pass
            
            # If nothing was received, send a generic probe
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    # Clean up first line
                    first_line = banner.split('\n')[0].strip()
                    return first_line
            except socket.error:
                pass
    except socket.error:
        pass
    
    return ""

def _grab_http_banner(ip: str, port: int, timeout: float) -> str:
    """Sends a basic HTTP request and extracts Server header or status line."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            response = s.recv(2048).decode('utf-8', errors='ignore')
            return _parse_http_response(response)
    except socket.error:
        return ""

def _grab_ssl_banner(ip: str, port: int, timeout: float) -> str:
    """Establishes SSL handshake and attempts HTTP GET probe."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            with context.wrap_socket(s, server_hostname=ip) as ss:
                ss.connect((ip, port))
                # Some servers might send banner immediately (e.g. wrapper SSL services)
                try:
                    ss.settimeout(0.5)
                    banner = ss.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner
                except socket.timeout:
                    pass
                
                # Send HTTP request
                ss.settimeout(timeout)
                ss.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = ss.recv(2048).decode('utf-8', errors='ignore')
                return _parse_http_response(response)
    except Exception:
        return ""

def _parse_http_response(response: str) -> str:
    """Helper to extract Server header or HTTP status from response."""
    if not response:
        return ""
    
    lines = response.split('\r\n')
    status_line = lines[0].strip()
    
    server_header = ""
    for line in lines:
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break
            
    if server_header:
        return f"{status_line} | Server: {server_header}"
    return status_line
