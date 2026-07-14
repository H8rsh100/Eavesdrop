import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from eavesdrop.service_id import get_service_name, grab_banner

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scans a single TCP port using a standard socket connection (TCP Connect).
    """
    result = {
        "port": port,
        "status": "closed",
        "service": get_service_name(port),
        "banner": ""
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            result["status"] = "open"
    except socket.timeout:
        # Timeout typically indicates a firewall dropping packets, i.e., filtered
        result["status"] = "filtered"
    except ConnectionRefusedError:
        result["status"] = "closed"
    except socket.error:
        result["status"] = "closed"

    if result["status"] == "open":
        result["banner"] = grab_banner(ip, port, timeout=timeout)
        
    return result

def scan(ip: str, ports: list[int], timeout: float = 1.0, threads: int = 100, on_progress=None) -> list[dict]:
    """
    Performs a multi-threaded TCP Connect scan against the target IP and ports.
    """
    results = []
    
    # Cap threads to not exceed length of ports
    max_workers = min(threads, len(ports)) if ports else 1
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in as_completed(future_to_port):
            try:
                res = future.result()
                results.append(res)
                if on_progress:
                    on_progress(res)
            except Exception as e:
                port = future_to_port[future]
                res = {
                    "port": port,
                    "status": "error",
                    "service": get_service_name(port),
                    "banner": f"Error: {str(e)}"
                }
                results.append(res)
                if on_progress:
                    on_progress(res)
                    
    return sorted(results, key=lambda x: x["port"])
