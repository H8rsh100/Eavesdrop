import logging
from eavesdrop.service_id import get_service_name

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scans a single UDP port.
    Sends a UDP packet. If no reply, status is open|filtered.
    If ICMP Destination Unreachable / Port Unreachable, status is closed.
    If UDP response, status is open.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, UDP, ICMP, sr1

    result = {
        "port": port,
        "status": "open|filtered",
        "service": get_service_name(port, "udp"),
        "banner": ""
    }

    try:
        # Construct UDP packet
        packet = IP(dst=ip) / UDP(dport=port)
        
        # Send UDP packet and wait for response (expecting UDP response or ICMP error)
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response is not None:
            if response.haslayer(UDP):
                result["status"] = "open"
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                # ICMP type 3 code 3 means Port Unreachable (closed)
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    result["status"] = "closed"
                elif icmp_layer.type == 3 and icmp_layer.code in (1, 2, 9, 10, 13):
                    result["status"] = "filtered" # Administratively prohibited
            else:
                result["status"] = "filtered"
                
    except Exception as e:
        result["status"] = "error"
        result["banner"] = f"Error: {str(e)}"
        
    return result

def scan(ip: str, ports: list[int], timeout: float = 1.0, threads: int = 100, on_progress=None) -> list[dict]:
    """
    Performs a multi-threaded UDP scan against the target IP and ports.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = []
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
                    "service": get_service_name(port, "udp"),
                    "banner": f"Error: {str(e)}"
                }
                results.append(res)
                if on_progress:
                    on_progress(res)
                    
    return sorted(results, key=lambda x: x["port"])
