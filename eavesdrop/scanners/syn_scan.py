import sys
import logging
from eavesdrop.service_id import get_service_name, grab_banner

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scans a single TCP port using a SYN packet (stealth scan).
    Lazy-imports scapy to save start-up overhead.
    """
    # Suppress scapy warning messages during import
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, sr1

    result = {
        "port": port,
        "status": "closed",
        "service": get_service_name(port),
        "banner": ""
    }

    try:
        # Construct IP and TCP SYN packets
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        
        # Send packet and wait for a single response
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response is None:
            # No response typical of a firewall dropping packets
            result["status"] = "filtered"
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12: # SYN-ACK
                result["status"] = "open"
                # Send RST to tear down connection cleanly
                from scapy.all import send
                rst_packet = IP(dst=ip) / TCP(dport=port, flags="R", seq=tcp_layer.ack)
                send(rst_packet, verbose=0)
            elif tcp_layer.flags & 0x04: # RST (RST-ACK or RST)
                result["status"] = "closed"
        else:
            result["status"] = "closed"
            
    except Exception as e:
        result["status"] = "error"
        result["banner"] = f"Error: {str(e)}"
        
    # Grab banner if open (banner grabbing requires TCP connect)
    if result["status"] == "open":
        result["banner"] = grab_banner(ip, port, timeout=timeout)
        
    return result

def scan(ip: str, ports: list[int], timeout: float = 1.0, threads: int = 100, on_progress=None) -> list[dict]:
    """
    Performs a multi-threaded TCP SYN scan against the target IP and ports.
    """
    # Using ThreadPoolExecutor since sr1 blocks until timeout or response
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
                    "service": get_service_name(port),
                    "banner": f"Error: {str(e)}"
                }
                results.append(res)
                if on_progress:
                    on_progress(res)
                    
    return sorted(results, key=lambda x: x["port"])
