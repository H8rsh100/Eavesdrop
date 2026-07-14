import argparse
import sys
import os
from eavesdrop.utils import validate_ip_or_hostname, parse_ports, is_admin
from eavesdrop.service_id import get_service_name
from eavesdrop.output import format_text, format_json, format_csv, write_output

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="Eavesdrop — A fast, concurrent TCP/UDP port scanner with service & banner detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authorized use only! Scanning networks without permission is illegal.
Examples:
  python -m eavesdrop.cli --target 127.0.0.1 --ports 1-1000
  python -m eavesdrop.cli --target scanme.nmap.org --scan-type syn --ports 22,80,443
  python -m eavesdrop.cli --target localhost --ports 80 --output report.json
"""
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or hostname to scan."
    )
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan. Supports single port (80), list (22,80,443), or range (1-1024). Default is common ports."
    )
    parser.add_argument(
        "-s", "--scan-type",
        choices=["tcp", "syn", "udp", "all"],
        default="tcp",
        help="Type of scan to perform: tcp (TCP Connect), syn (TCP SYN stealth), udp (UDP scan), all (TCP Connect + UDP). (default: tcp)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for port responses. (default: 1.0)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Maximum concurrency threads. (default: 100)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path. If not specified, results are printed to stdout."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format. (default: txt)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode to show real-time progress of ports scanned."
    )
    return parser.parse_args(args)

def main(args=None):
    parsed_args = parse_args(args)
    
    # 1. Resolve and validate target
    print(f"[*] Resolving target: {parsed_args.target}...")
    try:
        target_ip = validate_ip_or_hostname(parsed_args.target)
        print(f"[*] Target resolved to IP: {target_ip}")
    except ValueError as e:
        print(f"[-] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
        
    # 2. Parse ports
    try:
        ports = parse_ports(parsed_args.ports)
        print(f"[*] Configured {len(ports)} ports for scanning.")
    except ValueError as e:
        print(f"[-] Port Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

    # 3. Privilege / Scanner check
    scan_type = parsed_args.scan_type
    if scan_type in ("syn", "udp", "all"):
        if not is_admin():
            print(f"[!] Warning: scan type '{scan_type}' requires root/administrator privileges.")
            print("[!] Falling back to standard TCP Connect scan.")
            scan_type = "tcp"

    # 4. Execute Scanner
    results = []
    
    def on_progress(res):
        if parsed_args.verbose:
            status_str = f"{res['port']}/tcp | {res['status']:<10} | {res['service']}"
            if res.get('banner'):
                status_str += f" | {res['banner']}"
            print(f"[+] {status_str}")
        elif res['status'] == 'open':
            # Always print open ports to stdout during scan
            status_str = f"FOUND OPEN PORT: {res['port']}/tcp ({res['service']})"
            if res.get('banner'):
                status_str += f" - {res['banner']}"
            print(f"[+] {status_str}")

    print(f"[*] Starting {scan_type.upper()} scan against {target_ip} with {parsed_args.threads} threads...")
    
    if scan_type == "tcp":
        from eavesdrop.scanners.tcp_connect import scan as tcp_scan
        results = tcp_scan(
            ip=target_ip,
            ports=ports,
            timeout=parsed_args.timeout,
            threads=parsed_args.threads,
            on_progress=on_progress
        )
    elif scan_type == "syn":
        from eavesdrop.scanners.syn_scan import scan as syn_scan
        results = syn_scan(
            ip=target_ip,
            ports=ports,
            timeout=parsed_args.timeout,
            threads=parsed_args.threads,
            on_progress=on_progress
        )
    elif scan_type == "udp":
        from eavesdrop.scanners.udp_scan import scan as udp_scan
        results = udp_scan(
            ip=target_ip,
            ports=ports,
            timeout=parsed_args.timeout,
            threads=parsed_args.threads,
            on_progress=on_progress
        )
    elif scan_type == "all":
        # 'all' scan type does both TCP and UDP.
        # However, if we fell back, it became "tcp".
        # If we have root, we can run both.
        from eavesdrop.scanners.tcp_connect import scan as tcp_scan
        from eavesdrop.scanners.udp_scan import scan as udp_scan
        
        print("[*] Phase 1: TCP Connect Scan")
        tcp_results = tcp_scan(
            ip=target_ip,
            ports=ports,
            timeout=parsed_args.timeout,
            threads=parsed_args.threads,
            on_progress=on_progress
        )
        print("[*] Phase 2: UDP Scan")
        udp_results = udp_scan(
            ip=target_ip,
            ports=ports,
            timeout=parsed_args.timeout,
            threads=parsed_args.threads,
            on_progress=on_progress
        )
        # Merge results, indicating tcp/udp
        for r in tcp_results:
            r["protocol"] = "tcp"
        for r in udp_results:
            r["protocol"] = "udp"
        results = tcp_results + udp_results

    # 5. Format and Export Output
    output_format = parsed_args.format
    if parsed_args.output and not parsed_args.format:
        # Infer format from file extension if format flag was not explicitly provided
        ext = os.path.splitext(parsed_args.output)[1].lower()
        if ext == ".json":
            output_format = "json"
        elif ext == ".csv":
            output_format = "csv"
        else:
            output_format = "txt"
            
    if output_format == "json":
        formatted = format_json(results, target_ip, scan_type)
    elif output_format == "csv":
        formatted = format_csv(results, target_ip, scan_type)
    else:
        formatted = format_text(results, target_ip, scan_type)
        
    write_output(formatted, parsed_args.output)
    if parsed_args.output:
        print(f"[*] Results successfully written to: {parsed_args.output}")

if __name__ == "__main__":
    main()
