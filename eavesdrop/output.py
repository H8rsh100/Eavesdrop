import json
import csv
import sys
from typing import List, Dict

def format_text(results: List[Dict], target: str, scan_type: str) -> str:
    """Formats the results into a human-readable table."""
    lines = []
    lines.append(f"Eavesdrop Scan Report")
    lines.append(f"=====================")
    lines.append(f"Target    : {target}")
    lines.append(f"Scan Type : {scan_type.upper()}")
    lines.append("")
    
    # Header
    lines.append(f"{'PORT':<10} {'STATUS':<15} {'SERVICE':<15} {'BANNER / DETAILS'}")
    lines.append(f"{'-'*10} {'-'*15} {'-'*15} {'-'*30}")
    
    open_ports_count = 0
    for r in results:
        port_proto = f"{r['port']}/tcp" if "udp" not in scan_type.lower() else f"{r['port']}/udp"
        if r['status'] == 'open':
            open_ports_count += 1
        
        banner = r.get("banner", "")
        lines.append(f"{port_proto:<10} {r['status']:<15} {r['service']:<15} {banner}")
        
    lines.append("")
    lines.append(f"Scan complete. Found {open_ports_count} open ports out of {len(results)} scanned.")
    return "\n".join(lines)

def format_json(results: List[Dict], target: str, scan_type: str) -> str:
    """Formats the results as a JSON string."""
    data = {
        "target": target,
        "scan_type": scan_type,
        "results": results
    }
    return json.dumps(data, indent=4)

def format_csv(results: List[Dict], target: str, scan_type: str) -> str:
    """Formats the results as CSV content."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    # Write header
    writer.writerow(["Target", "Scan Type", "Port", "Status", "Service", "Banner"])
    for r in results:
        writer.writerow([
            target,
            scan_type,
            r["port"],
            r["status"],
            r["service"],
            r.get("banner", "")
        ])
    return output.getvalue()

def write_output(content: str, filepath: str) -> None:
    """Writes the formatted output content to a file."""
    if filepath == "-" or not filepath:
        sys.stdout.write(content + "\n")
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
