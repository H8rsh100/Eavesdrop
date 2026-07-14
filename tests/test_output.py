import json
import csv
import io
from eavesdrop.output import format_text, format_json, format_csv

def test_format_text():
    results = [
        {"port": 22, "status": "open", "service": "SSH", "banner": "OpenSSH"},
        {"port": 80, "status": "closed", "service": "HTTP", "banner": ""}
    ]
    txt = format_text(results, "127.0.0.1", "tcp")
    assert "Target    : 127.0.0.1" in txt
    assert "22/tcp" in txt
    assert "OpenSSH" in txt
    assert "Found 1 open ports" in txt

def test_format_json():
    results = [
        {"port": 22, "status": "open", "service": "SSH", "banner": "OpenSSH"}
    ]
    js_str = format_json(results, "127.0.0.1", "tcp")
    data = json.loads(js_str)
    assert data["target"] == "127.0.0.1"
    assert data["scan_type"] == "tcp"
    assert len(data["results"]) == 1
    assert data["results"][0]["port"] == 22

def test_format_csv():
    results = [
        {"port": 22, "status": "open", "service": "SSH", "banner": "OpenSSH"}
    ]
    csv_str = format_csv(results, "127.0.0.1", "tcp")
    f = io.StringIO(csv_str)
    reader = csv.reader(f)
    rows = list(reader)
    assert len(rows) == 2 # Header + 1 row
    assert rows[0] == ["Target", "Scan Type", "Port", "Status", "Service", "Banner"]
    assert rows[1] == ["127.0.0.1", "tcp", "22", "open", "SSH", "OpenSSH"]
