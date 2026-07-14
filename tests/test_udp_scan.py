from unittest.mock import patch
from scapy.all import IP, UDP, ICMP
from eavesdrop.scanners.udp_scan import scan_port, scan

@patch("scapy.all.sr1")
def test_udp_scan_port_open(mock_sr1):
    # Construct a real UDP response packet
    response_packet = IP(src="127.0.0.1") / UDP(sport=53, dport=12345)
    mock_sr1.return_value = response_packet

    res = scan_port("127.0.0.1", 53)
    assert res["status"] == "open"
    assert res["port"] == 53
    assert res["service"] == "DOMAIN"

@patch("scapy.all.sr1")
def test_udp_scan_port_closed(mock_sr1):
    # Construct a real ICMP Port Unreachable packet (type=3, code=3)
    response_packet = IP(src="127.0.0.1") / ICMP(type=3, code=3)
    mock_sr1.return_value = response_packet

    res = scan_port("127.0.0.1", 123)
    assert res["status"] == "closed"

@patch("scapy.all.sr1")
def test_udp_scan_port_no_response(mock_sr1):
    # Timeout/no response -> open|filtered
    mock_sr1.return_value = None

    res = scan_port("127.0.0.1", 161)
    assert res["status"] == "open|filtered"
