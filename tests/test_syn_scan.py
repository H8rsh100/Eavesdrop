from unittest.mock import patch
from scapy.all import IP, TCP
from eavesdrop.scanners.syn_scan import scan_port, scan

@patch("eavesdrop.scanners.syn_scan.grab_banner")
@patch("scapy.all.send")
@patch("scapy.all.sr1")
def test_syn_scan_port_open(mock_sr1, mock_send, mock_grab_banner):
    # Construct a real Scapy SYN-ACK response packet
    response_packet = IP(src="127.0.0.1") / TCP(sport=80, flags="SA", ack=101)
    mock_sr1.return_value = response_packet
    mock_grab_banner.return_value = "MockBanner"

    res = scan_port("127.0.0.1", 80)
    
    assert res["status"] == "open"
    assert res["port"] == 80
    assert res["service"] == "HTTP"
    assert res["banner"] == "MockBanner"
    
    # Verify we sent the RST packet
    assert mock_send.called

@patch("scapy.all.sr1")
def test_syn_scan_port_closed(mock_sr1):
    # Construct a real Scapy RST response packet
    response_packet = IP(src="127.0.0.1") / TCP(sport=22, flags="RA")
    mock_sr1.return_value = response_packet

    res = scan_port("127.0.0.1", 22)
    assert res["status"] == "closed"

@patch("scapy.all.sr1")
def test_syn_scan_port_filtered(mock_sr1):
    # Timeout/no response
    mock_sr1.return_value = None

    res = scan_port("127.0.0.1", 443)
    assert res["status"] == "filtered"
