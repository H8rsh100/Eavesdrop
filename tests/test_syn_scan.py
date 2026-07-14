import sys
from unittest.mock import patch, MagicMock

# Create mock scapy components
mock_scapy_all = MagicMock()
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = mock_scapy_all

from eavesdrop.scanners.syn_scan import scan_port, scan

@patch("eavesdrop.scanners.syn_scan.grab_banner")
def test_syn_scan_port_open(mock_grab_banner):
    # Setup mock sr1 and send on mock_scapy_all
    mock_sr1 = MagicMock()
    mock_send = MagicMock()
    mock_scapy_all.sr1 = mock_sr1
    mock_scapy_all.send = mock_send
    
    mock_response = MagicMock()
    mock_response.haslayer.return_value = True
    
    # TCP layer with SYN-ACK flags (0x12)
    mock_tcp = MagicMock()
    mock_tcp.flags = 0x12
    mock_tcp.ack = 101
    mock_response.getlayer.return_value = mock_tcp
    
    mock_sr1.return_value = mock_response
    mock_grab_banner.return_value = "MockBanner"

    res = scan_port("127.0.0.1", 80)
    
    assert res["status"] == "open"
    assert res["port"] == 80
    assert res["service"] == "HTTP"
    assert res["banner"] == "MockBanner"
    
    # Verify send was called with RST
    assert mock_send.called

def test_syn_scan_port_closed():
    mock_sr1 = MagicMock()
    mock_scapy_all.sr1 = mock_sr1
    
    mock_response = MagicMock()
    mock_response.haslayer.return_value = True
    
    # TCP layer with RST flag (0x04)
    mock_tcp = MagicMock()
    mock_tcp.flags = 0x04
    mock_response.getlayer.return_value = mock_tcp
    
    mock_sr1.return_value = mock_response

    res = scan_port("127.0.0.1", 22)
    assert res["status"] == "closed"

def test_syn_scan_port_filtered():
    mock_sr1 = MagicMock()
    mock_scapy_all.sr1 = mock_sr1
    # No response
    mock_sr1.return_value = None

    res = scan_port("127.0.0.1", 443)
    assert res["status"] == "filtered"
