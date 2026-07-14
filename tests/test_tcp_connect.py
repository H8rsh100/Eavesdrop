from unittest.mock import patch, MagicMock
import socket
from eavesdrop.scanners.tcp_connect import scan_port, scan

@patch("socket.socket")
def test_scan_port_open(mock_socket):
    mock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_inst
    
    # Connection succeeds
    mock_inst.connect.return_value = None
    
    # We mock grab_banner to return empty banner
    with patch("eavesdrop.scanners.tcp_connect.grab_banner") as mock_grab:
        mock_grab.return_value = "SSH-2.0-OpenSSH"
        res = scan_port("127.0.0.1", 22)
        assert res["status"] == "open"
        assert res["port"] == 22
        assert res["service"] == "SSH"
        assert res["banner"] == "SSH-2.0-OpenSSH"

@patch("socket.socket")
def test_scan_port_closed(mock_socket):
    mock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_inst
    
    # Connection refused
    mock_inst.connect.side_effect = ConnectionRefusedError()
    
    res = scan_port("127.0.0.1", 80)
    assert res["status"] == "closed"
    assert res["port"] == 80
    assert res["service"] == "HTTP"

@patch("socket.socket")
def test_scan_port_filtered(mock_socket):
    mock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_inst
    
    # Timeout
    mock_inst.connect.side_effect = socket.timeout()
    
    res = scan_port("127.0.0.1", 443)
    assert res["status"] == "filtered"

@patch("eavesdrop.scanners.tcp_connect.scan_port")
def test_scan_multiple_ports(mock_scan_port):
    # Mocking single port responses
    def side_effect(ip, port, timeout):
        if port == 22:
            return {"port": 22, "status": "open", "service": "SSH", "banner": ""}
        return {"port": 80, "status": "closed", "service": "HTTP", "banner": ""}
        
    mock_scan_port.side_effect = side_effect
    
    progress_records = []
    def on_progress(res):
        progress_records.append(res)
        
    results = scan("127.0.0.1", [80, 22], on_progress=on_progress)
    
    assert len(results) == 2
    assert results[0]["port"] == 22
    assert results[0]["status"] == "open"
    assert results[1]["port"] == 80
    assert results[1]["status"] == "closed"
    
    # Progress callback was called for both
    assert len(progress_records) == 2
