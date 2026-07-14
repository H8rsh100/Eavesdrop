from unittest.mock import patch, MagicMock
from eavesdrop.service_id import get_service_name, _parse_http_response, grab_banner

def test_get_service_name():
    # Test standard mapping
    assert get_service_name(22) == "SSH"
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    
    # Test unknown port
    assert get_service_name(61111) == "unknown"

def test_parse_http_response():
    resp_with_server = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"
    assert _parse_http_response(resp_with_server) == "HTTP/1.1 200 OK | Server: nginx/1.18.0"

    resp_no_server = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
    assert _parse_http_response(resp_no_server) == "HTTP/1.1 404 Not Found"

    assert _parse_http_response("") == ""

@patch("socket.socket")
def test_grab_banner_plain_tcp(mock_socket):
    mock_inst = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_inst
    
    # Simulate SSH banner returned on connect
    mock_inst.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    
    banner = grab_banner("127.0.0.1", 22)
    assert banner == "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
