import pytest
import socket
from unittest.mock import patch
from eavesdrop.utils import validate_ip_or_hostname, parse_ports, COMMON_PORTS, is_admin

def test_validate_ip_valid():
    assert validate_ip_or_hostname("127.0.0.1") == "127.0.0.1"
    assert validate_ip_or_hostname("8.8.8.8") == "8.8.8.8"

def test_validate_ip_invalid():
    with pytest.raises(ValueError):
        validate_ip_or_hostname("999.999.999.999")
    with pytest.raises(ValueError):
        validate_ip_or_hostname("")

@patch("socket.gethostbyname")
def test_validate_hostname_resolution(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"
    assert validate_ip_or_hostname("example.com") == "93.184.216.34"
    mock_gethostbyname.assert_called_once_with("example.com")

@patch("socket.gethostbyname")
def test_validate_hostname_resolution_fail(mock_gethostbyname):
    mock_gethostbyname.side_effect = socket.gaierror()
    with pytest.raises(ValueError):
        validate_ip_or_hostname("thisdomaindefinitelydoesnotexist12345.com")

def test_parse_ports_empty():
    # Should fallback to common ports sorted
    assert parse_ports("") == sorted(list(set(COMMON_PORTS)))
    assert parse_ports(None) == sorted(list(set(COMMON_PORTS)))
    assert parse_ports("  ") == sorted(list(set(COMMON_PORTS)))

def test_parse_ports_single():
    assert parse_ports("80") == [80]
    assert parse_ports("  443  ") == [443]

def test_parse_ports_list():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("80,80,22") == [22, 80] # duplicates removed, sorted

def test_parse_ports_range():
    assert parse_ports("80-83") == [80, 81, 82, 83]
    assert parse_ports("1000-1002, 22") == [22, 1000, 1001, 1002]

def test_parse_ports_errors():
    with pytest.raises(ValueError):
        parse_ports("abc")
    with pytest.raises(ValueError):
        parse_ports("80-70") # invalid range
    with pytest.raises(ValueError):
        parse_ports("0") # out of bounds
    with pytest.raises(ValueError):
        parse_ports("65536") # out of bounds
    with pytest.raises(ValueError):
        parse_ports("22, -80")

def test_is_admin():
    res = is_admin()
    assert isinstance(res, bool)

