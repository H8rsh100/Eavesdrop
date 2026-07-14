from unittest.mock import patch, ANY
import pytest
from eavesdrop.cli import parse_args, main

def test_parse_args():
    args = parse_args(["--target", "127.0.0.1", "--ports", "80-100", "--scan-type", "syn"])
    assert args.target == "127.0.0.1"
    assert args.ports == "80-100"
    assert args.scan_type == "syn"
    assert args.timeout == 1.0
    assert args.threads == 100

@patch("eavesdrop.cli.validate_ip_or_hostname")
@patch("eavesdrop.cli.parse_ports")
@patch("eavesdrop.cli.is_admin")
@patch("eavesdrop.cli.write_output")
@patch("eavesdrop.scanners.tcp_connect.scan")
def test_main_tcp_connect(mock_scan, mock_write_output, mock_is_admin, mock_parse_ports, mock_validate):
    mock_validate.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_is_admin.return_value = False
    mock_scan.return_value = [{"port": 80, "status": "open", "service": "HTTP", "banner": ""}]
    
    main(["--target", "localhost", "--ports", "80", "--scan-type", "tcp"])
    
    mock_validate.assert_called_once_with("localhost")
    mock_parse_ports.assert_called_once_with("80")
    mock_scan.assert_called_once_with(
        ip="127.0.0.1",
        ports=[80],
        timeout=1.0,
        threads=100,
        on_progress=ANY
    )
    mock_write_output.assert_called_once()

@patch("eavesdrop.cli.validate_ip_or_hostname")
@patch("eavesdrop.cli.parse_ports")
@patch("eavesdrop.cli.is_admin")
@patch("eavesdrop.cli.write_output")
@patch("eavesdrop.scanners.tcp_connect.scan")
def test_main_fallback_to_tcp(mock_scan, mock_write_output, mock_is_admin, mock_parse_ports, mock_validate):
    mock_validate.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [22]
    mock_is_admin.return_value = False # Not admin, should trigger fallback
    mock_scan.return_value = [{"port": 22, "status": "open", "service": "SSH", "banner": ""}]
    
    # Attempting SYN scan without admin privilege
    main(["--target", "127.0.0.1", "--ports", "22", "--scan-type", "syn"])
    
    # Should fall back to TCP connect scan
    mock_scan.assert_called_once_with(
        ip="127.0.0.1",
        ports=[22],
        timeout=1.0,
        threads=100,
        on_progress=ANY
    )
