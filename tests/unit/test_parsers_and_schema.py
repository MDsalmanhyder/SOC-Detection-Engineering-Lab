"""
Unit Tests for Log Parsers and Unified Normalized Schema.
"""

import pytest
from datetime import datetime
from normalizer.schema import NormalizedEvent, EventType, EventStatus, EventSource
from normalizer.parsers import LinuxAuthParser, WindowsSysmonParser, NetworkLogParser, AutoNormalizer


def test_linux_auth_ssh_failed():
    parser = LinuxAuthParser()
    raw = "Oct 10 09:15:23 ubuntu-srv sshd[1024]: Failed password for invalid user root from 192.0.2.45 port 54321 ssh2"
    event = parser.parse(raw)
    assert event is not None
    assert event.event_source == EventSource.LINUX_AUTH.value
    assert event.event_type == EventType.AUTHENTICATION.value
    assert event.action == "login_failed"
    assert event.status == EventStatus.FAILURE.value
    assert event.user == "root"
    assert event.source_ip == "192.0.2.45"
    assert event.source_port == 54321
    assert event.host == "ubuntu-srv"


def test_linux_auth_ssh_accepted():
    parser = LinuxAuthParser()
    raw = "Oct 10 09:16:00 ubuntu-srv sshd[1025]: Accepted password for lab-user from 192.0.2.45 port 54322 ssh2"
    event = parser.parse(raw)
    assert event is not None
    assert event.action == "login_success"
    assert event.status == EventStatus.SUCCESS.value
    assert event.user == "lab-user"


def test_linux_auth_sudo():
    parser = LinuxAuthParser()
    raw = "Oct 10 09:17:10 srv-app sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    event = parser.parse(raw)
    assert event is not None
    assert event.event_type == EventType.PRIVILEGE_CHANGE.value
    assert event.user == "alice"
    assert event.target_user == "root"
    assert event.command_line == "/bin/bash"


def test_windows_sysmon_process_create():
    parser = WindowsSysmonParser()
    raw = '{"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe", "CommandLine": "cmd.exe /c whoami", "Computer": "win-dc-01", "User": "CORP\\\\admin"}'
    event = parser.parse(raw)
    assert event is not None
    assert event.event_source == EventSource.SYSMON.value
    assert event.event_type == EventType.PROCESS_CREATION.value
    assert event.process_name == "cmd.exe"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.host == "win-dc-01"


def test_windows_security_logon_failed():
    parser = WindowsSysmonParser()
    raw = '{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "10.0.1.55", "Computer": "dc-01"}'
    event = parser.parse(raw)
    assert event is not None
    assert event.event_source == EventSource.WINDOWS_SECURITY.value
    assert event.event_type == EventType.AUTHENTICATION.value
    assert event.action == "login_failed"
    assert event.status == EventStatus.FAILURE.value
    assert event.user == "admin"
    assert event.source_ip == "10.0.1.55"


def test_network_parser_zeek_dns():
    parser = NetworkLogParser()
    raw = '{"event_type": "dns", "query": "corp-portal.internal.net", "src_ip": "10.0.1.10", "dest_ip": "1.1.1.1", "dest_port": 53}'
    event = parser.parse(raw)
    assert event is not None
    assert event.event_type == EventType.DNS_QUERY.value
    assert event.dns_query_name == "corp-portal.internal.net"
    assert event.source_ip == "10.0.1.10"


def test_auto_normalizer_dispatch():
    normalizer = AutoNormalizer()
    linux_raw = "Oct 10 10:00:00 test-host sshd[111]: Failed password for testuser from 10.0.0.2 port 2222 ssh2"
    ev1 = normalizer.normalize(linux_raw)
    assert ev1 is not None
    assert ev1.user == "testuser"

    win_raw = '{"EventID": 1, "Image": "C:\\\\powershell.exe", "CommandLine": "powershell.exe -enc AAAA"}'
    ev2 = normalizer.normalize(win_raw)
    assert ev2 is not None
    assert ev2.process_name == "powershell.exe"
