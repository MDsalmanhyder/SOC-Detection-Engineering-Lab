"""
Negative Detection Tests.
Verifies that benign and routine administrative activity does not trigger false positive alerts.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from normalizer.schema import NormalizedEvent, EventType, EventStatus
from engine import DetectionEngine


@pytest.fixture
def engine():
    rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
    return DetectionEngine(rules_dir=rules_path)


def test_benign_single_password_typo_no_alert(engine):
    """A single forgotten password must NOT fire DET-001 (threshold is 5)."""
    ev = NormalizedEvent(
        event_type=EventType.AUTHENTICATION.value,
        action="login_failed",
        status=EventStatus.FAILURE.value,
        user="bob",
        source_ip="10.0.1.20",
        host="ws-finance"
    )
    alerts = engine.process_event(ev)
    assert len(alerts) == 0


def test_benign_normal_process_execution_no_alert(engine):
    """Normal notepad, git, python, or chrome execution must not fire LOLBAS or PowerShell alerts."""
    procs = [
        ("notepad.exe", "notepad.exe C:\\Users\\alice\\memo.txt"),
        ("git.exe", "git.exe status"),
        ("python.exe", "python.exe -m pytest tests/"),
        ("chrome.exe", "chrome.exe --profile-directory=Default")
    ]
    for p_name, cmd in procs:
        ev = NormalizedEvent(
            event_type=EventType.PROCESS_CREATION.value,
            process_name=p_name,
            command_line=cmd,
            host="ws-sales"
        )
        alerts = engine.process_event(ev)
        assert len(alerts) == 0


def test_benign_dns_standard_lookups_no_alert(engine):
    """Legitimate corporate or internet domain lookups must not fire DNS tunneling alerts."""
    domains = ["google.com", "login.microsoftonline.com", "github.com", "intranet.local"]
    for d in domains:
        ev = NormalizedEvent(
            event_type=EventType.DNS_QUERY.value,
            dns_query_name=d,
            source_ip="10.0.1.15",
            host="sensor"
        )
        alerts = engine.process_event(ev)
        assert len(alerts) == 0


def test_benign_small_outbound_data_transfer_no_alert(engine):
    """Normal web traffic (e.g. 15 KB) must not fire large outbound transfer alert."""
    ev = NormalizedEvent(
        event_type=EventType.DATA_TRANSFER.value,
        source_ip="10.0.1.15",
        dest_ip="142.250.180.206",
        bytes_out=15000, # 15 KB
        host="sensor"
    )
    alerts = engine.process_event(ev)
    assert len(alerts) == 0


def test_benign_certutil_hash_verification_no_alert(engine):
    """Using certutil only to compute file hash (-hashfile) must not trigger download LOLBAS alert."""
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="certutil.exe",
        command_line="certutil.exe -hashfile installer.exe SHA256",
        host="ws-dev-01"
    )
    alerts = engine.process_event(ev)
    assert len(alerts) == 0
