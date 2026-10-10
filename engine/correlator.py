"""
Event Correlator and Sliding Window Aggregator.
Implements stateful event correlation:
- Threshold frequency aggregation (DET-001)
- Sequence detection (DET-002)
- Distinct port counting for port scans (DET-009)
- Cumulative volume summation for data exfiltration (DET-012)
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from normalizer.schema import NormalizedEvent, EventType, EventStatus
from engine.evaluator import RuleDefinition


class StatefulCorrelator:
    """
    Maintains sliding event buffers and evaluates correlation logic.
    """
    def __init__(self):
        # Buffer for all incoming normalized events
        self.events_buffer: List[NormalizedEvent] = []
        # Dynamic threshold overrides (rule_id -> dict of param overrides)
        self.threshold_overrides: Dict[str, Dict[str, Any]] = {}

    def set_threshold_override(self, rule_id: str, overrides: Dict[str, Any]):
        """Allows testing precision/recall with tuned thresholds."""
        self.threshold_overrides[rule_id] = overrides

    def add_event(self, event: NormalizedEvent):
        """Add event to correlator buffer."""
        self.events_buffer.append(event)
        # Keep buffer sorted by timestamp if out of order
        # and trim events older than 24 hours to prevent memory growth
        cutoff = event.timestamp - timedelta(hours=24)
        if len(self.events_buffer) > 10000:
            self.events_buffer = [e for e in self.events_buffer if e.timestamp >= cutoff]

    def clear(self):
        self.events_buffer.clear()

    def evaluate_correlations(self, current_event: NormalizedEvent, rules: Dict[str, RuleDefinition]) -> List[Tuple[RuleDefinition, Dict[str, Any], List[NormalizedEvent]]]:
        """
        Evaluate correlative rules against the buffer ending at current_event.
        Returns list of (rule, evidence_dict, supporting_events).
        """
        results = []

        # DET-001: Repeated Login Failures
        if "DET-001" in rules:
            rule = rules["DET-001"]
            matched, evidence, supporting = self._eval_det_001(current_event, rule)
            if matched:
                results.append((rule, evidence, supporting))

        # DET-002: Successful Login After Failures
        if "DET-002" in rules:
            rule = rules["DET-002"]
            matched, evidence, supporting = self._eval_det_002(current_event, rule)
            if matched:
                results.append((rule, evidence, supporting))

        # DET-009: Port Scan Behavior
        if "DET-009" in rules:
            rule = rules["DET-009"]
            matched, evidence, supporting = self._eval_det_009(current_event, rule)
            if matched:
                results.append((rule, evidence, supporting))

        # DET-012: Large Outbound Data Transfer
        if "DET-012" in rules:
            rule = rules["DET-012"]
            matched, evidence, supporting = self._eval_det_012(current_event, rule)
            if matched:
                results.append((rule, evidence, supporting))

        return results

    def _eval_det_001(self, current_event: NormalizedEvent, rule: RuleDefinition) -> Tuple[bool, Dict[str, Any], List[NormalizedEvent]]:
        """
        Threshold detection: count of login_failed events within window >= threshold.
        """
        if current_event.event_type != EventType.AUTHENTICATION.value or current_event.action != "login_failed":
            return False, {}, []

        # Tunable parameters
        overrides = self.threshold_overrides.get("DET-001", {})
        threshold = overrides.get("threshold", rule.threshold.get("default_count", 5))
        window_sec = overrides.get("window_seconds", rule.threshold.get("time_window_seconds", 300))

        key_ip = current_event.source_ip
        key_user = current_event.user
        window_start = current_event.timestamp - timedelta(seconds=window_sec)

        # Collect matching failures in window
        matched_events = []
        for e in self.events_buffer:
            if (e.timestamp >= window_start and e.timestamp <= current_event.timestamp and
                e.event_type == EventType.AUTHENTICATION.value and e.action == "login_failed"):
                # Check grouping (same source_ip or same user)
                if (key_ip and e.source_ip == key_ip) or (key_user and e.user == key_user):
                    matched_events.append(e)

        if len(matched_events) >= threshold:
            evidence = {
                "failed_attempts_count": len(matched_events),
                "threshold_configured": threshold,
                "time_window_seconds": window_sec,
                "target_user": key_user,
                "source_ip": key_ip,
                "summary": f"{len(matched_events)} failed login attempts for account '{key_user or key_ip or 'unknown'}' detected within {window_sec} seconds (threshold: {threshold})"
            }
            return True, evidence, matched_events

        return False, {}, []

    def _eval_det_002(self, current_event: NormalizedEvent, rule: RuleDefinition) -> Tuple[bool, Dict[str, Any], List[NormalizedEvent]]:
        """
        Sequence detection: Burst of login failures followed by login_success.
        """
        if current_event.event_type != EventType.AUTHENTICATION.value or current_event.action != "login_success":
            return False, {}, []

        overrides = self.threshold_overrides.get("DET-002", {})
        threshold = overrides.get("failure_threshold", rule.threshold.get("default_failure_count", 4))
        window_sec = overrides.get("window_seconds", rule.threshold.get("time_window_seconds", 600))

        key_user = current_event.user
        if not key_user:
            return False, {}, []

        window_start = current_event.timestamp - timedelta(seconds=window_sec)

        # Collect preceding failures for this user
        failures = []
        for e in self.events_buffer:
            if (e.timestamp >= window_start and e.timestamp < current_event.timestamp and
                e.event_type == EventType.AUTHENTICATION.value and e.action == "login_failed" and
                e.user == key_user):
                failures.append(e)

        if len(failures) >= threshold:
            evidence = {
                "preceding_failed_logins": len(failures),
                "threshold_required": threshold,
                "time_window_seconds": window_sec,
                "target_user": key_user,
                "source_ip": current_event.source_ip,
                "success_event_id": current_event.event_id,
                "summary": f"{len(failures)} failed login attempts followed by successful logon for account '{key_user}' within {window_sec}s"
            }
            supporting = failures + [current_event]
            return True, evidence, supporting

        return False, {}, []

    def _eval_det_009(self, current_event: NormalizedEvent, rule: RuleDefinition) -> Tuple[bool, Dict[str, Any], List[NormalizedEvent]]:
        """
        Distinct count detection: probing distinct destination ports >= threshold within window.
        """
        if current_event.event_type != EventType.NETWORK_CONNECTION.value or not current_event.dest_port:
            return False, {}, []

        overrides = self.threshold_overrides.get("DET-009", {})
        threshold = overrides.get("threshold", rule.threshold.get("default_distinct_ports", 10))
        window_sec = overrides.get("window_seconds", rule.threshold.get("time_window_seconds", 60))

        src_ip = current_event.source_ip
        if not src_ip:
            return False, {}, []

        window_start = current_event.timestamp - timedelta(seconds=window_sec)

        distinct_ports = set()
        matched_events = []
        for e in self.events_buffer:
            if (e.timestamp >= window_start and e.timestamp <= current_event.timestamp and
                e.event_type == EventType.NETWORK_CONNECTION.value and e.source_ip == src_ip and e.dest_port):
                distinct_ports.add(e.dest_port)
                matched_events.append(e)

        if len(distinct_ports) >= threshold:
            evidence = {
                "distinct_destination_ports_count": len(distinct_ports),
                "distinct_ports_sampled": sorted(list(distinct_ports))[:15],
                "threshold_configured": threshold,
                "time_window_seconds": window_sec,
                "source_ip": src_ip,
                "dest_ip": current_event.dest_ip,
                "summary": f"Host {src_ip} probed {len(distinct_ports)} distinct destination ports within {window_sec}s (threshold: {threshold})"
            }
            return True, evidence, matched_events

        return False, {}, []

    def _eval_det_012(self, current_event: NormalizedEvent, rule: RuleDefinition) -> Tuple[bool, Dict[str, Any], List[NormalizedEvent]]:
        """
        Sum aggregation: outbound data volume >= threshold bytes within window.
        """
        if (current_event.bytes_out or 0) <= 0:
            return False, {}, []

        overrides = self.threshold_overrides.get("DET-012", {})
        threshold_bytes = overrides.get("threshold_bytes", rule.threshold.get("default_bytes", 52428800))
        window_sec = overrides.get("window_seconds", rule.threshold.get("time_window_seconds", 300))

        src_ip = current_event.source_ip
        dest_ip = current_event.dest_ip
        if not src_ip:
            return False, {}, []

        window_start = current_event.timestamp - timedelta(seconds=window_sec)

        total_bytes = 0
        matched_events = []
        for e in self.events_buffer:
            if (e.timestamp >= window_start and e.timestamp <= current_event.timestamp and
                e.source_ip == src_ip and (not dest_ip or e.dest_ip == dest_ip)):
                b = e.bytes_out or 0
                if b > 0:
                    total_bytes += b
                    matched_events.append(e)

        if total_bytes >= threshold_bytes:
            mb = round(total_bytes / (1024 * 1024), 2)
            thresh_mb = round(threshold_bytes / (1024 * 1024), 2)
            evidence = {
                "total_bytes_out": total_bytes,
                "total_megabytes_out": mb,
                "threshold_megabytes": thresh_mb,
                "source_ip": src_ip,
                "dest_ip": dest_ip,
                "summary": f"{mb} MB outbound egress detected from {src_ip} to {dest_ip} within {window_sec}s (threshold: {thresh_mb} MB)"
            }
            return True, evidence, matched_events

        return False, {}, []
