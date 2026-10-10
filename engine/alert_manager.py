"""
Alert Manager and Deduplication/Suppression Engine.
Generates rich investigation records, enforces suppression windows, and manages alert lifecycles.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import uuid
from normalizer.schema import (
    Alert, NormalizedEvent, Severity, AlertStatus, MitreAttackRef
)
from engine.evaluator import RuleDefinition


class AlertManager:
    """
    Manages alert generation, deduplication, suppression windows, and analyst lifecycle updates.
    """
    def __init__(self):
        self.alerts: List[Alert] = []
        # Map of suppression_key -> datetime of last fired alert
        self.suppression_table: Dict[str, datetime] = {}
        # Count of suppressed triggers
        self.suppressed_counts: Dict[str, int] = {}

    def get_all_alerts(self) -> List[Alert]:
        return self.alerts

    def clear(self):
        self.alerts.clear()
        self.suppression_table.clear()
        self.suppressed_counts.clear()

    def generate_suppression_key(self, rule: RuleDefinition, event: NormalizedEvent) -> str:
        """
        Derives suppression key based on rule configuration.
        Default key: rule_id + host + (source_ip or user)
        """
        supp = rule.suppression
        keys = supp.get("keys", ["source_ip", "user"])
        parts = [rule.id, event.host]
        for k in keys:
            val = getattr(event, k, None) or ""
            parts.append(str(val))
        return ":".join(parts)

    def is_suppressed(self, rule: RuleDefinition, event: NormalizedEvent, current_time: datetime) -> bool:
        """
        Checks if an alert for this key is currently within its suppression cooldown window.
        """
        supp = rule.suppression
        window_sec = supp.get("window_seconds", 600)
        key = self.generate_suppression_key(rule, event)

        if key in self.suppression_table:
            last_fired = self.suppression_table[key]
            if current_time - last_fired < timedelta(seconds=window_sec):
                self.suppressed_counts[key] = self.suppressed_counts.get(key, 0) + 1
                return True

        return False

    def create_alert(
        self,
        rule: RuleDefinition,
        trigger_event: NormalizedEvent,
        why_it_fired: str,
        evidence: Dict[str, Any],
        supporting_events: List[NormalizedEvent],
        force: bool = False
    ) -> Optional[Alert]:
        """
        Creates and stores an actionable Alert record unless suppressed.
        """
        ts = trigger_event.timestamp
        supp_key = self.generate_suppression_key(rule, trigger_event)

        if not force and self.is_suppressed(rule, trigger_event, ts):
            # Suppressed to prevent alert storm
            return None

        # Update suppression timestamp
        self.suppression_table[supp_key] = ts

        # Determine time window
        window_start = supporting_events[0].timestamp if supporting_events else ts
        window_end = trigger_event.timestamp

        # Extract supporting event summaries and IDs
        supp_ids = [e.event_id for e in supporting_events]
        supp_summaries = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "user": e.user,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "raw": e.raw_log
            }
            for e in supporting_events[:20]  # Store first 20 supporting events for inspection
        ]

        # Extract analyst investigation and containment steps from rule
        inv_steps = rule.investigation.get("steps", [
            "1. Verify source IP ownership and user authentication context.",
            "2. Cross-reference process timeline and parent execution tree.",
            "3. Inspect surrounding network egress and DNS queries.",
            "4. Determine if legitimate administrative task or credential compromise.",
            "5. Apply containment isolation if indicators of attack are confirmed."
        ])

        containment_steps = [
            f"Isolate host '{trigger_event.host}' from network if malicious activity is verified.",
            f"Reset credentials for user '{trigger_event.user or 'target account'}' and terminate active sessions.",
            f"Block source IP '{trigger_event.source_ip or 'attacker IP'}' at the perimeter firewall."
        ]

        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.title,
            rule_version=rule.version,
            severity=rule.get_severity(),
            severity_rationale=rule.severity_rationale or f"Rule {rule.id} triggered with severity {rule.level}",
            created_at=datetime.now(timezone.utc),
            event_window_start=window_start,
            event_window_end=window_end,
            affected_host=trigger_event.host,
            affected_user=trigger_event.user,
            source_ip=trigger_event.source_ip,
            dest_ip=trigger_event.dest_ip,
            mitre_attack=rule.mitre,
            why_it_fired=why_it_fired,
            evidence=evidence,
            supporting_event_ids=supp_ids,
            supporting_events=supp_summaries,
            investigation_steps=inv_steps,
            containment_steps=containment_steps,
            status=AlertStatus.NEW,
            suppression_key=supp_key
        )

        self.alerts.append(alert)
        return alert

    def update_alert_status(self, alert_id: str, new_status: AlertStatus, note: Optional[str] = None) -> Optional[Alert]:
        """Update analyst status (e.g. Triaged, True Positive, False Positive, Resolved)."""
        for a in self.alerts:
            if a.alert_id == alert_id:
                a.status = new_status
                if note:
                    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    a.analyst_notes.append(f"[{now_str}] Status -> {new_status.value}: {note}")
                return a
        return None
