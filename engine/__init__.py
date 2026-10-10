"""
Detection Engine Orchestrator.
Coordinates Evaluator, Stateful Correlator, and Alert Manager.
"""

import os
from typing import List, Optional, Dict, Any
from normalizer.schema import NormalizedEvent, Alert
from engine.evaluator import DetectionEvaluator, RuleDefinition
from engine.correlator import StatefulCorrelator
from engine.alert_manager import AlertManager


class DetectionEngine:
    """
    Central Detection Engine that ingests normalized events, evaluates rules,
    correlates events across windows, and outputs alerts.
    """
    def __init__(self, rules_dir: Optional[str] = None):
        self.evaluator = DetectionEvaluator()
        self.correlator = StatefulCorrelator()
        self.alert_manager = AlertManager()
        
        # Track statistics
        self.total_events_processed = 0
        self.total_alerts_generated = 0

        if rules_dir and os.path.exists(rules_dir):
            self.evaluator.load_rules(rules_dir)

    @property
    def rules(self) -> Dict[str, RuleDefinition]:
        return self.evaluator.rules

    def load_rules(self, rules_dir: str):
        self.evaluator.load_rules(rules_dir)

    def process_event(self, event: NormalizedEvent) -> List[Alert]:
        """
        Process a single normalized event through both single-event evaluator
        and stateful correlation engine.
        """
        self.total_events_processed += 1
        new_alerts: List[Alert] = []

        # 1. Add event to correlation buffer
        self.correlator.add_event(event)

        # 2. Evaluate single-event rules
        for rule_id, rule in self.evaluator.rules.items():
            if not rule.is_correlative:
                matched, explanation = self.evaluator.evaluate_single_event(event, rule)
                if matched:
                    alert = self.alert_manager.create_alert(
                        rule=rule,
                        trigger_event=event,
                        why_it_fired=explanation,
                        evidence={"matched_field": explanation, "raw": event.raw_log},
                        supporting_events=[event]
                    )
                    if alert:
                        new_alerts.append(alert)
                        self.total_alerts_generated += 1

        # 3. Evaluate stateful correlations
        correlations = self.correlator.evaluate_correlations(event, self.evaluator.rules)
        for rule, evidence, supporting_events in correlations:
            alert = self.alert_manager.create_alert(
                rule=rule,
                trigger_event=event,
                why_it_fired=evidence.get("summary", "Correlation condition satisfied"),
                evidence=evidence,
                supporting_events=supporting_events
            )
            if alert:
                new_alerts.append(alert)
                self.total_alerts_generated += 1

        return new_alerts

    def process_events(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Process a batch of events."""
        all_alerts = []
        for e in events:
            alerts = self.process_event(e)
            all_alerts.extend(alerts)
        return all_alerts

    def reset(self):
        """Reset internal buffers and alerts."""
        self.correlator.clear()
        self.alert_manager.clear()
        self.total_events_processed = 0
        self.total_alerts_generated = 0
