"""
Evaluation Metrics for Detection Engineering.
Calculates Confusion Matrix, Precision, Recall, False Positive Rate (FPR),
F1-Score, and Detection Latency.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class DetectionMetrics(BaseModel):
    rule_id: str
    rule_name: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    precision: float = 0.0
    recall: float = 0.0
    false_positive_rate: float = 0.0
    f1_score: float = 0.0
    
    mean_latency_ms: float = 0.0
    latencies_ms: List[float] = Field(default_factory=list)

    def calculate(self):
        """Compute standard statistical classification metrics."""
        tp = self.true_positives
        fp = self.false_positives
        tn = self.true_negatives
        fn = self.false_negatives

        # Precision = TP / (TP + FP)
        self.precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        
        # Recall = TP / (TP + FN)
        self.recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        
        # FPR = FP / (FP + TN)
        self.false_positive_rate = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        
        # F1 = 2 * (P * R) / (P + R)
        if (self.precision + self.recall) > 0:
            self.f1_score = round(2 * (self.precision * self.recall) / (self.precision + self.recall), 4)
        else:
            self.f1_score = 0.0

        if self.latencies_ms:
            self.mean_latency_ms = round(sum(self.latencies_ms) / len(self.latencies_ms), 2)


class SystemEvaluationResult(BaseModel):
    total_events: int = 0
    total_benign_events: int = 0
    total_attack_events: int = 0
    total_alerts_raised: int = 0
    
    overall_true_positives: int = 0
    overall_false_positives: int = 0
    overall_true_negatives: int = 0
    overall_false_negatives: int = 0
    
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    overall_f1_score: float = 0.0
    overall_fpr: float = 0.0
    
    mean_detection_latency_ms: float = 0.0
    rule_metrics: Dict[str, DetectionMetrics] = Field(default_factory=dict)
    threshold_experiments: List[Dict[str, Any]] = Field(default_factory=list)

    def calculate_overall(self):
        tp = sum(m.true_positives for m in self.rule_metrics.values())
        fp = sum(m.false_positives for m in self.rule_metrics.values())
        fn = sum(m.false_negatives for m in self.rule_metrics.values())
        tn = self.total_benign_events - fp

        self.overall_true_positives = tp
        self.overall_false_positives = fp
        self.overall_true_negatives = max(0, tn)
        self.overall_false_negatives = fn

        self.overall_precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        self.overall_recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        self.overall_fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        if (self.overall_precision + self.overall_recall) > 0:
            self.overall_f1_score = round(
                2 * (self.overall_precision * self.overall_recall) / (self.overall_precision + self.overall_recall), 4
            )
        else:
            self.overall_f1_score = 0.0

        all_latencies = []
        for m in self.rule_metrics.values():
            all_latencies.extend(m.latencies_ms)
        if all_latencies:
            self.mean_detection_latency_ms = round(sum(all_latencies) / len(all_latencies), 2)
