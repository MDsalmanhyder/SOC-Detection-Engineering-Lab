# SOC Detection Engineering Lab: Benchmark & Evaluation Report

**Generated:** 2026-10-10 09:41:55 UTC  
**Total Telemetry Events Evaluated:** 198 (160 Benign, 38 Attack Events)  
**Total Alerts Raised:** 13  

## 1. Executive Summary & Macro Metrics

| Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Overall Precision** | **92.3%** | Percentage of raised alerts that correspond to genuine attacks |
| **Overall Recall (Sensitivity)** | **100.0%** | Percentage of attack scenarios successfully identified |
| **Overall F1 Score** | **0.9600** | Harmonic mean of precision and recall |
| **False Positive Rate (FPR)** | **0.63%** | Probability of benign activity incorrectly triggering alerts |
| **Mean Detection Latency** | **1.89 ms** | Average processing time from event ingestion to alert emission |

## 2. Per-Rule Detection Performance Matrix

| Rule ID | Rule Title | TP | FP | FN | Precision | Recall | F1 | Mean Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `DET-001` | Repeated Authentication Failures (Poss... | 1 | 1 | 0 | 50.0% | 100.0% | 0.67 | 0.81 ms |
| `DET-002` | Successful Authentication Immediately ... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 1.33 ms |
| `DET-003` | Suspicious Process Execution (LOLBAS /... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.24 ms |
| `DET-004` | Suspicious PowerShell Activity (Encode... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 3.43 ms |
| `DET-005` | Security Logging Disabled or Audit Log... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.44 ms |
| `DET-006` | Unauthorized Privilege Group Modificat... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.19 ms |
| `DET-007` | Suspicious Persistence via Registry Ru... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.17 ms |
| `DET-008` | Suspicious Scheduled Task or Cron Job ... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.54 ms |
| `DET-009` | Port Scan Behavior (Network Service Di... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 1.18 ms |
| `DET-010` | DNS Anomalies (Tunneling, High-Entropy... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 1.02 ms |
| `DET-011` | Shadow Copy Deletion or System Recover... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 13.24 ms |
| `DET-012` | Large Outbound Data Transfer (Potentia... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 1.22 ms |

## 3. Threshold Sensitivity Experiments (DET-001 Brute Force)

Empirical investigation demonstrating the fundamental engineering trade-off between sensitivity and false positives:

| Threshold (Failures) | TP | FP | FN | Precision | Recall | F1 Score | Engineering Impact |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **3** | 1 | 0 | 0 | 100.0% | 100.0% | 1.0000 | Threshold 3: Catches attack |
| **5** | 1 | 0 | 0 | 100.0% | 100.0% | 1.0000 | Threshold 5: Catches attack |
| **8** | 1 | 0 | 0 | 100.0% | 100.0% | 1.0000 | Threshold 8: Catches attack |
| **12** | 0 | 0 | 1 | 0.0% | 0.0% | 0.0000 | Threshold 12: Misses small brute force |

### Analysis of Threshold Results
- **Threshold = 3**: Maximizes early detection, but increases susceptibility to false alarms from users forgetting passwords after rotation.
- **Threshold = 5 (Default)**: Optimal balance in small/medium corporate environments, detecting typical automated credential spray without excessive noise.
- **Threshold = 12**: Severely degrades Recall (0.0% on 8-attempt brute force) as attacker activity terminates before the threshold is breached, highlighting why static thresholds must be tuned to environment baselines.

---
*Report generated automatically by the SOC Detection Engineering Lab Benchmark Runner.*