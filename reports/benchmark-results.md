# SOC Detection Engineering Lab: Benchmark & Evaluation Report

**Generated:** 2026-10-11 12:29:47 UTC  
**Total Telemetry Events Evaluated:** 208 (160 Benign, 48 Attack Events)  
**Total Alerts Raised:** 23  

## 1. Executive Summary & Macro Metrics

| Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Overall Precision** | **78.3%** | Percentage of raised alerts that correspond to genuine attacks |
| **Overall Recall (Sensitivity)** | **100.0%** | Percentage of attack scenarios successfully identified |
| **Overall F1 Score** | **0.8780** | Harmonic mean of precision and recall |
| **False Positive Rate (FPR)** | **3.12%** | Probability of benign activity incorrectly triggering alerts |
| **Mean Detection Latency** | **0.28 ms** | Average processing time from event ingestion to alert emission |

## 2. Per-Rule Detection Performance Matrix

| Rule ID | Rule Title | TP | FP | FN | Precision | Recall | F1 | Mean Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `DET-001` | Repeated Authentication Failures (Poss... | 1 | 1 | 0 | 50.0% | 100.0% | 0.67 | 0.47 ms |
| `DET-002` | Successful Authentication Immediately ... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.49 ms |
| `DET-003` | Suspicious Process Execution (LOLBAS /... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.17 ms |
| `DET-004` | Suspicious PowerShell Activity (Encode... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.15 ms |
| `DET-005` | Security Logging Disabled or Audit Log... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.13 ms |
| `DET-006` | Unauthorized Privilege Group Modificat... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.11 ms |
| `DET-007` | Suspicious Persistence via Registry Ru... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.10 ms |
| `DET-008` | Suspicious Scheduled Task or Cron Job ... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.12 ms |
| `DET-009` | Port Scan Behavior (Network Service Di... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.74 ms |
| `DET-010` | DNS Anomalies (Tunneling, High-Entropy... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.14 ms |
| `DET-011` | Shadow Copy Deletion or System Recover... | 1 | 1 | 0 | 50.0% | 100.0% | 0.67 | 0.16 ms |
| `DET-012` | Large Outbound Data Transfer (Potentia... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.27 ms |
| `DET-013` | Kerberoasting Service Ticket Request (... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.10 ms |
| `DET-014` | DCSync Active Directory Replication Ab... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.14 ms |
| `DET-015` | Trusted Developer Utility Proxy Execut... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.16 ms |
| `DET-016` | Remote Thread Process Injection (Creat... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.14 ms |
| `DET-017` | Ransomware Recovery Tampering (BCDEdit... | 1 | 0 | 0 | 100.0% | 100.0% | 1.00 | 0.19 ms |
| `DET-018` | Command and Control Web Periodic Beaco... | 1 | 3 | 0 | 25.0% | 100.0% | 0.40 | 0.74 ms |

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