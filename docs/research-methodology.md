# Research Methodology & Evaluation Framework

## 1. Scientific Standards for Detection Engineering
Detection engineering requires the same empirical rigor as experimental science:
1. **Hypothesis Formulation:** Define what adversary observable pattern is expected.
2. **Controlled Telemetry Generation:** Generate repeatable positive and negative test cases.
3. **Double-Blind Evaluation:** Run the detection engine over labeled datasets without rule modifications.
4. **Metric Quantification:** Calculate Precision, Recall, False Positive Rate, and F1 Score against an established ground truth manifest.
5. **Sensitivity Analysis:** Empirically vary parameters (thresholds, windows) to observe the trade-off frontier.

---

## 2. Telemetry Dataset Generation & Ground Truth

The synthetic test dataset was created using `datasets/generate_datasets.py` with seed determinism (`random.seed(42)`):

- **Benign Baseline Dataset (`datasets/synthetic/benign_baseline.jsonl`):**
  - 160 realistic events representing normal workstations and servers over a 4-hour operating period.
  - Includes occasional forgotten passwords (typos), routine developer execution (`notepad.exe`, `git.exe`, `python.exe -m pytest`), normal HTTPS egress, and approved domain lookups (`google.com`, `github.com`).
- **Attack Scenario Dataset (`datasets/synthetic/attack_scenarios.jsonl`):**
  - 38 attack events simulating 12 Atomic Red Team attack scenarios across all 12 detection rules.
- **Ground Truth Manifest (`datasets/manifests/ground_truth.json`):**
  - Explicitly maps each attack event ID and scenario to the expected rule trigger.

---

## 3. Mathematical Metric Definitions

Let:
- $TP$ = Number of genuine attack scenarios that correctly raised an alert for the expected rule.
- $FP$ = Number of benign events or unintended triggers that raised an alert.
- $FN$ = Number of genuine attack scenarios that failed to raise an alert.
- $TN$ = Number of benign events that did not raise an alert ($TotalBenign - FP$).

### A. Precision (Positive Predictive Value)
$$\text{Precision} = \frac{TP}{TP + FP}$$
Measures alert fidelity: what proportion of raised alerts represent genuine threats rather than false alarms?

### B. Recall (Sensitivity / True Positive Rate)
$$\text{Recall} = \frac{TP}{TP + FN}$$
Measures defensive coverage: what proportion of actual attack scenarios were successfully caught by the detection rules?

### C. False Positive Rate (FPR)
$$\text{FPR} = \frac{FP}{FP + TN}$$
Measures operational noise: what is the likelihood that normal operational activity triggers an alert?

### D. F1 Score (Harmonic Mean)
$$\text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
Balances the competing objectives of maximizing detection coverage while minimizing analyst alert fatigue.

### E. Detection Latency
$$\text{Latency} = t_{\text{alert}} - t_{\text{event\_ingestion}}$$
Measured in milliseconds ($\text{ms}$) using Python's high-resolution performance counter (`time.perf_counter()`).

---

## 4. Threshold Sensitivity Experiments
To evaluate rule resilience across diverse environments, the benchmark runner executes threshold sensitivity testing across varying thresholds on `DET-001` (Repeated Login Failures):

| Threshold | Precision | Recall | F1 Score | Finding |
| :---: | :---: | :---: | :---: | :--- |
| **3** | 100.0% | 100.0% | 1.0000 | Early warning; sensitive to password mistyping in noisy environments |
| **5 (Default)**| 100.0% | 100.0% | 1.0000 | Optimal balanced operational setting for workstations and jumpboxes |
| **8** | 100.0% | 100.0% | 1.0000 | Catches 8-attempt brute force right on the boundary |
| **12** | 0.0% | 0.0% | 0.0000 | **Detection Failure (FN=1):** Attack terminates at 8 attempts, threshold never breached |
