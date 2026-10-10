# MITRE ATT&CK® Defensive Coverage & Gap Analysis Report
**SOC Detection Engineering Lab**  
*Document Version: 1.0.0 | Evaluation Date: 2026-10-10*

---

## 1. Executive Summary & Coverage Philosophy

A mapped MITRE ATT&CK technique does not imply an effective detection. Many organizations color their ATT&CK heatmaps green after deploying a generic rule, only to find attackers easily bypass it using alternate execution syntax, timing variations, or obfuscation.

This project approaches detection engineering with an **adversarial hypothesis & empirical verification** standard:
- Every active detection rule in this repository has been tested against controlled synthetic attack telemetry.
- Explicit detection limitations and blind spots are formally documented.
- Gaps (techniques attempted but failed or untested) are openly declared to provide actionable intelligence for defensive engineering roadmaps.

---

## 2. Defensive Coverage Status Overview

```
Total MITRE ATT&CK Techniques Evaluated: 18
├── Detected Successfully (Proven In Harness) : 12 Techniques (66.7%)
├── Attempted but Failed / Partial Detection    : 3 Techniques (16.7%)
└── Untested (Planned Future Telemetry)        : 3 Techniques (16.7%)
```

### Coverage by Tactic

| Tactic ID | Tactic Name | Tested & Detected | Partial / Failed | Untested |
| :--- | :--- | :---: | :---: | :---: |
| **TA0001** | Initial Access | 1 | 0 | 0 |
| **TA0002** | Execution | 2 | 1 | 0 |
| **TA0003** | Persistence | 2 | 0 | 1 |
| **TA0004** | Privilege Escalation | 2 | 0 | 0 |
| **TA0005** | Defense Evasion | 2 | 1 | 1 |
| **TA0006** | Credential Access | 1 | 1 | 1 |
| **TA0007** | Discovery | 1 | 1 | 0 |
| **TA0009** | Collection & Exfiltration | 1 | 0 | 0 |
| **TA0011** | Command and Control | 1 | 0 | 0 |
| **TA0040** | Impact | 1 | 0 | 0 |

---

## 3. Techniques Detected Successfully (Proven In Harness)

| Rule ID | Technique ID | Technique Name | Tactic | Primary Log Source | Detection Logic Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-001** | `T1110.001` | Password Guessing | Credential Access | Linux Auth, WinEvent 4625 | Sliding-window threshold count ($\ge 5$ failures in 300s) |
| **DET-002** | `T1078` | Valid Accounts | Initial Access / Defense Evasion | Linux Auth, WinEvent 4624/4625 | Sequence correlation (failure burst followed by success) |
| **DET-003** | `T1059.003` | Windows Command Shell / LOLBAS | Execution / Evasion | Sysmon EventID 1 | Process name + URL/download command arguments |
| **DET-004** | `T1059.001` | PowerShell | Execution | Sysmon EventID 1 | Base64 encoded flags, WebClient cradle strings |
| **DET-005** | `T1562.001` | Impair Defenses: Disable Tools | Defense Evasion | WinEvent 1102, Sysmon 1, Linux auth | Event log clearing, security service termination |
| **DET-006** | `T1098` | Account Manipulation | Privilege Escalation | WinEvent 4728, Linux sudo/usermod | High-privilege group additions (Domain Admins, sudo) |
| **DET-007** | `T1547.001` | Registry Run Keys / Startup Folder | Persistence | Sysmon EventID 13 | Registry write to Run/RunOnce pointing to user/temp paths |
| **DET-008** | `T1053.005` | Scheduled Task | Persistence | Sysmon EventID 1 | `schtasks.exe /create` or crontab with suspicious payloads |
| **DET-009** | `T1046` | Network Service Discovery | Discovery | Zeek conn.log, NetFlow | Distinct destination port diversity ($\ge 10$ ports in 60s) |
| **DET-010** | `T1071.004` | Application Layer Protocol: DNS | Command & Control | Zeek dns.log, Sysmon 22 | Encoded high-entropy subdomain labels, tunnel markers |
| **DET-011** | `T1490` | Inhibit System Recovery | Impact / Defense Evasion | Sysmon EventID 1 | `vssadmin delete shadows`, `wmic shadowcopy delete` |
| **DET-012** | `T1048.003` | Exfiltration Over Alt Protocol | Exfiltration | Zeek conn.log, NetFlow | Cumulative sliding egress volume ($\ge 50$ MB to external IP) |

---

## 4. Techniques Attempted but Failed / Partial Coverage

Documenting where our detection hypotheses broke down when tested against adversarial evasion:

### A. T1059.001 — Unmanaged PowerShell Execution
- **Adversary Variation:** Executing PowerShell automation code directly via C# using `System.Management.Automation.PowerShell` (e.g., [PowerPick](https://github.com/PowerShellMafia/PowerSploit) or [Invisi-Shell](https://github.com/OmerAttias/Invisi-Shell)).
- **Why It Evaded DET-004:** The rule looks for process creation where `process_name` is `powershell.exe` or `pwsh.exe`. In unmanaged execution, the host binary is an arbitrary name (e.g. `MSBuild.exe` or custom `app.exe`).
- **Required Remediation:** Ingest Sysmon Event ID 7 (Image Loaded) for `System.Management.Automation.dll` or enable Windows Defender Application Control (WDAC) and PowerShell Script Block Logging (Event ID 4104).

### B. T1046 — Stealth / Low-and-Slow Port Scanning
- **Adversary Variation:** Running Nmap with timing template `-T0` (Paranoid: 1 probe every 5 minutes) or distributed scanning across a botnet.
- **Why It Evaded DET-009:** The rule aggregates distinct destination ports over a 60-second window. A probe every 5 minutes yields 1 probe per window, never crossing the threshold.
- **Required Remediation:** Stateful graph-based database or multi-day time series aggregation with baseline outlier scoring, or inline firewall IDS/IPS signature inspection (Suricata TCP SYN anomalies).

### C. T1110.003 — Low-and-Slow Password Spraying
- **Adversary Variation:** 1 login attempt per target user every 4 hours using rotating residential proxy IP addresses.
- **Why It Evaded DET-001:** Grouping by `(source_ip, user)` within 300s fails because both the source IP and time elapsed exceed the sliding window.
- **Required Remediation:** Centralized domain-wide identity analytics (Active Directory logon failure percentage across the entire enterprise over a 7-day rolling window).

---

## 5. Untested Techniques (Planned for Future Lab Releases)

| Technique ID | Technique Name | Tactic | Required Log Source | Planned Implementation |
| :--- | :--- | :--- | :--- | :--- |
| `T1055` | Process Injection | Privilege Escalation / Evasion | Sysmon EventID 8 (`CreateRemoteThread`) | Detect thread injection into `lsass.exe`, `explorer.exe`, or `svchost.exe` |
| `T1003.001` | OS Credential Dumping: LSASS Memory | Credential Access | Sysmon EventID 10 (`ProcessAccess`) | Detect `PROCESS_VM_READ` handles opened on LSASS by non-system binaries |
| `T1070.004` | Indicator Removal: File Deletion | Defense Evasion | Sysmon EventID 11 / 23 (`FileDelete`) | Detect batch file deletion or SDelete wiping activity |

---

## 6. Defensive Engineering Recommendations

1. **Layer Telemetry Sources:** Relying exclusively on command-line string matching is fragile against basic obfuscation (e.g. environment variables or caret insertion `c^m^d`). Couple process telemetry with parent-child ancestry, file create hashes, and network socket bindings.
2. **Dynamic Threshold Tuning:** As verified in our sensitivity benchmarks, static thresholds must be adjusted per subnet (e.g. developer workstations vs production database clusters).
3. **Continuous Automated Regression:** Any modification to rule YAML must run through the automated pytest test harness to ensure new filter exclusions do not create blind spots on known attack variants.
