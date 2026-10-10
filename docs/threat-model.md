# Threat Model: SOC Detection Engineering Lab

## 1. Scope & Objective
This threat model defines the adversary profiles, attack vectors, and telemetry visibility boundaries for the Detection Engineering Lab environment. The goal is to establish which adversary tactics are observable, which are detectable with high fidelity, and which fall into documented defensive blind spots.

---

## 2. Adversary Personas & Attacker Profiles

### A. Opportunistic Initial Access Broker (IAB)
- **Motivations:** Fast discovery, credential harvesting, initial foothold brokering.
- **Tools:** Automated SSH/RDP brute-force bots, mass port scanners, public LOLBAS staging scripts.
- **Tactics:** T1110.001 (Password Guessing), T1046 (Network Service Discovery), T1059.003 (Certutil download).
- **Visibility Profile:** Highly visible in authentication logs and process creation telemetry due to high activity frequency and standard tooling.

### B. Targeted Ransomware Operator
- **Motivations:** Host destruction, backup elimination, data extortion.
- **Tools:** PsExec, vssadmin, wevtutil, Mimikatz, encoded PowerShell stagers.
- **Tactics:** T1490 (Inhibit System Recovery), T1562.001 (Impair Defenses), T1059.001 (PowerShell Execution), T1547.001 (Persistence).
- **Visibility Profile:** Creates unmistakable high-severity signals (shadow copy deletion, event log clearing). Immediate detection is critical before encryption commences.

### C. Advanced Persistent Threat (APT) / Cyber Espionage
- **Motivations:** Long-term stealth persistence, intellectual property theft, covert data exfiltration.
- **Tools:** Custom in-memory loaders, living-off-the-land utilities, covert DNS tunnels, low-and-slow egress.
- **Tactics:** T1071.004 (DNS Tunneling), T1048.003 (Exfiltration Over Alt Protocol), T1078 (Valid Accounts).
- **Visibility Profile:** Difficult to detect via static signatures; requires behavioral aggregation, egress anomaly baselining, and sequence correlation.

---

## 3. Telemetry Visibility Matrix

| Telemetry Source | Visibility Coverage | Blind Spots | Mitigations |
| :--- | :--- | :--- | :--- |
| **Linux Auth Logs** | SSH logins, sudo executions, user additions, PAM failures | Direct console logins, kernel-level rootkits, unlogged daemon authentication | Auditd kernel rules, centralized rsyslog forwarding |
| **Windows Sysmon Event 1** | Process creation, command line arguments, parent processes, hashes | Arguments spoofed after creation, unmanaged code execution in memory | PowerShell ScriptBlock logging (EID 4104), Sysmon EID 7/8 |
| **Windows Sysmon Event 13** | Registry key writes to Run/RunOnce, Services, Security providers | Registry writes via kernel drivers or indirect COM loading | WMI event consumer monitoring, file integrity monitoring |
| **Zeek Network Logs** | Outbound TCP/UDP flows, total egress bytes, plaintext DNS queries | Encrypted TLS payload inspection, DNS over HTTPS (DoH) to public resolvers | TLS decryption proxy, firewall egress rule blocking external UDP 53/DoH IPs |

---

## 4. Detection Engineering Hypotheses

1. **Hypothesis H1 (Authentication):** An attacker guessing passwords generates an anomaly in failed logon frequency exceeding standard operational noise ($\ge 5$ attempts / 5 min).
2. **Hypothesis H2 (LOLBAS Staging):** Legitimate business workloads rarely execute `certutil.exe` or `bitsadmin.exe` with URL arguments pointing outside internal software distribution mirrors.
3. **Hypothesis H3 (Defense Evasion):** Legitimate administrators do not clear Windows Event Logs via `wevtutil cl` or stop security daemons without prior authorized change tickets.
4. **Hypothesis H4 (Covert C2):** DNS tunneling creates an observable statistical signature in DNS request labels (character count $\ge 25$, high Shannon entropy, or distinctive subdomain markers).
