# Detection Engineering Limitations & Blind Spots

## 1. Philosophical Grounding
In cybersecurity detection engineering, **there is no such thing as 100% detection coverage**. Every rule is an imperfect heuristic bounded by:
1. What telemetry is collected.
2. What time windows are evaluated.
3. How much adversary deviation or obfuscation is tolerated.

This document catalogs known limitations and evasion strategies across our lab's detection rules.

---

## 2. Rule-Specific Limitations & Evasion Analysis

### A. Authentication Rules (`DET-001`, `DET-002`)
- **Threshold Bypass via Low-and-Slow:** An adversary attempting 1 password attempt per hour per account easily bypasses a 300-second (5-minute) correlation window.
- **Source IP Rotation:** Attackers utilizing residential proxy networks (e.g. Luminati, Tor, or botnets) rotate the IP address for every attempt, defeating correlations grouped strictly by `source_ip`.
- **Application-Layer Log Blindness:** OS-level auth monitoring (`/var/log/auth.log` or Windows Event 4625) does not observe web application logins (Okta, Azure AD SSO, WordPress admin) unless application logs are explicitly ingested.

### B. Process & LOLBAS Rules (`DET-003`, `DET-004`)
- **Binary Renaming & Masquerading:** If an adversary copies `certutil.exe` to `C:\Users\Public\svchost.exe`, a rule matching `process_name == "certutil.exe"` will miss the execution unless `OriginalFileName` from Sysmon PE metadata is verified.
- **Command-Line Obfuscation:** In Windows Command Prompt, string concatenation and environment variables (`cmd.exe /c "set a=cert&& set b=util&& %a%%b% -urlcache ..."`) or carets (`c^e^r^t^u^t^i^l`) bypass naive substring matching.
- **Unmanaged PowerShell Execution:** Executing script payloads via custom C# binaries directly utilizing `System.Management.Automation` does not spawn `powershell.exe`.

### C. Persistence & Privilege Rules (`DET-006`, `DET-007`, `DET-008`)
- **Alternative Persistence Mechanisms:** Adversaries can persist via WMI Event Subscriptions, COM Hijacking, Office Add-ins, or Service DLL search order hijacking without touching Registry `Run` keys or `schtasks.exe`.
- **Shadow Admin Rights:** In Active Directory, granting `GenericAll` or `WriteDacl` permissions over an administrative OU grants equivalent compromise without adding an account to `Domain Admins`.

### D. Network & Data Exfiltration Rules (`DET-009`, `DET-010`, `DET-012`)
- **DNS over HTTPS (DoH):** If endpoint endpoints query Cloudflare `1.1.1.1` or Google `8.8.8.8` over HTTPS (port 443), internal DNS network tap sensors observe standard HTTPS traffic, completely blinding network DNS parsers.
- **Low-Throughput Egress Trickling:** Exfiltrating 100 MB at 10 KB per minute over 7 days circumvents short-term volumetric egress alerts ($\ge 50$ MB / 5 min).
- **Sanctioned Cloud SaaS Exfiltration:** Exfiltrating data directly to an attacker-controlled Microsoft OneDrive or AWS S3 bucket over trusted corporate TLS channels mimics authorized cloud workflows.

---

## 3. High-Volume Log Constraints & Architectural Trade-offs
- **In-Memory Windowing:** Sliding-window correlations require buffering recent events in memory. In enterprise networks producing 50,000 EPS (events per second), stateful windowing must be delegated to scalable stream-processing engines (Apache Flink, Kafka Streams, or ClickHouse sliding intervals) rather than in-memory Python structures.
- **Alert Suppression Window Trade-off:** A 600-second suppression window prevents alert storms, but could mask a secondary distinct attack phase against a different account if suppression keys are defined too broadly.
