# Data Dictionary: Unified Normalized Event Schema

This document details the standardized schema fields implemented in `normalizer/schema.py` for endpoint, authentication, and network security telemetry.

---

## 1. Core Event Schema (`NormalizedEvent`)

| Field Name | Type | Required | Description | Example |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | String (UUID) | Yes | Unique identifier generated for the event | `e4b0c792-7d2e-4ef5-bc11-a8e99b0c6114` |
| `timestamp` | DateTime (UTC) | Yes | ISO-8601 formatted event occurrence timestamp | `2026-10-10T09:15:23.000Z` |
| `event_source` | String (Enum) | Yes | Telemetry origin subsystem (`LinuxAuth`, `Sysmon`, `WindowsSecurity`, `ZeekConn`, `ZeekDNS`, `Synthetic`) | `LinuxAuth` |
| `event_type` | String (Enum) | Yes | High-level taxonomy category (`authentication`, `process_creation`, `network_connection`, `registry_modification`, `privilege_change`, `persistence_change`, `dns_query`, `security_log_tampering`, `data_transfer`) | `authentication` |
| `action` | String | No | Granular event action (`login_failed`, `login_success`, `process_created`, `flow_recorded`, `group_member_added`, `audit_log_cleared`) | `login_failed` |
| `status` | String (Enum) | Yes | Event outcome: `success`, `failure`, or `unknown` | `failure` |
| `host` | String | Yes | Hostname or system endpoint name | `workstation-01` |
| `user` | String | No | Subject or initiating user account | `lab-user` |
| `source_ip` | String | No | Originating IPv4 or IPv6 network address | `192.0.2.25` |
| `source_port` | Integer | No | Originating source transport port | `49152` |
| `dest_ip` | String | No | Target IPv4 or IPv6 network address | `10.0.0.5` |
| `dest_port` | Integer | No | Destination transport port | `22` |
| `protocol` | String | No | Network protocol (`TCP`, `UDP`, `SSH`, `DNS`, `HTTP`) | `SSH` |
| `process_name` | String | No | Target or initiating process binary name | `powershell.exe` |
| `process_path` | String | No | Full file system path to executable | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `command_line` | String | No | Executed command line string with all arguments | `powershell.exe -enc SQBFAFg...` |
| `process_id` | Integer | No | Operating system Process ID (PID) | `4820` |
| `parent_process_name`| String | No | Spawning parent executable name | `cmd.exe` |
| `parent_command_line`| String | No | Spawning parent command line string | `cmd.exe /c start.bat` |
| `hashes` | Dictionary | No | Cryptographic file hashes (MD5, SHA1, SHA256) | `{"sha256": "3a7b..."}` |
| `registry_key` | String | No | Target Windows Registry key modified | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` |
| `registry_value` | String | No | Value name and data written to registry | `C:\Temp\payload.exe` |
| `target_user` | String | No | Target account modified during privilege operations | `backdoor-user` |
| `target_group` | String | No | Target security group modified | `Domain Admins` |
| `dns_query_name` | String | No | Fully Qualified Domain Name (FQDN) queried | `abc12345.tunnel.c2.net` |
| `bytes_out` | Integer | No | Outbound transfer byte volume | `52428800` |
| `bytes_in` | Integer | No | Inbound transfer byte volume | `12048` |
| `raw_log` | String | No | Preserved original raw log message before parsing | *Original syslog or JSON string* |

---

## 2. Actionable Alert Schema (`Alert`)

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `alert_id` | String | Actionable ticket identifier (`ALT-YYYYMMDDHHMMSS-XXXXXX`) |
| `rule_id` | String | Identifier of triggering detection rule (`DET-001` through `DET-012`) |
| `rule_name` | String | Human-readable title of rule |
| `rule_version` | String | Semantic version of rule specification |
| `severity` | String (Enum) | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `severity_rationale` | String | Defensive justification explaining why this severity was selected |
| `mitre_attack` | Object | MITRE ATT&CK reference (`tactic`, `technique_id`, `technique_name`, `url`) |
| `why_it_fired` | String | Clear technical explanation of the conditions that triggered the alert |
| `evidence` | Object | Extracted key indicators (counts, thresholds, process trees, queries) |
| `supporting_event_ids` | List[String] | Array of normalized event IDs that formed the detection evidence |
| `investigation_steps` | List[String] | Actionable triage checklist for the security analyst |
| `containment_steps` | List[String] | Recommended initial containment / remediation procedures |
| `status` | String (Enum) | `New`, `Triaged`, `True Positive`, `False Positive`, `Resolved` |
| `suppression_key` | String | Composite key used to prevent duplicate alerts during cooldown window |
