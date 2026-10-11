"""
Rule Loader and Single-Event Evaluator.
Parses Sigma YAML rules, matches pattern selections, and evaluates events.
"""

import os
import re
import glob
import yaml
from typing import Dict, List, Any, Optional, Tuple
from normalizer.schema import NormalizedEvent, Severity, MitreAttackRef


class RuleDefinition:
    def __init__(self, raw_data: Dict[str, Any], filepath: str):
        self.raw_data = raw_data
        self.filepath = filepath
        self.id = raw_data.get("id", "DET-UNKNOWN")
        self.uuid = raw_data.get("uuid", "")
        self.title = raw_data.get("title", "")
        self.status = raw_data.get("status", "experimental")
        self.version = str(raw_data.get("version", "1.0.0"))
        self.description = raw_data.get("description", "").strip()
        self.hypothesis = raw_data.get("hypothesis", "").strip()
        self.level = raw_data.get("level", "medium").capitalize()
        self.logsource = raw_data.get("logsource", {})
        self.detection = raw_data.get("detection", {})
        self.threshold = raw_data.get("threshold", {})
        self.suppression = raw_data.get("suppression", {})
        self.falsepositives = raw_data.get("falsepositives", [])
        self.limitations = raw_data.get("limitations", [])
        self.investigation = raw_data.get("investigation", {})
        self.severity_rationale = raw_data.get("severity_rationale", "").strip()
        
        mitre = raw_data.get("mitre_attack", {})
        self.mitre = MitreAttackRef(
            tactic=mitre.get("tactic", "Unknown"),
            technique_id=mitre.get("technique_id", "Unknown"),
            technique_name=mitre.get("technique_name", "Unknown"),
            subtechnique_id=mitre.get("subtechnique_id"),
            url=mitre.get("url")
        )

        self.is_correlative = "correlation" in self.detection

    def get_severity(self) -> Severity:
        lvl = self.level.capitalize()
        if lvl == "Critical":
            return Severity.CRITICAL
        elif lvl == "High":
            return Severity.HIGH
        elif lvl == "Low":
            return Severity.LOW
        elif lvl == "Informational":
            return Severity.INFORMATIONAL
        return Severity.MEDIUM


class DetectionEvaluator:
    """
    Evaluator that loads Sigma YAML rules and matches normalized security events.
    """
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: Dict[str, RuleDefinition] = {}
        if rules_dir:
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        """Recursively load all .yml or .yaml rule files."""
        pattern = os.path.join(rules_dir, "**", "*.y*ml")
        files = glob.glob(pattern, recursive=True)
        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data:
                        rule = RuleDefinition(data, filepath)
                        self.rules[rule.id] = rule
            except Exception as e:
                print(f"Error loading rule from {filepath}: {e}")

    def evaluate_single_event(self, event: NormalizedEvent, rule: RuleDefinition) -> Tuple[bool, str]:
        """
        Evaluate non-correlative, single-event rules.
        Returns (matched, explanation).
        """
        det = rule.detection
        if not det:
            return False, ""

        # DET-003: LOLBAS Execution
        if rule.id == "DET-003":
            if event.event_type != "process_creation":
                return False, ""
            p_name = (event.process_name or "").lower()
            cmd = (event.command_line or "").lower()
            lolbas_procs = ["certutil.exe", "certutil", "bitsadmin.exe", "bitsadmin", "mshta.exe", "mshta", "curl", "wget"]
            proc_match = any(p in p_name for p in lolbas_procs)
            patterns = ["-urlcache", "http://", "https://", "-split", "/transfer", "javascript:", "vbscript:"]
            pattern_match = any(pat in cmd for pat in patterns)
            if proc_match and pattern_match:
                return True, f"LOLBAS binary '{event.process_name}' executed with suspicious arguments: {event.command_line}"
            return False, ""

        # DET-004: Suspicious PowerShell
        if rule.id == "DET-004":
            if event.event_type != "process_creation":
                return False, ""
            p_name = (event.process_name or "").lower()
            cmd = (event.command_line or "").lower()
            if not any(ps in p_name for ps in ["powershell", "pwsh"]):
                return False, ""
            ps_indicators = [
                "-enc", "-encodedcommand", "-e ", "downloadstring", "iex ", "invoke-expression",
                "net.webclient", "bypass -w hidden", "-nop -noni -w hidden"
            ]
            matched_indicator = next((ind for ind in ps_indicators if ind in cmd), None)
            if matched_indicator:
                return True, f"PowerShell executed with high-risk argument pattern '{matched_indicator}': {event.command_line}"
            return False, ""

        # DET-005: Security Logging Disabled or Audit Log Cleared
        if rule.id == "DET-005":
            if event.event_type == "security_log_tampering":
                return True, f"Security logging tampering detected: {event.action} on host {event.host}"
            if event.event_type == "process_creation":
                cmd = (event.command_line or "").lower()
                tamper_cmds = [
                    "wevtutil cl", "wevtutil.exe cl", "clear-eventlog",
                    "sc stop windefend", "sc stop sysmon", "systemctl stop auditd", "service auditd stop"
                ]
                matched_cmd = next((c for c in tamper_cmds if c in cmd), None)
                if matched_cmd:
                    return True, f"Defense impairment command executed '{matched_cmd}': {event.command_line}"
            return False, ""

        # DET-006: Privilege Group Modification
        if rule.id == "DET-006":
            if event.event_type == "privilege_change" and event.action == "group_member_added":
                group = (event.target_group or "").lower()
                priv_groups = ["admin", "domain admins", "enterprise admins", "sudo", "wheel", "root"]
                if any(pg in group for pg in priv_groups):
                    return True, f"Account '{event.target_user}' added to privileged group '{event.target_group}'"
            if event.event_type == "process_creation":
                cmd = (event.command_line or "").lower()
                priv_cmds = [
                    "net localgroup administrators /add", "net group \"domain admins\" /add",
                    "usermod -ag sudo", "usermod -ag wheel", "gpasswd -a"
                ]
                matched_cmd = next((c for c in priv_cmds if c in cmd), None)
                if matched_cmd:
                    return True, f"Privileged group escalation command executed: {event.command_line}"
            return False, ""

        # DET-007: Registry Run Key Persistence
        if rule.id == "DET-007":
            if event.event_type == "registry_modification":
                key = (event.registry_key or "").lower()
                val = (event.registry_value or "").lower()
                is_run = any(rk in key for rk in ["\\currentversion\\run", "\\currentversion\\runonce"])
                is_suspicious_path = any(sp in val for sp in ["appdata", "temp", "users\\public", "c:\\programdata", ".vbs", ".bat", ".ps1", "powershell", "cmd.exe"])
                if is_run and is_suspicious_path:
                    return True, f"Autorun registry persistence configured pointing to suspicious path: {event.registry_key} -> {event.registry_value}"
            return False, ""

        # DET-008: Scheduled Task Creation
        if rule.id == "DET-008":
            if event.event_type == "process_creation":
                p_name = (event.process_name or "").lower()
                cmd = (event.command_line or "").lower()
                is_schtasks = "schtasks" in p_name and ("/create" in cmd or "/sc" in cmd)
                suspicious_args = any(sa in cmd for sa in ["powershell", "cmd.exe", "temp\\", "appdata\\", "users\\public", "wscript", "cscript", "/ru system"])
                is_cron = "crontab -e" in cmd or "/etc/cron" in cmd or "/var/spool/cron" in cmd
                if (is_schtasks and suspicious_args) or is_cron:
                    return True, f"Scheduled task or cron persistence created: {event.command_line}"
            return False, ""

        # DET-010: DNS Anomalies and Tunneling
        if rule.id == "DET-010":
            if event.event_type == "dns_query":
                qname = (event.dns_query_name or "").lower()
                if any(marker in qname for marker in [".tunnel.", ".dnscat.", ".c2."]):
                    return True, f"Suspicious DNS tunnel marker query observed: {event.dns_query_name}"
                # Long subdomain check (> 25 chars in first label or high entropy)
                labels = qname.split(".")
                if labels and len(labels[0]) >= 25:
                    return True, f"Abnormally long high-entropy DNS subdomain query ({len(labels[0])} chars): {event.dns_query_name}"
            return False, ""

        # DET-011: Shadow Copy Deletion
        if rule.id == "DET-011":
            if event.event_type == "process_creation":
                p_name = (event.process_name or "").lower()
                cmd = (event.command_line or "").lower()
                tools = ["vssadmin", "wmic", "bcdedit", "wbadmin"]
                if any(t in p_name for t in tools):
                    shadow_cmds = ["delete shadows", "shadowcopy delete", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "delete catalog -quiet"]
                    if any(sc in cmd for sc in shadow_cmds):
                        return True, f"System recovery / Shadow copy deletion executed: {event.command_line}"
            return False, ""

        # DET-013: Kerberoasting Service Ticket Request (T1558.003)
        if rule.id == "DET-013":
            if event.event_type in ["authentication", "kerberos"]:
                action = (event.action or "").lower()
                enc = str(event.metadata.get("ticket_encryption", "")).lower()
                svc = (event.service_name or event.metadata.get("service_name", "") or "").lower()
                raw = (event.raw_log or "").lower()
                is_kerb_tgs = "kerberos" in action or "tgs" in action or "4769" in raw
                is_rc4 = enc == "0x17" or "0x17" in raw or "rc4" in raw
                is_not_computer = not svc.endswith("$")
                if (is_kerb_tgs or "kerberoast" in action) and is_rc4 and is_not_computer:
                    return True, f"Kerberoasting TGS ticket requested with RC4-HMAC (0x17) for service '{svc or event.service_name}' by user '{event.user}'"
            return False, ""

        # DET-014: DCSync Directory Replication Rights Abuse (T1003.006)
        if rule.id == "DET-014":
            if event.event_type in ["privilege_change", "directory_service"]:
                action = (event.action or "").lower()
                rights = str(event.metadata.get("extended_rights", "")).lower()
                user = (event.user or "").lower()
                raw = (event.raw_log or "").lower()
                dcsync_guids = [
                    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
                    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-In-Filtered-Set
                    "89e95b76-444d-11d2-ae06-00c04fb6dd80"   # DS-Replication-Get-Changes
                ]
                has_guid = any(g in rights or g in raw for g in dcsync_guids)
                is_dcsync_action = "dcsync" in action or "directory_service_access" in action or "replication" in action
                is_non_dc = not user.endswith("$")
                if is_dcsync_action and (has_guid or "dcsync" in raw) and is_non_dc:
                    return True, f"DCSync Directory Replication Rights (DS-Replication-Get-Changes-All) requested by non-DC account '{event.user}'"
            return False, ""

        # DET-015: Trusted Developer Utility Proxy Execution (MSBuild / InstallUtil - T1127.001)
        if rule.id == "DET-015":
            if event.event_type == "process_creation":
                p_name = (event.process_name or "").lower()
                cmd = (event.command_line or "").lower()
                is_compiler = any(p in p_name for p in ["msbuild.exe", "msbuild", "installutil.exe", "installutil"])
                suspicious_loc = any(loc in cmd for loc in ["temp\\", "appdata\\", "users\\public", "c:\\programdata", ".csproj", ".xml", "/logfile="])
                if is_compiler and suspicious_loc:
                    return True, f"Trusted compiler proxy execution '{event.process_name}' executing payload from user-writable path: {event.command_line}"
            return False, ""

        # DET-016: Remote Thread Process Injection (CreateRemoteThread - T1055.001)
        if rule.id == "DET-016":
            action = (event.action or "").lower()
            p_name = (event.process_name or "").lower()
            target = (event.metadata.get("target_process_name", "") or p_name).lower()
            parent = (event.parent_process_name or "").lower()
            if event.event_type in ["process_creation", "process_injection"] or "remote_thread" in action:
                critical_targets = ["lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe"]
                is_target_critical = any(t in target for t in critical_targets)
                is_remote_thread = "remote_thread" in action or str(event.metadata.get("event_id")) in ["8", "10"]
                if is_target_critical and is_remote_thread and "csrss.exe" not in parent:
                    return True, f"Suspicious Remote Thread injection created into target process '{target}' from source '{event.parent_process_name or event.process_name}'"
            return False, ""

        # DET-017: Ransomware Recovery Tampering (BCDEdit / WBAdmin - T1490)
        if rule.id == "DET-017":
            if event.event_type == "process_creation":
                p_name = (event.process_name or "").lower()
                cmd = (event.command_line or "").lower()
                tools = ["bcdedit", "wbadmin"]
                if any(t in p_name for t in tools):
                    ransom_cmds = [
                        "recoveryenabled no",
                        "bootstatuspolicy ignoreallfailures",
                        "delete catalog -quiet",
                        "delete systemstatebackup"
                    ]
                    if any(rc in cmd for rc in ransom_cmds):
                        return True, f"Ransomware recovery inhibition command executed: {event.command_line}"
            return False, ""

        # Generic pattern fallback if defined in YAML selection
        return False, ""


class RuleQueryTranslator:
    """
    Translates Sigma detection rules into Microsoft Sentinel KQL, Splunk SPL,
    and Elastic EQL queries for Detection-as-Code workflows.
    """
    @staticmethod
    def translate_to_kql(rule: RuleDefinition) -> str:
        r_id = rule.id
        if r_id == "DET-001":
            return (
                "// Microsoft Sentinel KQL\n"
                "SecurityEvent\n"
                "| where EventID == 4625\n"
                "| where LogonType in (2, 3, 10)\n"
                "| summarize FailureCount = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated)\n"
                "    by IpAddress, TargetUserName, bin(TimeGenerated, 5m)\n"
                "| where FailureCount >= 5"
            )
        elif r_id == "DET-002":
            return (
                "// Microsoft Sentinel KQL\n"
                "let Failures = SecurityEvent\n"
                "| where EventID == 4625 and TimeGenerated >= ago(1h)\n"
                "| summarize FailCount = count() by TargetUserName, IpAddress;\n"
                "let Successes = SecurityEvent\n"
                "| where EventID == 4624 and TimeGenerated >= ago(1h);\n"
                "Failures\n"
                "| where FailCount >= 4\n"
                "| join kind=inner (Successes) on TargetUserName, IpAddress"
            )
        elif r_id == "DET-003":
            return (
                "// Microsoft Sentinel KQL\n"
                "DeviceProcessEvents\n"
                "| where FileName in~ ('certutil.exe', 'bitsadmin.exe', 'mshta.exe')\n"
                "| where ProcessCommandLine has_any ('-urlcache', 'http://', 'https://', '-split', '/transfer', 'javascript:')"
            )
        elif r_id == "DET-004":
            return (
                "// Microsoft Sentinel KQL\n"
                "DeviceProcessEvents\n"
                "| where FileName in~ ('powershell.exe', 'pwsh.exe')\n"
                "| where ProcessCommandLine has_any ('-enc', '-encodedcommand', 'downloadstring', 'iex', 'net.webclient')"
            )
        elif r_id == "DET-005":
            return (
                "// Microsoft Sentinel KQL\n"
                "SecurityEvent\n"
                "| where EventID == 1102 or (EventID == 4688 and CommandLine has_any ('wevtutil cl', 'clear-eventlog', 'sc stop windefend'))"
            )
        elif r_id == "DET-013":
            return (
                "// Microsoft Sentinel KQL\n"
                "SecurityEvent\n"
                "| where EventID == 4769\n"
                "| where TicketEncryptionType =~ '0x17'\n"
                "| where not(ServiceName endswith '$')\n"
                "| project TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, IpAddress"
            )
        elif r_id == "DET-014":
            return (
                "// Microsoft Sentinel KQL\n"
                "SecurityEvent\n"
                "| where EventID == 4662\n"
                "| where ObjectServer =~ 'DS' and ObjectType in~ ('{19195a5b-6da0-11d0-afd3-00c04fd930c9}', 'domainDNS')\n"
                "| where AccessMask has '0x100'\n"
                "| where Properties has_any ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')\n"
                "| where not(AccountName endswith '$')"
            )
        elif r_id == "DET-015":
            return (
                "// Microsoft Sentinel KQL\n"
                "DeviceProcessEvents\n"
                "| where FileName in~ ('msbuild.exe', 'installutil.exe')\n"
                "| where ProcessCommandLine has_any ('temp\\\\', 'appdata\\\\', 'users\\\\public', '.csproj', '.xml')"
            )
        elif r_id == "DET-016":
            return (
                "// Microsoft Sentinel KQL\n"
                "DeviceEvents\n"
                "| where ActionType =~ 'CreateRemoteThread'\n"
                "| where FileName in~ ('lsass.exe', 'svchost.exe', 'explorer.exe')\n"
                "| where not(InitiatingProcessFileName =~ 'csrss.exe')"
            )
        elif r_id == "DET-017":
            return (
                "// Microsoft Sentinel KQL\n"
                "DeviceProcessEvents\n"
                "| where FileName in~ ('bcdedit.exe', 'wbadmin.exe')\n"
                "| where ProcessCommandLine has_any ('recoveryenabled no', 'bootstatuspolicy ignoreallfailures', 'delete catalog -quiet')"
            )
        elif r_id == "DET-018":
            return (
                "// Microsoft Sentinel KQL\n"
                "CommonSecurityLog\n"
                "| summarize ConnectionCount = count(), Jitter = stdev(TimeGenerated) by SourceIP, DestinationIP, bin(TimeGenerated, 5m)\n"
                "| where ConnectionCount >= 5"
            )
        else:
            return f"// Microsoft Sentinel KQL\nSecurityEvent | where EventID in (4624, 4688) | where CommandLine has '{rule.title}'"

    @staticmethod
    def translate_to_splunk(rule: RuleDefinition) -> str:
        r_id = rule.id
        if r_id == "DET-001":
            return (
                "# Splunk SPL\n"
                "sourcetype=\"WinEventLog:Security\" EventCode=4625\n"
                "| bucket _time span=5m\n"
                "| stats count as failure_count by user, src_ip, _time\n"
                "| search failure_count >= 5"
            )
        elif r_id == "DET-003":
            return (
                "# Splunk SPL\n"
                "index=endpoint (process_name=\"certutil.exe\" OR process_name=\"bitsadmin.exe\")\n"
                "| search CommandLine=\"*-urlcache*\" OR CommandLine=\"*http://*\" OR CommandLine=\"*https://*\""
            )
        elif r_id == "DET-004":
            return (
                "# Splunk SPL\n"
                "index=endpoint (process_name=\"powershell.exe\" OR process_name=\"pwsh.exe\")\n"
                "| search CommandLine=\"*-enc*\" OR CommandLine=\"*DownloadString*\" OR CommandLine=\"*IEX*\""
            )
        elif r_id == "DET-013":
            return (
                "# Splunk SPL\n"
                "sourcetype=\"WinEventLog:Security\" EventCode=4769 Ticket_Encryption_Type=\"0x17\"\n"
                "| search NOT Service_Name=\"*$*\"\n"
                "| stats count by TargetUserName, Service_Name, src_ip"
            )
        elif r_id == "DET-014":
            return (
                "# Splunk SPL\n"
                "sourcetype=\"WinEventLog:Security\" EventCode=4662 (AccessMask=\"*0x100*\" OR Properties=\"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\")\n"
                "| search NOT TargetUserName=\"*$*\""
            )
        elif r_id == "DET-017":
            return (
                "# Splunk SPL\n"
                "index=endpoint (process_name=\"bcdedit.exe\" OR process_name=\"wbadmin.exe\")\n"
                "| search CommandLine=\"*recoveryenabled no*\" OR CommandLine=\"*bootstatuspolicy ignoreallfailures*\" OR CommandLine=\"*delete catalog*\""
            )
        else:
            return f"# Splunk SPL\nindex=* (process_name=\"*{rule.id.lower()}*\" OR CommandLine=\"*{rule.title}*\")"

    @staticmethod
    def translate_to_elastic(rule: RuleDefinition) -> str:
        r_id = rule.id
        if r_id == "DET-003":
            return (
                "// Elastic EQL\n"
                "process where event.type == \"start\" and\n"
                "  process.name in (\"certutil.exe\", \"bitsadmin.exe\", \"mshta.exe\") and\n"
                "  process.command_line : (\"*-urlcache*\", \"*http://*\", \"*https://*\", \"*-split*\")"
            )
        elif r_id == "DET-004":
            return (
                "// Elastic EQL\n"
                "process where event.type == \"start\" and\n"
                "  process.name in (\"powershell.exe\", \"pwsh.exe\") and\n"
                "  process.command_line : (\"*-enc*\", \"*DownloadString*\", \"*IEX*\", \"*Net.WebClient*\")"
            )
        elif r_id == "DET-013":
            return (
                "// Elastic EQL / KQL\n"
                "authentication where event.action == \"kerberos_ticket_request\" and\n"
                "  winlog.event_data.TicketEncryptionType == \"0x17\" and\n"
                "  not winlog.event_data.ServiceName : \"*$\""
            )
        elif r_id == "DET-017":
            return (
                "// Elastic EQL\n"
                "process where event.type == \"start\" and\n"
                "  process.name in (\"bcdedit.exe\", \"wbadmin.exe\") and\n"
                "  process.command_line : (\"*recoveryenabled no*\", \"*ignoreallfailures*\", \"*delete catalog*\")"
            )
        else:
            return f"// Elastic EQL\nprocess where event.type == \"start\" and process.name == \"{rule.id.lower()}.exe\""

