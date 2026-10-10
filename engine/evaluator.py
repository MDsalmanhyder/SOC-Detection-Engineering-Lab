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

        # Generic pattern fallback if defined in YAML selection
        return False, ""
