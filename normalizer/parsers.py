"""
Parsers for Linux Auth, Windows Sysmon/Security, and Network Security Telemetry.
Normalizes diverse raw log formats into Unified NormalizedEvent objects.
"""

import re
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from normalizer.schema import (
    NormalizedEvent, EventSource, EventType, EventStatus
)


class BaseParser:
    def parse(self, raw: str) -> Optional[NormalizedEvent]:
        raise NotImplementedError


class LinuxAuthParser(BaseParser):
    """
    Parses Linux /var/log/auth.log or /var/log/secure lines:
    - SSH Failed password
    - SSH Accepted password
    - sudo commands
    - useradd / usermod / group additions
    - auditd service stopped
    """

    # Syslog timestamp: "Oct 10 12:15:23" or ISO "2026-10-10T12:15:23Z"
    SYSLOG_TIME_RE = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<daemon>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
    )
    ISO_TIME_RE = re.compile(
        r"^(?P<iso_time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>[^\s]+)\s+(?P<daemon>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
    )

    SSH_FAILED_RE = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) (?P<proto>\S+)"
    )
    SSH_ACCEPTED_RE = re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) (?P<proto>\S+)"
    )
    SUDO_CMD_RE = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
    )
    USERMOD_GROUP_RE = re.compile(
        r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"
    )
    SYSTEMD_STOP_RE = re.compile(
        r"Stopped (?:Audit Daemon|auditd|syslog).*"
    )

    MONTHS = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    def _parse_timestamp(self, month_str: str, day_str: str, time_str: str) -> datetime:
        now = datetime.now(timezone.utc)
        month = self.MONTHS.get(month_str, now.month)
        day = int(day_str)
        h, m, s = map(int, time_str.split(":"))
        return datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)

    def parse(self, raw: str) -> Optional[NormalizedEvent]:
        raw_clean = raw.strip()
        if not raw_clean:
            return None

        # Check ISO format first, then syslog standard format
        iso_match = self.ISO_TIME_RE.match(raw_clean)
        syslog_match = self.SYSLOG_TIME_RE.match(raw_clean) if not iso_match else None

        if iso_match:
            d = iso_match.groupdict()
            try:
                # Handle possible missing timezone
                ts_str = d["iso_time"].replace("Z", "+00:00")
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
            host = d["host"]
            daemon = d["daemon"].strip()
            msg = d["msg"]
        elif syslog_match:
            d = syslog_match.groupdict()
            ts = self._parse_timestamp(d["month"], d["day"], d["time"])
            host = d["host"]
            daemon = d["daemon"].strip()
            msg = d["msg"]
        else:
            # Fallback if raw message without standard prefix
            ts = datetime.now(timezone.utc)
            host = "linux-endpoint"
            daemon = "auth"
            msg = raw_clean

        # Check for SSH Failed password
        m_failed = self.SSH_FAILED_RE.search(msg)
        if m_failed:
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.LINUX_AUTH.value,
                event_type=EventType.AUTHENTICATION.value,
                action="login_failed",
                host=host,
                user=m_failed.group("user"),
                source_ip=m_failed.group("ip"),
                source_port=int(m_failed.group("port")),
                dest_port=22,
                protocol="SSH",
                status=EventStatus.FAILURE.value,
                process_name="sshd",
                raw_log=raw_clean
            )

        # Check for SSH Accepted password
        m_accepted = self.SSH_ACCEPTED_RE.search(msg)
        if m_accepted:
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.LINUX_AUTH.value,
                event_type=EventType.AUTHENTICATION.value,
                action="login_success",
                host=host,
                user=m_accepted.group("user"),
                source_ip=m_accepted.group("ip"),
                source_port=int(m_accepted.group("port")),
                dest_port=22,
                protocol="SSH",
                status=EventStatus.SUCCESS.value,
                process_name="sshd",
                raw_log=raw_clean
            )

        # Check for sudo privileged execution
        if "sudo" in daemon:
            m_sudo = self.SUDO_CMD_RE.search(msg)
            if m_sudo:
                return NormalizedEvent(
                    timestamp=ts,
                    event_source=EventSource.LINUX_AUTH.value,
                    event_type=EventType.PRIVILEGE_CHANGE.value,
                    action="sudo_execution",
                    host=host,
                    user=m_sudo.group("user"),
                    target_user=m_sudo.group("target_user"),
                    command_line=m_sudo.group("command"),
                    process_name="sudo",
                    status=EventStatus.SUCCESS.value,
                    raw_log=raw_clean
                )

        # Check for group addition (e.g. usermod adding to sudo)
        m_usermod = self.USERMOD_GROUP_RE.search(msg)
        if m_usermod:
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.LINUX_AUTH.value,
                event_type=EventType.PRIVILEGE_CHANGE.value,
                action="group_member_added",
                host=host,
                target_user=m_usermod.group("user"),
                target_group=m_usermod.group("group"),
                process_name="usermod",
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Check for auditd stopped
        if self.SYSTEMD_STOP_RE.search(msg) or "auditd" in msg and "stopping" in msg.lower():
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.LINUX_AUTH.value,
                event_type=EventType.SECURITY_LOG_TAMPERING.value,
                action="service_stopped",
                host=host,
                service_name="auditd",
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Default fallback
        return NormalizedEvent(
            timestamp=ts,
            event_source=EventSource.LINUX_AUTH.value,
            event_type=EventType.UNKNOWN.value,
            action="general_auth_event",
            host=host,
            status=EventStatus.UNKNOWN.value,
            raw_log=raw_clean
        )


class WindowsSysmonParser(BaseParser):
    """
    Parses Windows Event Logs and Sysmon events from JSON/dict or key-value structures:
    - Sysmon EventID 1: Process Creation
    - Sysmon EventID 3: Network Connection
    - Sysmon EventID 13: Registry Value Set
    - Security EventID 4625: Logon Failure
    - Security EventID 4624: Logon Success
    - Security EventID 4728 / 4732: Member added to Security Group
    - Security EventID 1102: Audit Log Cleared
    - System EventID 7040 / 7045: Service Config Change / Installed
    """

    def parse(self, raw: str) -> Optional[NormalizedEvent]:
        raw_clean = raw.strip()
        if not raw_clean:
            return None

        # Expect JSON or key-value structure
        data: Dict[str, Any] = {}
        if raw_clean.startswith("{") and raw_clean.endswith("}"):
            try:
                data = json.loads(raw_clean)
            except Exception:
                return None
        else:
            # Parse key=value or comma separated if applicable
            for pair in raw_clean.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    data[k.strip()] = v.strip()

        event_id = str(data.get("EventID") or data.get("event_id") or "")
        channel = str(data.get("Channel") or data.get("source") or "")
        host = data.get("Computer") or data.get("host") or "win-workstation-01"
        
        # Parse timestamp
        ts_val = data.get("UtcTime") or data.get("TimeCreated") or data.get("timestamp")
        if isinstance(ts_val, str):
            try:
                ts = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
        elif isinstance(ts_val, datetime):
            ts = ts_val
        else:
            ts = datetime.now(timezone.utc)

        user = data.get("User") or data.get("TargetUserName") or data.get("user")

        # Sysmon Event ID 1: Process Creation
        if event_id == "1" or data.get("event_type") == "process_creation":
            image = data.get("Image") or data.get("process_path") or ""
            proc_name = image.split("\\")[-1].split("/")[-1] if image else data.get("process_name", "")
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.SYSMON.value,
                event_type=EventType.PROCESS_CREATION.value,
                action="process_created",
                host=host,
                user=user,
                process_name=proc_name or data.get("process_name"),
                process_path=image,
                command_line=data.get("CommandLine") or data.get("command_line", ""),
                process_id=int(data.get("ProcessId", 0)) if str(data.get("ProcessId", "")).isdigit() else None,
                parent_process_name=data.get("ParentImage", "").split("\\")[-1] if data.get("ParentImage") else data.get("parent_process_name"),
                parent_command_line=data.get("ParentCommandLine") or data.get("parent_command_line"),
                hashes={"sha256": data.get("Hashes", "")} if data.get("Hashes") else data.get("hashes", {}),
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Sysmon Event ID 3: Network Connection
        if event_id == "3":
            image = data.get("Image") or ""
            proc_name = image.split("\\")[-1] if image else data.get("process_name")
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.SYSMON.value,
                event_type=EventType.NETWORK_CONNECTION.value,
                action="network_connected",
                host=host,
                user=user,
                process_name=proc_name,
                source_ip=data.get("SourceIp"),
                source_port=int(data.get("SourcePort", 0)) if str(data.get("SourcePort", "")).isdigit() else None,
                dest_ip=data.get("DestinationIp"),
                dest_port=int(data.get("DestinationPort", 0)) if str(data.get("DestinationPort", "")).isdigit() else None,
                protocol=data.get("Protocol", "TCP"),
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Sysmon Event ID 13: Registry Value Set
        if event_id == "13":
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.SYSMON.value,
                event_type=EventType.REGISTRY_MODIFICATION.value,
                action="registry_value_set",
                host=host,
                user=user,
                registry_key=data.get("TargetObject"),
                registry_value=data.get("Details"),
                process_name=data.get("Image", "").split("\\")[-1] if data.get("Image") else None,
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Windows Event ID 4625: Logon Failure
        if event_id == "4625":
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.WINDOWS_SECURITY.value,
                event_type=EventType.AUTHENTICATION.value,
                action="login_failed",
                host=host,
                user=data.get("TargetUserName") or user,
                source_ip=data.get("IpAddress") or data.get("source_ip"),
                source_port=int(data.get("IpPort", 0)) if str(data.get("IpPort", "")).isdigit() else None,
                status=EventStatus.FAILURE.value,
                raw_log=raw_clean
            )

        # Windows Event ID 4624: Logon Success
        if event_id == "4624":
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.WINDOWS_SECURITY.value,
                event_type=EventType.AUTHENTICATION.value,
                action="login_success",
                host=host,
                user=data.get("TargetUserName") or user,
                source_ip=data.get("IpAddress") or data.get("source_ip"),
                source_port=int(data.get("IpPort", 0)) if str(data.get("IpPort", "")).isdigit() else None,
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Windows Event ID 4728 or 4732: Security Group Member Added
        if event_id in ("4728", "4732"):
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.WINDOWS_SECURITY.value,
                event_type=EventType.PRIVILEGE_CHANGE.value,
                action="group_member_added",
                host=host,
                user=data.get("SubjectUserName"),
                target_user=data.get("MemberName") or data.get("target_user"),
                target_group=data.get("TargetUserName") or data.get("target_group"),  # Often group name in 4728
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Windows Event ID 1102: Audit Log Cleared
        if event_id == "1102":
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.WINDOWS_SECURITY.value,
                event_type=EventType.SECURITY_LOG_TAMPERING.value,
                action="audit_log_cleared",
                host=host,
                user=data.get("SubjectUserName") or user,
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Windows Event ID 7040 or 7045: Service Changed / Installed
        if event_id in ("7040", "7045"):
            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.WINDOWS_SECURITY.value,
                event_type=EventType.SERVICE_MODIFICATION.value,
                action="service_installed" if event_id == "7045" else "service_state_change",
                host=host,
                service_name=data.get("ServiceName"),
                command_line=data.get("ImagePath"),
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Fallback for generic dict
        return NormalizedEvent(
            timestamp=ts,
            event_source=channel or EventSource.WINDOWS_SECURITY.value,
            event_type=data.get("event_type", EventType.UNKNOWN.value),
            host=host,
            user=user,
            status=data.get("status", EventStatus.UNKNOWN.value),
            raw_log=raw_clean,
            metadata=data
        )


class NetworkLogParser(BaseParser):
    """
    Parses Network security logs:
    - Zeek conn.log / dns.log
    - Suricata EVE JSON
    - Firewall traffic logs
    """

    def parse(self, raw: str) -> Optional[NormalizedEvent]:
        raw_clean = raw.strip()
        if not raw_clean:
            return None

        # Check for JSON format (Suricata / Zeek JSON format)
        if raw_clean.startswith("{") and raw_clean.endswith("}"):
            try:
                data = json.loads(raw_clean)
            except Exception:
                return None

            ts_raw = data.get("timestamp") or data.get("ts")
            if isinstance(ts_raw, (int, float)):
                ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            elif isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event_type_str = data.get("event_type", "")
            
            # DNS query log
            if event_type_str == "dns" or "dns" in data:
                dns_info = data.get("dns", {})
                query_name = dns_info.get("rrname") or data.get("query") or dns_info.get("query")
                return NormalizedEvent(
                    timestamp=ts,
                    event_source=EventSource.ZEEK_DNS.value,
                    event_type=EventType.DNS_QUERY.value,
                    action="dns_lookup",
                    host=data.get("host", "lan-gateway"),
                    source_ip=data.get("src_ip") or data.get("id.orig_h"),
                    source_port=int(data.get("src_port") or data.get("id.orig_p") or 0) or None,
                    dest_ip=data.get("dest_ip") or data.get("id.resp_h"),
                    dest_port=int(data.get("dest_port") or data.get("id.resp_p") or 53),
                    protocol="DNS",
                    dns_query_name=query_name,
                    dns_response_code=str(dns_info.get("rcode", "NOERROR")),
                    status=EventStatus.SUCCESS.value,
                    raw_log=raw_clean
                )

            # High egress / Data transfer or connection
            bytes_out = int(data.get("orig_bytes") or data.get("bytes_out") or data.get("bytes_toclient") or 0)
            bytes_in = int(data.get("resp_bytes") or data.get("bytes_in") or data.get("bytes_toserver") or 0)
            dest_port = int(data.get("dest_port") or data.get("id.resp_p") or 0) or None

            return NormalizedEvent(
                timestamp=ts,
                event_source=EventSource.ZEEK_CONN.value,
                event_type=EventType.DATA_TRANSFER.value if bytes_out > 1000000 else EventType.NETWORK_CONNECTION.value,
                action="flow_recorded",
                host=data.get("host", "network-tap"),
                source_ip=data.get("src_ip") or data.get("id.orig_h"),
                source_port=int(data.get("src_port") or data.get("id.orig_p") or 0) or None,
                dest_ip=data.get("dest_ip") or data.get("id.resp_h"),
                dest_port=dest_port,
                protocol=data.get("proto") or data.get("protocol", "TCP"),
                bytes_out=bytes_out,
                bytes_in=bytes_in,
                status=EventStatus.SUCCESS.value,
                raw_log=raw_clean
            )

        # Tab-delimited Zeek or Syslog fallback
        parts = raw_clean.split("\t")
        if len(parts) >= 8:
            # Zeek standard conn.log format
            try:
                ts = datetime.fromtimestamp(float(parts[0]), tz=timezone.utc)
                return NormalizedEvent(
                    timestamp=ts,
                    event_source=EventSource.ZEEK_CONN.value,
                    event_type=EventType.NETWORK_CONNECTION.value,
                    action="flow_recorded",
                    source_ip=parts[2],
                    source_port=int(parts[3]) if parts[3].isdigit() else None,
                    dest_ip=parts[4],
                    dest_port=int(parts[5]) if parts[5].isdigit() else None,
                    protocol=parts[6],
                    bytes_out=int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                    bytes_in=int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0,
                    status=EventStatus.SUCCESS.value,
                    raw_log=raw_clean
                )
            except Exception:
                pass

        return None


class AutoNormalizer:
    """
    Intelligent normalizer that examines input log strings or dicts
    and dispatches to the appropriate parser.
    """
    def __init__(self):
        self.linux_parser = LinuxAuthParser()
        self.windows_parser = WindowsSysmonParser()
        self.network_parser = NetworkLogParser()

    def normalize(self, raw_input: Any) -> Optional[NormalizedEvent]:
        if isinstance(raw_input, NormalizedEvent):
            return raw_input

        if isinstance(raw_input, dict):
            # Already a normalized dictionary or raw structured event
            if "event_type" in raw_input and "timestamp" in raw_input:
                try:
                    return NormalizedEvent(**raw_input)
                except Exception:
                    pass
            # Structured Windows/Sysmon or Network JSON
            raw_str = json.dumps(raw_input)
            if "EventID" in raw_input or "CommandLine" in raw_input or "TargetUserName" in raw_input:
                return self.windows_parser.parse(raw_str)
            if "dns" in raw_input or "orig_bytes" in raw_input or "id.orig_h" in raw_input:
                return self.network_parser.parse(raw_str)
            return self.windows_parser.parse(raw_str)

        if isinstance(raw_str := str(raw_input), str):
            raw_trimmed = raw_str.strip()
            if not raw_trimmed:
                return None
            if raw_trimmed.startswith("{"):
                # Try JSON parsers
                res = self.windows_parser.parse(raw_trimmed)
                if res and res.event_type != EventType.UNKNOWN.value:
                    return res
                res = self.network_parser.parse(raw_trimmed)
                if res:
                    return res
            # Check Linux syslog markers
            if any(k in raw_trimmed for k in ["sshd", "sudo", "useradd", "usermod", "systemd", "auth.log", "pam_unix"]):
                return self.linux_parser.parse(raw_trimmed)
            # Try Linux parser anyway
            res = self.linux_parser.parse(raw_trimmed)
            if res and res.action in ("login_failed", "login_success", "sudo_execution", "group_member_added", "service_stopped"):
                return res
            # Try network parser
            res = self.network_parser.parse(raw_trimmed)
            if res:
                return res
            # Fallback Windows parser
            return self.windows_parser.parse(raw_trimmed)

        return None
