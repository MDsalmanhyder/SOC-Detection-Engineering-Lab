"""
Unified Normalized Security Event Schema and Alert Data Models
SOC Detection Engineering Lab
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict
import uuid


class EventSource(str, Enum):
    LINUX_AUTH = "LinuxAuth"
    SYSMON = "Sysmon"
    WINDOWS_SECURITY = "WindowsSecurity"
    ZEEK_CONN = "ZeekConn"
    ZEEK_DNS = "ZeekDNS"
    SURICATA = "Suricata"
    FIREWALL = "Firewall"
    SYNTHETIC = "Synthetic"


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    REGISTRY_MODIFICATION = "registry_modification"
    PRIVILEGE_CHANGE = "privilege_change"
    PERSISTENCE_CHANGE = "persistence_change"
    DNS_QUERY = "dns_query"
    SERVICE_MODIFICATION = "service_modification"
    SECURITY_LOG_TAMPERING = "security_log_tampering"
    DATA_TRANSFER = "data_transfer"
    UNKNOWN = "unknown"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AlertStatus(str, Enum):
    NEW = "New"
    TRIAGED = "Triaged"
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    RESOLVED = "Resolved"


class MitreAttackRef(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    url: Optional[str] = None


class NormalizedEvent(BaseModel):
    """
    Normalized security event representing endpoint, authentication,
    and network telemetry in a standardized format.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_source: str = EventSource.SYNTHETIC.value
    event_type: str = EventType.UNKNOWN.value
    action: Optional[str] = None  # e.g., "login_failed", "login_success", "process_created"
    
    # Entities
    host: str = "unknown-host"
    user: Optional[str] = None
    
    # Network fields
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_out: Optional[int] = 0
    bytes_in: Optional[int] = 0
    
    # Process fields
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    parent_process_id: Optional[int] = None
    hashes: Dict[str, str] = Field(default_factory=dict)
    
    # Persistence & Registry & Privilege fields
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    target_user: Optional[str] = None
    target_group: Optional[str] = None
    service_name: Optional[str] = None
    task_name: Optional[str] = None
    
    # DNS fields
    dns_query_name: Optional[str] = None
    dns_response_code: Optional[str] = None
    
    # Status & raw
    status: str = EventStatus.UNKNOWN.value
    raw_log: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class Alert(BaseModel):
    """
    Rich, actionable SOC alert record.
    """
    alert_id: str = Field(default_factory=lambda: f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}")
    rule_id: str
    rule_name: str
    rule_version: str = "1.0.0"
    severity: Severity = Severity.MEDIUM
    severity_rationale: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_window_start: datetime
    event_window_end: datetime
    
    # Context
    affected_host: str
    affected_user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    
    # Detection intelligence
    mitre_attack: MitreAttackRef
    why_it_fired: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_events: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Operations & Triage
    investigation_steps: List[str] = Field(default_factory=list)
    containment_steps: List[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    analyst_notes: List[str] = Field(default_factory=list)
    suppression_key: str
    is_suppressed: bool = False

    model_config = ConfigDict(populate_by_name=True)
