"""
Typed Pydantic v2 models for the SOC Incident Response OpenEnv environment.
All models are fully typed and JSON-serialisable — required by the OpenEnv spec.
"""
from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from enum import Enum
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    CONTAINED = "contained"
    ESCALATED = "escalated"
    CLOSED = "closed"


class ActionType(str, Enum):
    ENRICH_ALERT = "enrich_alert"
    CORRELATE_ALERTS = "correlate_alerts"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    COLLECT_FORENSICS = "collect_forensics"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    CREATE_TICKET = "create_ticket"


class MITRETactic(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class HostStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    ISOLATED = "isolated"
    PATCHED = "patched"


# ---------------------------------------------------------------------------
# Domain entities
# ---------------------------------------------------------------------------

class ThreatIndicator(BaseModel):
    type: Literal["ip", "hash", "domain", "user", "process", "registry_key"]
    value: str
    reputation: Optional[str] = None
    context: Optional[str] = None


class SIEMAlert(BaseModel):
    alert_id: str
    timestamp: str
    severity: AlertSeverity
    rule_name: str
    description: str
    host_id: str
    user_id: Optional[str] = None
    mitre_tactic: Optional[MITRETactic] = None
    mitre_technique: Optional[str] = None
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    raw_log: Optional[str] = None
    status: AlertStatus = AlertStatus.PENDING
    enrichment: Optional[Dict[str, Any]] = None
    ground_truth: Optional[bool] = None  # True=TP, False=FP — never sent to agent


class NetworkHost(BaseModel):
    host_id: str
    hostname: str
    ip_address: str
    subnet: str
    os: str
    role: str
    owner: Optional[str] = None
    is_critical: bool = False
    is_vip: bool = False
    status: HostStatus = HostStatus.CLEAN
    active_sessions: List[str] = Field(default_factory=list)
    running_processes: List[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    """Ground-truth kill chain — used only by grader, never exposed to agent."""
    patient_zero_host: str
    stages: List[MITRETactic]
    lateral_movement_targets: List[str] = Field(default_factory=list)
    crown_jewel_host: str
    exfiltration_complete: bool = False
    attacker_dwell_minutes: int = 0


class BusinessConstraint(BaseModel):
    host_id: Optional[str] = None
    user_id: Optional[str] = None
    constraint_type: Literal[
        "cannot_isolate", "legal_hold", "customer_facing", "executive", "critical_infra"
    ]
    reason: str
    severity: Literal["advisory", "hard_block"]


class InvestigationNote(BaseModel):
    step: int
    action_taken: str
    finding: str
    timestamp: str


# ---------------------------------------------------------------------------
# OpenEnv spec: Observation, Action, Reward
# ---------------------------------------------------------------------------

class Observation(BaseModel):
    """What the agent sees at each step — ground_truth fields are excluded."""
    step: int
    task_id: str
    task_description: str
    active_alerts: List[SIEMAlert]
    acknowledged_alerts: List[SIEMAlert] = Field(default_factory=list)
    hosts: List[NetworkHost]
    business_constraints: List[BusinessConstraint] = Field(default_factory=list)
    notes: List[InvestigationNote] = Field(default_factory=list)
    elapsed_minutes: int = 0
    max_minutes: int = 120
    steps_remaining: int = 40
    last_action_result: Optional[str] = None
    last_action_success: bool = True

    def model_dump_safe(self) -> Dict[str, Any]:
        """Serialise without ground_truth — safe to send to agent."""
        d = self.model_dump()
        for alert in d.get("active_alerts", []):
            alert.pop("ground_truth", None)
        for alert in d.get("acknowledged_alerts", []):
            alert.pop("ground_truth", None)
        return d


class Action(BaseModel):
    """The agent's action at each step."""
    action_type: ActionType
    alert_id: Optional[str] = None
    alert_ids: Optional[List[str]] = None
    host_id: Optional[str] = None
    user_id: Optional[str] = None
    artifact_types: Optional[List[str]] = None
    source: Optional[str] = None
    priority: Optional[Literal["P1", "P2", "P3"]] = None
    summary: Optional[str] = None
    classification: Optional[Literal["true_positive", "false_positive"]] = None
    correlation_hypothesis: Optional[str] = None


class Reward(BaseModel):
    """Per-step reward with full breakdown."""
    total: float = Field(ge=-1.0, le=1.0)
    classification_delta: float = 0.0
    chain_coverage_delta: float = 0.0
    containment_delta: float = 0.0
    dwell_penalty: float = 0.0
    fp_penalty: float = 0.0
    compliance_delta: float = 0.0
    info: str = ""


class EnvState(BaseModel):
    """Full internal state — includes ground truth. Returned by state()."""
    task_id: str
    step: int
    done: bool
    cumulative_reward: float
    observation: Observation
    attack_chain: Optional[AttackChain] = None
    agent_classifications: Dict[str, bool] = Field(default_factory=dict)
    identified_stages: List[MITRETactic] = Field(default_factory=list)
    isolated_hosts: List[str] = Field(default_factory=list)
    disabled_accounts: List[str] = Field(default_factory=list)
    forensics_collected: Dict[str, List[str]] = Field(default_factory=dict)
    escalated: bool = False
    ticket_created: bool = False
