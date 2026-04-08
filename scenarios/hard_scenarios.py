"""Hard scenario: active breach + business constraints — CEO laptop, legal hold, customer API."""
from __future__ import annotations
from typing import Any, Dict

from soc_env.models import (
    AlertSeverity, AttackChain, BusinessConstraint, HostStatus, MITRETactic,
    NetworkHost, Observation, SIEMAlert, ThreatIndicator,
)

_HOSTS = [
    NetworkHost(host_id="HOST-CEO",    hostname="ceo-macbook-pro",      ip_address="10.0.1.5",  subnet="10.0.1.0/24", os="macOS Ventura",      role="executive_workstation", owner="ceo_user",    is_critical=False, is_vip=True,  status=HostStatus.COMPROMISED),
    NetworkHost(host_id="HOST-DC",     hostname="domain-controller-01", ip_address="10.0.2.5",  subnet="10.0.2.0/24", os="Windows Server 2022", role="domain_controller",     is_critical=True,                        status=HostStatus.SUSPICIOUS),
    NetworkHost(host_id="HOST-API",    hostname="customer-api-prod-01", ip_address="10.0.3.20", subnet="10.0.3.0/24", os="Linux Ubuntu 22.04",  role="customer_api",          is_critical=True,                        status=HostStatus.SUSPICIOUS),
    NetworkHost(host_id="HOST-DB",     hostname="customer-db-prod-01",  ip_address="10.0.3.21", subnet="10.0.3.0/24", os="Linux RHEL 9",        role="customer_database",     is_critical=True,                        status=HostStatus.CLEAN),
    NetworkHost(host_id="HOST-BACKUP", hostname="backup-server-01",     ip_address="10.0.4.10", subnet="10.0.4.0/24", os="Linux Debian 12",     role="backup",                is_critical=False,                       status=HostStatus.SUSPICIOUS),
]

_CONSTRAINTS = [
    BusinessConstraint(host_id="HOST-CEO", constraint_type="cannot_isolate",  reason="CEO is in live board meeting presenting to investors. Isolation will cut the presentation.", severity="hard_block"),
    BusinessConstraint(host_id="HOST-CEO", constraint_type="legal_hold",      reason="Ongoing litigation — outside counsel requires preservation of all CEO device evidence.",     severity="advisory"),
    BusinessConstraint(host_id="HOST-DC",  constraint_type="critical_infra",  reason="Domain controller — isolation locks out all 1200 employees within 30 minutes.",             severity="advisory"),
    BusinessConstraint(host_id="HOST-API", constraint_type="customer_facing",  reason="API serves 50000 active users. Isolation triggers SLA breach and $500k penalty.",          severity="hard_block"),
    BusinessConstraint(user_id="ceo_user", constraint_type="executive",        reason="CEO account — disabling requires CISO and CEO board approval.",                            severity="advisory"),
]

_ALERTS = [
    SIEMAlert(alert_id="ALT-H01", timestamp="2024-03-15T14:00:00Z", severity=AlertSeverity.CRITICAL, rule_name="C2 Beacon Detected — CEO Device",       description="Periodic HTTPS callbacks to known C2 domain from CEO MacBook every 5 minutes.",           host_id="HOST-CEO",    user_id="ceo_user",   mitre_tactic=MITRETactic.PERSISTENCE,       mitre_technique="T1071.001", indicators=[ThreatIndicator(type="domain", value="telemetry-analytics-corp.com", reputation="malicious"), ThreatIndicator(type="ip", value="185.220.101.47", reputation="malicious")], ground_truth=True),
    SIEMAlert(alert_id="ALT-H02", timestamp="2024-03-15T14:05:00Z", severity=AlertSeverity.CRITICAL, rule_name="Kerberoasting from Executive Subnet",    description="CEO subnet host sending abnormal Kerberos TGS requests targeting svc_api account.",       host_id="HOST-CEO",    user_id="ceo_user",   mitre_tactic=MITRETactic.CREDENTIAL_ACCESS, mitre_technique="T1558.003", indicators=[ThreatIndicator(type="user",   value="svc_api",                   reputation="suspicious")], ground_truth=True),
    SIEMAlert(alert_id="ALT-H03", timestamp="2024-03-15T14:12:00Z", severity=AlertSeverity.HIGH,     rule_name="Domain Controller — Suspicious LDAP",   description="Bulk LDAP enumeration of all user accounts and group memberships via svc_api.",            host_id="HOST-DC",     user_id="svc_api",    mitre_tactic=MITRETactic.DISCOVERY,         mitre_technique="T1087.002", indicators=[ThreatIndicator(type="user",   value="svc_api",                   reputation="suspicious")], ground_truth=True),
    SIEMAlert(alert_id="ALT-H04", timestamp="2024-03-15T14:18:00Z", severity=AlertSeverity.HIGH,     rule_name="DCSync Attack Detected",                description="Non-DC host requesting domain replication (DCSync) — credential dumping technique.",       host_id="HOST-DC",     user_id="svc_api",    mitre_tactic=MITRETactic.CREDENTIAL_ACCESS, mitre_technique="T1003.006", indicators=[ThreatIndicator(type="user",   value="svc_api",                   reputation="malicious")],  ground_truth=True),
    SIEMAlert(alert_id="ALT-H05", timestamp="2024-03-15T14:22:00Z", severity=AlertSeverity.CRITICAL, rule_name="API Server — Anomalous DB Query Volume", description="Customer API executing 10x normal database query volume. Possible data staging.",           host_id="HOST-API",    user_id="svc_api",    mitre_tactic=MITRETactic.COLLECTION,        mitre_technique="T1530",     indicators=[ThreatIndicator(type="user",   value="svc_api",                   reputation="malicious")],  ground_truth=True),
    SIEMAlert(alert_id="ALT-H06", timestamp="2024-03-15T14:25:00Z", severity=AlertSeverity.HIGH,     rule_name="Customer API Response Time Degraded",   description="API p99 latency spiked to 8s (baseline 200ms). 3% error rate. Customer impact ongoing.",  host_id="HOST-API",    user_id=None,         mitre_tactic=MITRETactic.IMPACT,            mitre_technique="T1499",     indicators=[], ground_truth=True),
    SIEMAlert(alert_id="ALT-H07", timestamp="2024-03-15T14:28:00Z", severity=AlertSeverity.HIGH,     rule_name="Backup Server — Unexpected SSH Login",  description="SSH login to backup server from API server IP — lateral movement attempt.",                host_id="HOST-BACKUP", user_id="svc_api",    mitre_tactic=MITRETactic.LATERAL_MOVEMENT,  mitre_technique="T1021.004", indicators=[ThreatIndicator(type="ip",     value="10.0.3.20",                 reputation="suspicious")],  ground_truth=True),
    SIEMAlert(alert_id="ALT-H08", timestamp="2024-03-15T14:30:00Z", severity=AlertSeverity.LOW,      rule_name="Certificate Expiry Warning",            description="SSL certificate for internal monitoring dashboard expires in 14 days.",                    host_id="HOST-DC",     user_id=None,         mitre_tactic=None,                          indicators=[], ground_truth=False),
]

_CHAIN = AttackChain(
    patient_zero_host="HOST-CEO",
    stages=[
        MITRETactic.INITIAL_ACCESS, MITRETactic.PERSISTENCE, MITRETactic.CREDENTIAL_ACCESS,
        MITRETactic.DISCOVERY, MITRETactic.LATERAL_MOVEMENT, MITRETactic.COLLECTION,
        MITRETactic.EXFILTRATION, MITRETactic.IMPACT,
    ],
    lateral_movement_targets=["HOST-DC", "HOST-API", "HOST-BACKUP"],
    crown_jewel_host="HOST-DB",
    exfiltration_complete=False,
    attacker_dwell_minutes=30,
)


def get_hard_scenario(seed: int = 42) -> Dict[str, Any]:
    obs = Observation(
        step=0,
        task_id="constrained_incident_response",
        task_description=(
            "ACTIVE P1 INCIDENT. Attacker has compromised the CEO MacBook and is moving laterally. "
            "HARD CONSTRAINTS: (1) HOST-CEO CANNOT be isolated — CEO is in live board meeting. "
            "(2) HOST-API CANNOT be isolated — 50k customers, $500k SLA penalty. "
            "ADVISORY: HOST-DC isolation locks out 1200 employees. CEO account requires board approval. "
            "COMPLIANCE: Collect forensics from CEO device (legal hold). Escalate. Create ticket. "
            "Goal: contain breach, protect HOST-DB (customer database), stay within constraints. "
            "Alert IDs: ALT-H01 through ALT-H08."
        ),
        active_alerts=[a.model_copy(deep=True) for a in _ALERTS],
        hosts=[h.model_copy(deep=True) for h in _HOSTS],
        business_constraints=[c.model_copy(deep=True) for c in _CONSTRAINTS],
        elapsed_minutes=30,
        max_minutes=240,
        steps_remaining=40,
    )
    return {"observation": obs, "attack_chain": _CHAIN.model_copy(deep=True)}
