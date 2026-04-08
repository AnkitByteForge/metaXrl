"""Medium scenario: 15 alerts across 4 hosts — full 9-stage ATT&CK kill chain to reconstruct."""
from __future__ import annotations
from typing import Any, Dict

from soc_env.models import (
    AlertSeverity, AttackChain, HostStatus, MITRETactic,
    NetworkHost, Observation, SIEMAlert, ThreatIndicator,
)

_HOSTS = [
    NetworkHost(host_id="HOST-WS-07", hostname="marketing-ws-07", ip_address="10.0.1.17", subnet="10.0.1.0/24", os="Windows 11", role="workstation", owner="tmartin", is_critical=False, status=HostStatus.COMPROMISED),
    NetworkHost(host_id="HOST-WS-11", hostname="finance-ws-11",   ip_address="10.0.1.21", subnet="10.0.1.0/24", os="Windows 10", role="workstation", owner="alee",    is_critical=False, status=HostStatus.SUSPICIOUS),
    NetworkHost(host_id="HOST-SRV-DC", hostname="domain-controller-01", ip_address="10.0.2.5",  subnet="10.0.2.0/24", os="Windows Server 2019", role="domain_controller", is_critical=True,  status=HostStatus.SUSPICIOUS),
    NetworkHost(host_id="HOST-SRV-DB", hostname="finance-db-01",  ip_address="10.0.3.10", subnet="10.0.3.0/24", os="Linux RHEL 8",         role="database_server", is_critical=True,  owner="svc_finance", status=HostStatus.CLEAN),
]

_ALERTS = [
    # Stage 1 — Initial Access
    SIEMAlert(alert_id="ALT-M01", timestamp="2024-03-15T09:00:00Z", severity=AlertSeverity.MEDIUM,   rule_name="Macro-Enabled Office Doc Opened",     description="User opened a macro-enabled Word document from email attachment.",                        host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.INITIAL_ACCESS,    mitre_technique="T1566.001", indicators=[ThreatIndicator(type="hash",    value="d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", reputation="malicious"), ThreatIndicator(type="domain", value="invoice-docs-2024.com", reputation="malicious")], ground_truth=True),
    # Stage 2 — Execution
    SIEMAlert(alert_id="ALT-M02", timestamp="2024-03-15T09:02:00Z", severity=AlertSeverity.HIGH,     rule_name="VBA Macro Spawned Child Process",      description="WINWORD.EXE spawned cmd.exe which spawned powershell.exe.",                             host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.EXECUTION,         mitre_technique="T1204.002", indicators=[ThreatIndicator(type="process", value="WINWORD.EXE->cmd.exe->powershell.exe",   reputation="malicious")], ground_truth=True),
    # Stage 3 — Persistence
    SIEMAlert(alert_id="ALT-M03", timestamp="2024-03-15T09:04:00Z", severity=AlertSeverity.HIGH,     rule_name="Registry Run Key Modified",           description="Persistence entry added to HKCU CurrentVersion Run.",                                    host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.PERSISTENCE,       mitre_technique="T1547.001", indicators=[ThreatIndicator(type="registry_key", value="HKCU\\...\\Run\\WindowsUpdateHelper", reputation="malicious")], ground_truth=True),
    # Stage 4 — Defense Evasion
    SIEMAlert(alert_id="ALT-M04", timestamp="2024-03-15T09:06:00Z", severity=AlertSeverity.HIGH,     rule_name="Windows Defender Disabled via Registry", description="Windows Defender real-time protection disabled via registry key.",                      host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.DEFENSE_EVASION,   mitre_technique="T1562.001", indicators=[ThreatIndicator(type="registry_key", value="DisableRealtimeMonitoring=1",         reputation="malicious")], ground_truth=True),
    # Stage 5 — Credential Access
    SIEMAlert(alert_id="ALT-M05", timestamp="2024-03-15T09:10:00Z", severity=AlertSeverity.CRITICAL, rule_name="LSASS Memory Access Detected",         description="Process accessed lsass.exe memory — possible credential dumping with mimikatz.",          host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.CREDENTIAL_ACCESS, mitre_technique="T1003.001", indicators=[ThreatIndicator(type="process", value="mimikatz.exe",                              reputation="malicious")], ground_truth=True),
    # Stage 6 — Discovery
    SIEMAlert(alert_id="ALT-M06", timestamp="2024-03-15T09:15:00Z", severity=AlertSeverity.MEDIUM,   rule_name="Internal Network Scan Detected",      description="Host scanning internal subnets on ports 445, 3389, 5985.",                               host_id="HOST-WS-07",  user_id="tmartin",    mitre_tactic=MITRETactic.DISCOVERY,         mitre_technique="T1046",     indicators=[ThreatIndicator(type="ip",      value="10.0.1.17",                                reputation="suspicious")],  ground_truth=True),
    # FP noise
    SIEMAlert(alert_id="ALT-M07", timestamp="2024-03-15T09:16:00Z", severity=AlertSeverity.LOW,      rule_name="Scheduled Task Created",              description="Scheduled task for Windows Update created by SYSTEM account.",                            host_id="HOST-WS-11",  user_id="SYSTEM",     mitre_tactic=None, indicators=[], ground_truth=False),
    # Stage 7 — Lateral Movement (pass-the-hash)
    SIEMAlert(alert_id="ALT-M08", timestamp="2024-03-15T09:22:00Z", severity=AlertSeverity.HIGH,     rule_name="Pass-the-Hash Login Detected",         description="Successful NTLM auth to finance workstation using harvested credential hash.",             host_id="HOST-WS-11",  user_id="tmartin",    mitre_tactic=MITRETactic.LATERAL_MOVEMENT,  mitre_technique="T1550.002", indicators=[ThreatIndicator(type="hash",    value="ntlm:aad3b435b51404ee",               reputation="malicious")],   ground_truth=True),
    # Stage 8 — Credential Access on DC
    SIEMAlert(alert_id="ALT-M09", timestamp="2024-03-15T09:28:00Z", severity=AlertSeverity.CRITICAL, rule_name="Kerberoasting Attack Detected",        description="SPN scanning and TGS requests for service accounts from non-standard host.",              host_id="HOST-SRV-DC", user_id="tmartin",    mitre_tactic=MITRETactic.CREDENTIAL_ACCESS, mitre_technique="T1558.003", indicators=[ThreatIndicator(type="user",    value="svc_finance",                          reputation="suspicious")],  ground_truth=True),
    # FP noise
    SIEMAlert(alert_id="ALT-M10", timestamp="2024-03-15T09:30:00Z", severity=AlertSeverity.LOW,      rule_name="DNS Query for External Domain",        description="Routine DNS lookup for software-updates.microsoft.com.",                                  host_id="HOST-WS-11",  user_id="alee",       mitre_tactic=None, indicators=[], ground_truth=False),
    # Stage 9 — Collection
    SIEMAlert(alert_id="ALT-M11", timestamp="2024-03-15T09:35:00Z", severity=AlertSeverity.HIGH,     rule_name="Sensitive File Access — Finance Dir",  description="Bulk read of finance reports directory — 400 files in 2 minutes.",                        host_id="HOST-SRV-DB", user_id="svc_finance", mitre_tactic=MITRETactic.COLLECTION,        mitre_technique="T1560",     indicators=[ThreatIndicator(type="user",    value="svc_finance",                          reputation="suspicious")],  ground_truth=True),
    # FP noise
    SIEMAlert(alert_id="ALT-M12", timestamp="2024-03-15T09:38:00Z", severity=AlertSeverity.LOW,      rule_name="Account Password Changed",            description="User alee changed password via self-service portal.",                                     host_id="HOST-SRV-DC", user_id="alee",       mitre_tactic=None, indicators=[], ground_truth=False),
    # Stage 10 — Exfiltration staging
    SIEMAlert(alert_id="ALT-M13", timestamp="2024-03-15T09:42:00Z", severity=AlertSeverity.CRITICAL, rule_name="Large Compressed Archive Created",     description="7z archive (1.8GB) created in temp directory containing xlsx and pdf files.",               host_id="HOST-WS-11",  user_id="tmartin",    mitre_tactic=MITRETactic.COLLECTION,        mitre_technique="T1560.001", indicators=[ThreatIndicator(type="hash",    value="archive_temp_a7f2c1",                  reputation="suspicious")],  ground_truth=True),
    # Stage 11 — Exfiltration upload
    SIEMAlert(alert_id="ALT-M14", timestamp="2024-03-15T09:45:00Z", severity=AlertSeverity.CRITICAL, rule_name="Data Exfiltration — Encrypted Upload",  description="1.8GB upload to mega.nz via HTTPS from finance workstation.",                             host_id="HOST-WS-11",  user_id="tmartin",    mitre_tactic=MITRETactic.EXFILTRATION,      mitre_technique="T1041",     indicators=[ThreatIndicator(type="domain",  value="mega.nz",                              reputation="suspicious")],  ground_truth=True),
    # FP noise
    SIEMAlert(alert_id="ALT-M15", timestamp="2024-03-15T09:47:00Z", severity=AlertSeverity.LOW,      rule_name="PowerShell Script Block Logging",      description="Routine IT admin disk cleanup script executed by IT service account.",                    host_id="HOST-SRV-DC", user_id="svc_itadmin", mitre_tactic=None, indicators=[], ground_truth=False),
]

_CHAIN = AttackChain(
    patient_zero_host="HOST-WS-07",
    stages=[
        MITRETactic.INITIAL_ACCESS, MITRETactic.EXECUTION, MITRETactic.PERSISTENCE,
        MITRETactic.DEFENSE_EVASION, MITRETactic.CREDENTIAL_ACCESS, MITRETactic.DISCOVERY,
        MITRETactic.LATERAL_MOVEMENT, MITRETactic.COLLECTION, MITRETactic.EXFILTRATION,
    ],
    lateral_movement_targets=["HOST-WS-11", "HOST-SRV-DC"],
    crown_jewel_host="HOST-SRV-DB",
    exfiltration_complete=False,
    attacker_dwell_minutes=47,
)


def get_medium_scenario(seed: int = 42) -> Dict[str, Any]:
    obs = Observation(
        step=0,
        task_id="attack_chain_reconstruction",
        task_description=(
            "ACTIVE INCIDENT — 15 alerts across 4 hosts in the last 47 minutes. "
            "Your mission: (1) Correlate alerts to identify the full MITRE ATT&CK kill chain. "
            "(2) Identify patient zero — the first compromised host. "
            "(3) Contain the threat before it reaches the finance database HOST-SRV-DB. "
            "Use correlate_alerts with hypothesis to map the attack stages. "
            "Alert IDs: ALT-M01 through ALT-M15."
        ),
        active_alerts=[a.model_copy(deep=True) for a in _ALERTS],
        hosts=[h.model_copy(deep=True) for h in _HOSTS],
        business_constraints=[],
        elapsed_minutes=47,
        max_minutes=120,
        steps_remaining=25,
    )
    return {"observation": obs, "attack_chain": _CHAIN.model_copy(deep=True)}
