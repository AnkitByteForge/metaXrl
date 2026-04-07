"""Easy scenario: single alert triage session — 5 alerts, 3 true positives, 2 false positives."""
from __future__ import annotations
import random
from typing import Any, Dict

from soc_env.models import (
    AlertSeverity, AlertStatus, HostStatus, MITRETactic,
    NetworkHost, Observation, SIEMAlert, ThreatIndicator,
)

_ALERTS = [
    SIEMAlert(
        alert_id="ALT-001",
        timestamp="2024-03-15T08:12:00Z",
        severity=AlertSeverity.HIGH,
        rule_name="Suspicious PowerShell Execution",
        description="PowerShell launched with encoded command on workstation. Base64 payload detected.",
        host_id="HOST-WS-04",
        user_id="jsmith",
        mitre_tactic=MITRETactic.EXECUTION,
        mitre_technique="T1059.001",
        indicators=[
            ThreatIndicator(type="process", value="powershell.exe -enc JABzAD0ATgBlAHcA...", reputation="malicious"),
            ThreatIndicator(type="hash", value="a3f4b2c1d9e8f7a6b5c4d3e2f1a0b9c8", reputation="malicious"),
        ],
        raw_log="[2024-03-15 08:12:00] PROCESS_CREATE pid=4421 parent=cmd.exe cmd='powershell.exe -enc JABzAD0ATgBlAHcA...'",
        ground_truth=True,
    ),
    SIEMAlert(
        alert_id="ALT-002",
        timestamp="2024-03-15T08:14:00Z",
        severity=AlertSeverity.MEDIUM,
        rule_name="Failed Login Threshold Exceeded",
        description="15 failed RDP login attempts from external IP 203.0.113.42 in 5 minutes.",
        host_id="HOST-SRV-01",
        user_id=None,
        mitre_tactic=MITRETactic.CREDENTIAL_ACCESS,
        mitre_technique="T1110.001",
        indicators=[
            ThreatIndicator(type="ip", value="203.0.113.42", reputation="malicious"),
        ],
        raw_log="[2024-03-15 08:14:00] AUTH_FAIL count=15 src=203.0.113.42 dst=HOST-SRV-01 proto=RDP",
        ground_truth=True,
    ),
    SIEMAlert(
        alert_id="ALT-003",
        timestamp="2024-03-15T08:15:30Z",
        severity=AlertSeverity.LOW,
        rule_name="USB Device Connected",
        description="USB mass storage device connected on HR workstation.",
        host_id="HOST-WS-12",
        user_id="mwilson",
        mitre_tactic=None,
        indicators=[
            ThreatIndicator(type="hash", value="usb_vendor_0x0781", reputation="clean"),
        ],
        raw_log="[2024-03-15 08:15:30] USB_CONNECT device='SanDisk Ultra' user=mwilson",
        ground_truth=False,  # FP: IT-sanctioned backup drive
    ),
    SIEMAlert(
        alert_id="ALT-004",
        timestamp="2024-03-15T08:18:00Z",
        severity=AlertSeverity.CRITICAL,
        rule_name="Data Exfiltration — Large Upload",
        description="2.4GB uploaded to external IP via HTTPS. Destination not in approved cloud list.",
        host_id="HOST-WS-04",
        user_id="jsmith",
        mitre_tactic=MITRETactic.EXFILTRATION,
        mitre_technique="T1048.002",
        indicators=[
            ThreatIndicator(type="ip", value="198.51.100.77", reputation="suspicious"),
            ThreatIndicator(type="domain", value="file-share-quick.net", reputation="malicious"),
        ],
        raw_log="[2024-03-15 08:18:00] NET_UPLOAD src=HOST-WS-04 dst=198.51.100.77 bytes=2576716800 proto=HTTPS",
        ground_truth=True,
    ),
    SIEMAlert(
        alert_id="ALT-005",
        timestamp="2024-03-15T08:19:00Z",
        severity=AlertSeverity.MEDIUM,
        rule_name="Antivirus Definition Update Failed",
        description="AV definition update failed 3 times on server.",
        host_id="HOST-SRV-03",
        user_id=None,
        mitre_tactic=None,
        indicators=[],
        raw_log="[2024-03-15 08:19:00] AV_UPDATE_FAIL retries=3 host=HOST-SRV-03",
        ground_truth=False,  # FP: network timeout, not an attack
    ),
]

_HOSTS = [
    NetworkHost(host_id="HOST-WS-04", hostname="workstation-04", ip_address="10.0.1.14", subnet="10.0.1.0/24", os="Windows 11", role="workstation", owner="jsmith", is_critical=False, status=HostStatus.SUSPICIOUS),
    NetworkHost(host_id="HOST-WS-12", hostname="workstation-12", ip_address="10.0.1.22", subnet="10.0.1.0/24", os="Windows 10", role="workstation", owner="mwilson", is_critical=False, status=HostStatus.CLEAN),
    NetworkHost(host_id="HOST-SRV-01", hostname="rdp-gateway-01", ip_address="10.0.2.10", subnet="10.0.2.0/24", os="Windows Server 2019", role="rdp_gateway", is_critical=True, status=HostStatus.CLEAN),
    NetworkHost(host_id="HOST-SRV-03", hostname="file-server-03", ip_address="10.0.2.30", subnet="10.0.2.0/24", os="Windows Server 2022", role="file_server", is_critical=False, status=HostStatus.CLEAN),
]


def get_easy_scenario(seed: int = 42) -> Dict[str, Any]:
    alerts = [a.model_copy(deep=True) for a in _ALERTS]
    if seed != 42:
        random.Random(seed).shuffle(alerts)
    obs = Observation(
        step=0,
        task_id="alert_triage",
        task_description=(
            "You are a SOC Tier-1 analyst. Five SIEM alerts fired in the last 10 minutes. "
            "Your job: (1) Classify each alert as true_positive or false_positive — "
            "use enrich_alert to gather context first. "
            "(2) For each true positive, take containment action: isolate_endpoint or disable_account. "
            "Available alert IDs: ALT-001, ALT-002, ALT-003, ALT-004, ALT-005."
        ),
        active_alerts=alerts,
        hosts=[h.model_copy(deep=True) for h in _HOSTS],
        business_constraints=[],
        elapsed_minutes=0,
        max_minutes=30,
        steps_remaining=10,
    )
    return {"observation": obs, "attack_chain": None}
