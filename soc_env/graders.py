"""
Deterministic graders for all 3 tasks.
Every grader:
  - Takes EnvState (includes ground truth)
    - Returns float strictly in (0.0, 1.0)
  - Is 100% deterministic: same state -> same score
"""
from __future__ import annotations
from typing import Dict, Tuple

from .models import EnvState, HostStatus


# Keep margin large enough to survive external validator rounding/serialization.
_SCORE_EPS = 1e-1


def _strict_score(value: float) -> float:
    """Clamp score to a strict open interval required by deployment validators."""
    return max(_SCORE_EPS, min(1.0 - _SCORE_EPS, value))


# ---------------------------------------------------------------------------
# Task 1 — Easy: Alert triage
# ---------------------------------------------------------------------------

def grade_task_easy(state: EnvState) -> float:
    _, score = _score_alert_triage(state)
    return round(_strict_score(score), 4)


def grade_task_easy_detailed(state: EnvState) -> Tuple[Dict, float]:
    breakdown, score = _score_alert_triage(state)
    return breakdown, round(_strict_score(score), 4)


def _score_alert_triage(state: EnvState) -> Tuple[Dict, float]:
    """
    score = 0.6 * classification_accuracy
          + 0.4 * containment_action_score
          - fp_isolation_penalty
    """
    all_alerts = state.observation.active_alerts + state.observation.acknowledged_alerts
    if not all_alerts:
        return {}, _strict_score(0.0)

    tp_alerts = [a for a in all_alerts if a.ground_truth is True]
    fp_alerts = [a for a in all_alerts if a.ground_truth is False]

    # Classification accuracy
    correct_tp = sum(
        1 for a in tp_alerts
        if state.agent_classifications.get(a.alert_id) is True
    )
    correct_fp = sum(
        1 for a in fp_alerts
        if state.agent_classifications.get(a.alert_id) is False
    )
    classification_accuracy = (correct_tp + correct_fp) / len(all_alerts)

    # Containment: did agent isolate host or disable account for each TP?
    containment_hits = 0
    for a in tp_alerts:
        if a.host_id in state.isolated_hosts:
            containment_hits += 1
        elif a.user_id and a.user_id in state.disabled_accounts:
            containment_hits += 1
    action_score = containment_hits / len(tp_alerts) if tp_alerts else 1.0

    # Penalty for isolating FP hosts
    fp_host_ids = {a.host_id for a in fp_alerts}
    fp_isolations = sum(1 for h in state.isolated_hosts if h in fp_host_ids)
    fp_penalty = min(fp_isolations * 0.1, 0.3)

    final = _strict_score(round(
        0.6 * classification_accuracy + 0.4 * action_score - fp_penalty, 4
    ))
    breakdown = {
        "classification_accuracy": round(classification_accuracy, 3),
        "action_score": round(action_score, 3),
        "fp_isolations": fp_isolations,
        "fp_penalty": fp_penalty,
        "total_alerts": len(all_alerts),
        "correct_tp": correct_tp,
        "correct_fp": correct_fp,
    }
    return breakdown, final


# ---------------------------------------------------------------------------
# Task 2 — Medium: Attack chain reconstruction
# ---------------------------------------------------------------------------

def grade_task_medium(state: EnvState) -> float:
    _, score = _score_chain_reconstruction(state)
    return round(_strict_score(score), 4)


def grade_task_medium_detailed(state: EnvState) -> Tuple[Dict, float]:
    breakdown, score = _score_chain_reconstruction(state)
    return breakdown, round(_strict_score(score), 4)


def _score_chain_reconstruction(state: EnvState) -> Tuple[Dict, float]:
    """
    score = 0.50 * chain_coverage
          + 0.30 * containment_score
          - 0.10 * dwell_penalty
          - 0.10 * fp_isolation_penalty
    """
    chain = state.attack_chain
    if not chain:
        return {}, _strict_score(0.0)

    # Chain coverage
    true_stages = set(chain.stages)
    found_stages = set(state.identified_stages)
    chain_coverage = len(true_stages & found_stages) / len(true_stages) if true_stages else 0.0

    # Containment
    pz_isolated = chain.patient_zero_host in state.isolated_hosts
    lat_isolated = bool(set(chain.lateral_movement_targets) & set(state.isolated_hosts))
    crown_host = next(
        (h for h in state.observation.hosts if h.host_id == chain.crown_jewel_host), None
    )
    crown_safe = crown_host is None or crown_host.status not in (HostStatus.COMPROMISED,)
    containment_score = (0.4 * int(pz_isolated)) + (0.3 * int(lat_isolated)) + (0.3 * int(crown_safe))

    # Dwell penalty
    dwell_penalty = min(chain.attacker_dwell_minutes / 120.0 * 0.1, 0.1)

    # FP isolation penalty
    all_chain_hosts = {chain.patient_zero_host} | set(chain.lateral_movement_targets) | {chain.crown_jewel_host}
    fp_isolations = sum(1 for h in state.isolated_hosts if h not in all_chain_hosts)
    fp_penalty = min(fp_isolations * 0.05, 0.1)

    final = _strict_score(round(
        0.5 * chain_coverage + 0.3 * containment_score - dwell_penalty - fp_penalty, 4
    ))
    breakdown = {
        "chain_coverage": round(chain_coverage, 3),
        "stages_found": len(found_stages & true_stages),
        "stages_total": len(true_stages),
        "containment_score": round(containment_score, 3),
        "pz_isolated": pz_isolated,
        "lat_isolated": lat_isolated,
        "crown_safe": crown_safe,
        "dwell_penalty": round(dwell_penalty, 3),
        "fp_isolations": fp_isolations,
        "fp_penalty": round(fp_penalty, 3),
    }
    return breakdown, final


# ---------------------------------------------------------------------------
# Task 3 — Hard: Constrained incident response
# ---------------------------------------------------------------------------

def grade_task_hard(state: EnvState) -> float:
    _, score = _score_constrained_response(state)
    return round(_strict_score(score), 4)


def grade_task_hard_detailed(state: EnvState) -> Tuple[Dict, float]:
    breakdown, score = _score_constrained_response(state)
    return breakdown, round(_strict_score(score), 4)


def _score_constrained_response(state: EnvState) -> Tuple[Dict, float]:
    """
    score = 0.40 * security_score
          + 0.35 * business_continuity_score
          + 0.25 * compliance_score
    """
    obs = state.observation

    # Security (reuse medium grader)
    _, security_score = _score_chain_reconstruction(state)

    # Business continuity
    hard_violations = 0
    advisory_violations = 0
    for bc in obs.business_constraints:
        host_acted = bc.host_id and bc.host_id in state.isolated_hosts
        user_acted = bc.user_id and bc.user_id in state.disabled_accounts
        if host_acted or user_acted:
            if bc.severity == "hard_block":
                hard_violations += 1
            else:
                advisory_violations += 1

    business_continuity = max(0.0,
        1.0 - (hard_violations * 0.4) - (advisory_violations * 0.1)
    )
    # Bonus: customer-facing systems kept alive
    customer_hosts = [
        h for h in obs.hosts
        if any(bc.host_id == h.host_id and bc.constraint_type == "customer_facing"
               for bc in obs.business_constraints)
    ]
    customer_alive = all(h.status != HostStatus.ISOLATED for h in customer_hosts)
    if customer_alive:
        business_continuity = min(1.0, business_continuity + 0.1)

    # Compliance
    legal_hold_hosts = [
        bc.host_id for bc in obs.business_constraints
        if bc.constraint_type == "legal_hold" and bc.host_id
    ]
    forensics_compliance = (
        sum(1 for h in legal_hold_hosts if h in state.forensics_collected) / len(legal_hold_hosts)
        if legal_hold_hosts else 1.0
    )
    compliance_score = round(
        0.5 * forensics_compliance
        + 0.3 * float(state.escalated)
        + 0.2 * float(state.ticket_created),
        4,
    )

    final = _strict_score(round(
        0.40 * security_score + 0.35 * business_continuity + 0.25 * compliance_score, 4
    ))
    breakdown = {
        "security_score": round(security_score, 3),
        "business_continuity": round(business_continuity, 3),
        "hard_violations": hard_violations,
        "advisory_violations": advisory_violations,
        "customer_alive": customer_alive,
        "compliance_score": round(compliance_score, 3),
        "forensics_compliance": round(forensics_compliance, 3),
        "escalated": state.escalated,
        "ticket_created": state.ticket_created,
    }
    return breakdown, final
