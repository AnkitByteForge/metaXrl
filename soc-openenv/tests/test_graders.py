"""Grader tests — bounds, determinism, and scoring logic."""
import pytest
from soc_env import SOCEnv, Action
from soc_env.models import ActionType


def run_episode(task_id, steps=8, seed=42):
    env = SOCEnv(task_id=task_id, seed=seed); env.reset()
    for _ in range(steps):
        s = env.state()
        if s.done: break
        alerts = s.observation.active_alerts
        a = (Action(action_type=ActionType.ENRICH_ALERT,
                    alert_id=alerts[0].alert_id, source="threat_intel")
             if alerts else
             Action(action_type=ActionType.CREATE_TICKET, priority="P2", summary="done"))
        _, _, done, _ = env.step(a)
        if done: break
    return env


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_grade_bounded(task_id):
    score = run_episode(task_id).grade()
    assert 0.0 <= score <= 1.0


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_grade_deterministic(task_id):
    s1 = run_episode(task_id, seed=42).grade()
    s2 = run_episode(task_id, seed=42).grade()
    assert s1 == s2


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_grade_returns_float(task_id):
    score = run_episode(task_id).grade()
    assert isinstance(score, float)


def test_perfect_easy_agent_scores_high():
    """Agent that correctly classifies all alerts should score > 0.5."""
    from soc_env.graders import grade_task_easy
    from soc_env.scenarios.easy_scenarios import _ALERTS
    env = SOCEnv(task_id="alert_triage", seed=42); env.reset()
    s = env._state
    for alert in _ALERTS:
        s.agent_classifications[alert.alert_id] = bool(alert.ground_truth)
        if alert.ground_truth:
            s.isolated_hosts.append(alert.host_id)
    score = grade_task_easy(s)
    assert score >= 0.5, f"Perfect easy agent scored only {score}"


def test_hard_constraint_respect_scores_higher():
    """Agent respecting constraints should outscore one that violates them."""
    from soc_env.graders import grade_task_hard
    env_good = SOCEnv(task_id="constrained_incident_response", seed=42); env_good.reset()
    env_good._state.isolated_hosts = ["HOST-BACKUP"]
    env_good._state.escalated = True
    env_good._state.ticket_created = True
    env_good._state.forensics_collected = {"HOST-CEO": ["memory_dump", "event_logs"]}
    good_score = grade_task_hard(env_good._state)

    env_bad = SOCEnv(task_id="constrained_incident_response", seed=42); env_bad.reset()
    env_bad._state.isolated_hosts = ["HOST-CEO", "HOST-API"]  # violates hard blocks
    bad_score = grade_task_hard(env_bad._state)

    assert good_score > bad_score, f"Constraint-respecting agent ({good_score}) should beat violator ({bad_score})"
