"""Core environment contract tests."""
import pytest
from soc_env import SOCEnv, Action
from soc_env.models import ActionType, Observation, Reward, EnvState


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_reset_returns_observation(task_id):
    env = SOCEnv(task_id=task_id, seed=42)
    obs = env.reset()
    assert isinstance(obs, Observation)
    assert obs.step == 0
    assert len(obs.active_alerts) > 0
    assert len(obs.hosts) > 0


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_reset_is_reproducible(task_id):
    e1 = SOCEnv(task_id=task_id, seed=42); o1 = e1.reset()
    e2 = SOCEnv(task_id=task_id, seed=42); o2 = e2.reset()
    assert o1.model_dump() == o2.model_dump()


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_step_returns_correct_types(task_id):
    env = SOCEnv(task_id=task_id, seed=42)
    obs = env.reset()
    action = Action(action_type=ActionType.ENRICH_ALERT,
                    alert_id=obs.active_alerts[0].alert_id, source="threat_intel")
    obs2, reward, done, info = env.step(action)
    assert isinstance(obs2, Observation)
    assert isinstance(reward, Reward)
    assert isinstance(done, bool)
    assert isinstance(info, dict)
    assert -1.0 <= reward.total <= 1.0


@pytest.mark.parametrize("task_id", SOCEnv.TASK_IDS)
def test_state_returns_envstate(task_id):
    env = SOCEnv(task_id=task_id, seed=42); env.reset()
    s = env.state()
    assert isinstance(s, EnvState)
    assert s.task_id == task_id


def test_step_raises_before_reset():
    env = SOCEnv()
    with pytest.raises(RuntimeError, match="reset"):
        env.step(Action(action_type=ActionType.CREATE_TICKET, priority="P1"))


def test_episode_terminates():
    env = SOCEnv(task_id="alert_triage", seed=42); env.reset()
    for _ in range(SOCEnv.MAX_STEPS["alert_triage"] + 2):
        s = env.state()
        if s.done: break
        alerts = s.observation.active_alerts
        action = (Action(action_type=ActionType.ENRICH_ALERT,
                         alert_id=alerts[0].alert_id, source="threat_intel")
                  if alerts else
                  Action(action_type=ActionType.CREATE_TICKET, priority="P3", summary="done"))
        _, _, done, _ = env.step(action)
        if done: break
    assert env.state().done


def test_hard_block_prevents_isolation():
    env = SOCEnv(task_id="constrained_incident_response", seed=42); env.reset()
    obs, _, _, _ = env.step(Action(action_type=ActionType.ISOLATE_ENDPOINT, host_id="HOST-CEO"))
    assert "BLOCKED" in (obs.last_action_result or "")
    assert obs.last_action_success is False


def test_ground_truth_hidden_in_observation():
    env = SOCEnv(task_id="alert_triage", seed=42)
    obs = env.reset()
    obs_dict = obs.model_dump_safe()
    for alert in obs_dict.get("active_alerts", []):
        assert "ground_truth" not in alert, "ground_truth must never reach the agent"
