"""Scenario loader — dispatches to the right scenario module by task_id."""
from __future__ import annotations
from typing import Any, Dict

from .easy_scenarios import get_easy_scenario
from .medium_scenarios import get_medium_scenario
from .hard_scenarios import get_hard_scenario


def load_scenario(task_id: str, seed: int = 42) -> Dict[str, Any]:
    """Return scenario dict with keys: 'observation', 'attack_chain' (optional)."""
    if task_id == "alert_triage":
        return get_easy_scenario(seed)
    elif task_id == "attack_chain_reconstruction":
        return get_medium_scenario(seed)
    elif task_id == "constrained_incident_response":
        return get_hard_scenario(seed)
    raise ValueError(f"Unknown task_id: {task_id!r}")
