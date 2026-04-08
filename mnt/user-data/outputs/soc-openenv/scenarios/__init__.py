"""Scenario loader — dispatches to the right scenario module by task_id."""
from __future__ import annotations
from importlib import import_module
from typing import Any, Dict


def _get_scenario_fn(module_name: str, function_name: str):
    package = __package__ or "scenarios"
    module = import_module(f"{package}.{module_name}")
    return getattr(module, function_name)


def load_scenario(task_id: str, seed: int = 42) -> Dict[str, Any]:
    """Return scenario dict with keys: 'observation', 'attack_chain' (optional)."""
    if task_id == "alert_triage":
        return _get_scenario_fn("easy_scenarios", "get_easy_scenario")(seed)
    elif task_id == "attack_chain_reconstruction":
        return _get_scenario_fn("medium_scenarios", "get_medium_scenario")(seed)
    elif task_id == "constrained_incident_response":
        return _get_scenario_fn("hard_scenarios", "get_hard_scenario")(seed)
    raise ValueError(f"Unknown task_id: {task_id!r}")
