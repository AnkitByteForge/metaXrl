"""SOC Incident Response — OpenEnv scenario loaders."""
from typing import Any, Dict
from .easy_scenarios import get_easy_scenario
from .medium_scenarios import get_medium_scenario
from .hard_scenarios import get_hard_scenario


def load_scenario(task_id: str, seed: int = 42) -> Dict[str, Any]:
    """Load scenario for a given task ID.
    
    Args:
        task_id: "alert_triage", "attack_chain_reconstruction", or "constrained_incident_response"
        seed: Random seed for reproducibility
        
    Returns:
        Dict with "observation" and "attack_chain" keys
    """
    if task_id == "alert_triage":
        return get_easy_scenario(seed)
    elif task_id == "attack_chain_reconstruction":
        return get_medium_scenario(seed)
    elif task_id == "constrained_incident_response":
        return get_hard_scenario(seed)
    else:
        raise ValueError(f"Unknown task_id: {task_id}")


__all__ = ["load_scenario"]