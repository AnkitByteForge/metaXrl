import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from soc_env import SOCEnv

@pytest.fixture
def easy_env():
    e = SOCEnv(task_id="alert_triage", seed=42); e.reset(); return e

@pytest.fixture
def medium_env():
    e = SOCEnv(task_id="attack_chain_reconstruction", seed=42); e.reset(); return e

@pytest.fixture
def hard_env():
    e = SOCEnv(task_id="constrained_incident_response", seed=42); e.reset(); return e
