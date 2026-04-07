# SOC Incident Response — OpenEnv

A real-world Security Operations Center environment where an AI agent acts as a Tier-1 SOC analyst. The agent triages SIEM alerts, reconstructs MITRE ATT&CK kill chains, isolates compromised hosts, and navigates genuine business constraints during active incidents.

**Industry:** $200B+ cybersecurity market. CrowdStrike, Palo Alto, Microsoft all building autonomous SOC agents.
**Why it matters:** SOC analysts face 1,000+ alerts/day. Mean time to containment is 280 days. This environment trains agents for exactly that workflow.

---

## Tasks

| ID | Difficulty | Max Steps | Description |
|---|---|---|---|
| `alert_triage` | Easy | 10 | 5 alerts (3 TP, 2 FP) — classify and contain |
| `attack_chain_reconstruction` | Medium | 25 | 15 alerts, 4 hosts, 9-stage ATT&CK kill chain |
| `constrained_incident_response` | Hard | 40 | Active breach, CEO laptop, customer API, legal hold |

---

## Observation Space

```
Observation
├── step, task_id, task_description
├── active_alerts: List[SIEMAlert]
│   ├── alert_id, timestamp, severity, rule_name, description
│   ├── host_id, user_id, mitre_tactic, mitre_technique
│   ├── indicators: [{type, value, reputation}]
│   ├── raw_log, status, enrichment (after enrich_alert)
│   └── [ground_truth hidden from agent]
├── hosts: List[NetworkHost]
│   └── host_id, hostname, ip, role, status, is_critical, is_vip
├── business_constraints: List[BusinessConstraint]
│   └── host_id/user_id, constraint_type, severity (advisory|hard_block), reason
├── notes: List[InvestigationNote]   (agent's action history)
├── elapsed_minutes, steps_remaining
└── last_action_result, last_action_success
```

---

## Action Space

| action_type | Required fields | Effect |
|---|---|---|
| `enrich_alert` | `alert_id`, `source` ("threat_intel"\|"user_context"\|"asset_db") | Reveals indicator reputations and context |
| `correlate_alerts` | `alert_ids` (list), `correlation_hypothesis` | Links alerts, identifies MITRE tactics |
| `isolate_endpoint` | `host_id` | Cuts host from network (blocked by hard_block constraints) |
| `disable_account` | `user_id` | Revokes credentials, kills sessions |
| `collect_forensics` | `host_id`, `artifact_types` | Collects evidence; applies legal hold if required |
| `escalate_to_tier2` | `summary` | Hands off to senior analyst |
| `create_ticket` | `priority`, `summary` | Creates incident record |

---

## Reward Function

| Event | Reward |
|---|---|
| Enrich alert | +0.05 |
| New ATT&CK stage identified | +0.08 per stage |
| Correct host isolation (in chain) | +0.25 |
| Correct account disable | +0.10 |
| Collect forensics | +0.05 |
| Appropriate escalation | +0.10 |
| Create ticket | +0.05 |
| False positive isolation | −0.20 |
| Per-step dwell time | −0.015 to −0.030 |
| Invalid action | −0.02 |

Rewards clipped to [−1.0, 1.0] per step.

---

## Grader Logic

**Easy** — `score = 0.6 × classification_accuracy + 0.4 × containment_score − fp_penalty`

**Medium** — `score = 0.5 × chain_coverage + 0.3 × containment + −0.1 × dwell − 0.1 × fp_isolations`

**Hard** — `score = 0.40 × security + 0.35 × business_continuity + 0.25 × compliance`

All graders are 100% deterministic. Same state → same score, always.

---

## Setup & Usage

### Install locally

```bash
git clone https://github.com/YOUR_USERNAME/soc-openenv
cd soc-openenv
pip install -r requirements.txt
pip install -e . --no-deps
```

### Run the server

```bash
python server.py
# API docs at http://localhost:7860/docs
```

### Quick API test

```bash
# Reset
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": "alert_triage", "seed": 42}'

# Step
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"task_id":"alert_triage","action":{"action_type":"enrich_alert","alert_id":"ALT-001","source":"threat_intel"}}'

# Grade
curl -X POST "http://localhost:7860/grade?task_id=alert_triage"
```

### Run baseline inference

```bash
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
export HF_TOKEN="hf_your_token_here"

python inference.py          # all 3 tasks
python inference.py --task alert_triage   # single task
```

### Run tests

```bash
pip install pytest
pytest tests/ -v
```

### Docker

```bash
docker build -t soc-openenv .
docker run -p 7860:7860 \
  -e API_BASE_URL="https://router.huggingface.co/v1" \
  -e MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct" \
  -e HF_TOKEN="hf_your_token_here" \
  soc-openenv
```

### Validate before submitting

```bash
chmod +x validate.sh
./validate.sh                                      # local checks
./validate.sh https://YOUR_USERNAME-soc-openenv.hf.space  # + HF ping
```

### Deploy to Hugging Face Spaces

```bash
pip install huggingface_hub
huggingface-cli login
openenv push --repo-id YOUR_USERNAME/soc-openenv
```

---

## Baseline Scores

Run `python inference.py` after setting your API keys to generate actual numbers. Replace the placeholders below:

| Task | Difficulty | Score | Notes |
|---|---|---|---|
| alert_triage | Easy | TBD | Run inference.py |
| attack_chain_reconstruction | Medium | TBD | Run inference.py |
| constrained_incident_response | Hard | TBD | Run inference.py |

Scores are reproducible with `seed=42`. Results saved to `baseline_results.json`.

---

## Project Structure

```
soc-openenv/
├── openenv.yaml              OpenEnv spec (name, tasks, endpoints)
├── Dockerfile                Container — port 7860, healthcheck
├── requirements.txt          Pinned Python dependencies
├── pyproject.toml            Package config
├── README.md                 This file
├── inference.py              Baseline script (MANDATORY — root level)
├── server.py                 FastAPI: /reset /step /state /grade /tasks
├── validate.sh               Pre-submission validator
│
├── soc_env/                  Core package
│   ├── __init__.py
│   ├── models.py             Pydantic models: Observation, Action, Reward, EnvState
│   ├── environment.py        SOCEnv: reset() step() state() grade()
│   └── graders.py            3 deterministic graders → float [0.0, 1.0]
│
├── scenarios/                Synthetic scenario data
│   ├── __init__.py           load_scenario() dispatcher
│   ├── easy_scenarios.py     5 alerts, clear TP/FP
│   ├── medium_scenarios.py   15 alerts, 9-stage ATT&CK chain
│   └── hard_scenarios.py     Active breach + business constraints
│
└── tests/
    ├── conftest.py
    ├── test_environment.py   reset/step/state contract, hard-block enforcement
    └── test_graders.py       bounds, determinism, scoring logic
```

---

## MITRE ATT&CK Coverage

The medium and hard scenarios cover the following tactics:
Initial Access → Execution → Persistence → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration → Impact

Technique IDs follow ATT&CK Enterprise v14.

---

## Contact

help_openenvhackathon@scaler.com
