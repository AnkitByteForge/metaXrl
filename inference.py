"""
inference.py — Baseline inference script for SOC Incident Response OpenEnv.

MANDATORY: must be named inference.py and live in the repo root.

The script uses the OpenAI client against an OpenAI-compatible Hugging Face
endpoint, so the model call stays standard while the credentials come from HF.

Environment variables:
    API_BASE_URL  — Hugging Face / OpenAI-compatible LLM endpoint
    MODEL_NAME    — model identifier
    HF_TOKEN      — Hugging Face access token (no default)
    LOCAL_IMAGE_NAME — optional, for docker-image based flows

Usage:
    python inference.py                    # runs all 3 tasks
    python inference.py --task alert_triage
"""
import argparse
import json
import os
import re
import sys
import textwrap
import openenv
from typing import Any, Dict, List, Optional

from openai import OpenAI

from soc_env import SOCEnv, Action
from soc_env.models import ActionType

# ---------------------------------------------------------------------------
# Config — read from environment variables (mandatory per spec)
# ---------------------------------------------------------------------------
API_BASE_URL: str = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME: str   = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
HF_TOKEN: Optional[str] = os.getenv("HF_TOKEN")
LOCAL_IMAGE_NAME: Optional[str] = os.getenv("LOCAL_IMAGE_NAME")

TEMPERATURE: float = 0.1
MAX_TOKENS: int    = 512
SEED: int          = 42
SCORE_EPS: float   = 1e-1

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = textwrap.dedent("""
You are an expert Tier-1 SOC (Security Operations Center) analyst.
You will be given the current state of a simulated security incident.
Respond with exactly ONE action as a raw JSON object — no markdown, no explanation, nothing else.

Available action_type values and their required fields:
  enrich_alert        -> alert_id (str), source ("threat_intel"|"user_context"|"asset_db")
  correlate_alerts    -> alert_ids (list of str), correlation_hypothesis (str)
  isolate_endpoint    -> host_id (str)
  disable_account     -> user_id (str)
  collect_forensics   -> host_id (str), artifact_types (list: "memory_dump","event_logs","network_capture")
  escalate_to_tier2   -> summary (str)
  create_ticket       -> priority ("P1"|"P2"|"P3"), summary (str)

Strategy:
1. Enrich high-severity alerts first to understand indicators.
2. Correlate related alerts to identify ATT&CK stages.
3. Isolate compromised hosts — but NEVER violate hard_block business constraints.
4. Disable attacker-controlled accounts.
5. Collect forensics on legal-hold hosts.
6. Escalate if there are complex business constraints you cannot resolve.
7. Create a ticket before closing.

Output format example:
{"action_type": "enrich_alert", "alert_id": "ALT-001", "source": "threat_intel"}
""").strip()

# ---------------------------------------------------------------------------
# Build prompt from observation dict
# ---------------------------------------------------------------------------

def observation_to_prompt(obs: dict, step: int) -> str:
    active   = obs.get("active_alerts", [])
    hosts    = obs.get("hosts", [])
    constraints = obs.get("business_constraints", [])
    notes    = obs.get("notes", [])[-3:]

    lines = [
        f"STEP {step} | Task: {obs.get('task_id')} | Steps left: {obs.get('steps_remaining')} | Elapsed: {obs.get('elapsed_minutes')}min",
        "",
        "=== TASK DESCRIPTION ===",
        obs.get("task_description", ""),
        "",
        f"=== ACTIVE ALERTS ({len(active)}) ===",
    ]
    for a in active[:12]:
        lines.append(
            f"  [{a['alert_id']}] SEV={a['severity'].upper()} HOST={a['host_id']} "
            f"USER={a.get('user_id','N/A')} TACTIC={a.get('mitre_tactic') or '?'} "
            f"RULE: {a['rule_name']}"
        )
        if a.get("enrichment"):
            lines.append(f"    enrichment: {json.dumps(a['enrichment'])}")
        if a.get("indicators"):
            for ind in a["indicators"][:2]:
                lines.append(f"    indicator: {ind['type']}={ind['value']} rep={ind.get('reputation','?')}")

    lines += ["", f"=== HOSTS ==="]
    for h in hosts:
        lines.append(
            f"  [{h['host_id']}] {h['hostname']} status={h['status']} "
            f"role={h['role']} critical={h['is_critical']} vip={h.get('is_vip', False)}"
        )

    if constraints:
        lines += ["", "=== BUSINESS CONSTRAINTS (respect hard_block!) ==="]
        for bc in constraints:
            lines.append(
                f"  host={bc.get('host_id','N/A')} user={bc.get('user_id','N/A')} "
                f"type={bc['constraint_type']} severity={bc['severity']} | {bc['reason']}"
            )

    if notes:
        lines += ["", "=== RECENT ACTIONS ==="]
        for n in notes:
            lines.append(f"  Step {n['step']}: {n['action_taken']} -> {n['finding'][:100]}")

    last = obs.get("last_action_result")
    if last:
        lines += ["", f"=== LAST RESULT === {last[:200]}"]

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Parse LLM output -> Action
# ---------------------------------------------------------------------------

def parse_action(response_text: str, obs: dict) -> Action:
    text = response_text.strip()
    # Strip markdown fences
    text = re.sub(r"```[a-z]*", "", text).strip().rstrip("`").strip()
    # Try direct parse
    try:
        return Action(**json.loads(text))
    except Exception:
        pass
    # Find first JSON object
    match = re.search(r"\{[^{}]+\}", text, re.DOTALL)
    if match:
        try:
            return Action(**json.loads(match.group(0)))
        except Exception:
            pass
    # Fallback: enrich first alert
    active = obs.get("active_alerts", [])
    if active:
        return Action(action_type=ActionType.ENRICH_ALERT,
                      alert_id=active[0]["alert_id"], source="threat_intel")
    return Action(action_type=ActionType.CREATE_TICKET, priority="P3", summary="fallback")


def strict_score(value: float) -> float:
    """Clamp score to strict open interval expected by external validators."""
    return max(SCORE_EPS, min(1.0 - SCORE_EPS, float(value)))

# ---------------------------------------------------------------------------
# Run one task episode
# ---------------------------------------------------------------------------

def run_task(client: Optional[OpenAI], task_id: str) -> Dict[str, Any]:
    print(f"[START] task={task_id} seed={SEED} model={MODEL_NAME}", flush=True)

    env = SOCEnv(task_id=task_id, seed=SEED)
    obs = env.reset()
    obs_dict = obs.model_dump()

    total_reward = 0.0
    step_log: List[str] = []

    for step_num in range(1, SOCEnv.MAX_STEPS[task_id] + 1):
        user_prompt = observation_to_prompt(obs_dict, step_num)
        llm_error: Optional[str] = None
        used_fallback = False
        if client is None:
            used_fallback = True
            llm_error = "client_unavailable"
            response_text = ""
        else:
            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": user_prompt},
                    ],
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                )
                response_text = completion.choices[0].message.content or ""
            except Exception as exc:
                llm_error = str(exc)
                used_fallback = True
                response_text = ""

        action = parse_action(response_text, obs_dict)
        payload = {k: v for k, v in action.model_dump().items() if v is not None and k != "action_type"}

        try:
            obs, reward, done, info = env.step(action)
            obs_dict = obs.model_dump()
        except Exception as exc:
            llm_error = str(exc)
            used_fallback = True
            break

        total_reward += reward.total
        step_log.append(f"step={step_num} action={action.action_type.value} reward={reward.total:+.3f} info={reward.info}")
        print(
            "[STEP] "
            f"task={task_id} "
            f"step={step_num} "
            f"action={action.action_type.value} "
            f"payload={json.dumps(payload, separators=(',', ':'))} "
            f"reward={reward.total:+.3f} "
            f"cumulative={total_reward:+.3f} "
            f"fallback={str(used_fallback).lower()} "
            f"llm_error={json.dumps(llm_error) if llm_error is not None else 'null'} "
            f"done={str(done).lower()}",
            flush=True,
        )

        if done:
            break

    score = strict_score(env.grade())
    print(
        "[END] "
        f"task={task_id} "
        f"steps={step_num} "
        f"cumulative_reward={total_reward:+.4f} "
        f"score={score:.4f}",
        flush=True,
    )
    return {
        "task_id": task_id,
        "steps_taken": step_num,
        "cumulative_reward": round(total_reward, 4),
        "final_score": score,
        "step_log": step_log,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SOC OpenEnv baseline inference")
    parser.add_argument("--task", choices=SOCEnv.TASK_IDS + ["all"], default="all",
                        help="Which task to run (default: all)")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    client: Optional[OpenAI] = None
    if HF_TOKEN:
        client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    else:
        print("WARN: HF_TOKEN not set. Running with deterministic fallback actions.", flush=True)
    tasks  = SOCEnv.TASK_IDS if args.task == "all" else [args.task]
    results = []

    for task_id in tasks:
        results.append(run_task(client, task_id))

    for r in results:
        print(
            f"SUMMARY task={r['task_id']} score={r['final_score']:.4f} reward={r['cumulative_reward']:+.4f}",
            flush=True,
        )

    with open("baseline_results.json", "w") as f:
        json.dump(results, f, indent=2)

    all_ok = all(isinstance(r["final_score"], float) and 0.0 <= r["final_score"] <= 1.0 for r in results)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
