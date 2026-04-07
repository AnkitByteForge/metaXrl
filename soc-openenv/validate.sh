#!/usr/bin/env bash
# validate.sh — Pre-submission validator for SOC OpenEnv
# Run BEFORE submitting to catch all disqualifying issues.
#
# Usage:
#   chmod +x validate.sh
#   ./validate.sh                              # local checks only
#   ./validate.sh https://your-space.hf.space  # + HF Space ping

set -uo pipefail
PING_URL="${1:-}"
PASS=0; FAIL=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
pass() { echo -e "${GREEN}PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}FAIL${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}WARN${NC} $1"; }
hdr()  { echo -e "\n${BOLD}── $1 ──${NC}"; }

echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  SOC OpenEnv — Pre-submission Validator${NC}"
echo -e "${BOLD}========================================${NC}"

# 1. Required files
hdr "1. Required files"
for f in openenv.yaml Dockerfile requirements.txt inference.py server.py README.md pyproject.toml \
          soc_env/__init__.py soc_env/models.py soc_env/environment.py soc_env/graders.py \
          scenarios/__init__.py scenarios/easy_scenarios.py scenarios/medium_scenarios.py scenarios/hard_scenarios.py \
          tests/test_environment.py tests/test_graders.py validate.sh; do
  [ -f "$f" ] && pass "$f" || fail "MISSING: $f"
done

# 2. openenv.yaml structure
hdr "2. openenv.yaml"
grep -q "^name:"   openenv.yaml && pass "name field"    || fail "name field missing"
grep -q "^tasks:"  openenv.yaml && pass "tasks field"   || fail "tasks field missing"
TC=$(grep -c "^  - id:" openenv.yaml 2>/dev/null || echo 0)
[ "$TC" -ge 3 ] && pass "3+ tasks ($TC)" || fail "Need 3+ tasks, found $TC"
grep -q "POST /reset" openenv.yaml && pass "reset endpoint" || fail "reset endpoint missing"

# 3. Python syntax
hdr "3. Python syntax"
for f in server.py inference.py soc_env/models.py soc_env/environment.py soc_env/graders.py \
         scenarios/easy_scenarios.py scenarios/medium_scenarios.py scenarios/hard_scenarios.py; do
  python3 -m py_compile "$f" 2>/dev/null && pass "syntax OK: $f" || fail "syntax error: $f"
done

# 4. Environment contract
hdr "4. Environment contract (reset/step/state/grade)"
python3 - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from soc_env import SOCEnv, Action
from soc_env.models import ActionType, Observation, Reward, EnvState
errors = []
for task_id in SOCEnv.TASK_IDS:
    try:
        env = SOCEnv(task_id=task_id, seed=42)
        obs = env.reset()
        assert isinstance(obs, Observation)
        assert obs.step == 0
        action = Action(action_type=ActionType.ENRICH_ALERT,
                        alert_id=obs.active_alerts[0].alert_id if obs.active_alerts else None,
                        source="threat_intel")
        obs2, reward, done, info = env.step(action)
        assert isinstance(obs2, Observation)
        assert isinstance(reward, Reward)
        assert isinstance(done, bool)
        assert -1.0 <= reward.total <= 1.0
        s = env.state()
        assert isinstance(s, EnvState)
        score = env.grade()
        assert 0.0 <= score <= 1.0
        print(f"  OK {task_id}: reward={reward.total:+.3f} score={score:.3f}")
    except Exception as e:
        errors.append(f"  FAIL {task_id}: {e}")
for e in errors: print(e)
sys.exit(1 if errors else 0)
PYEOF
[ $? -eq 0 ] && pass "All 3 tasks: reset/step/state/grade" || fail "Environment contract failed"

# 5. Grader determinism
hdr "5. Grader determinism"
python3 - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from soc_env import SOCEnv, Action
from soc_env.models import ActionType
def run(task_id):
    env = SOCEnv(task_id=task_id, seed=42); env.reset()
    for _ in range(5):
        s = env.state()
        if s.done: break
        alerts = s.observation.active_alerts
        a = (Action(action_type=ActionType.ENRICH_ALERT, alert_id=alerts[0].alert_id, source="threat_intel")
             if alerts else Action(action_type=ActionType.CREATE_TICKET, priority="P2", summary="done"))
        _, _, done, _ = env.step(a)
        if done: break
    return env.grade()
errors = []
for t in SOCEnv.TASK_IDS:
    s1, s2 = run(t), run(t)
    if s1 == s2: print(f"  OK {t}: {s1:.4f}")
    else: errors.append(f"  FAIL {t}: {s1} != {s2}")
for e in errors: print(e)
sys.exit(1 if errors else 0)
PYEOF
[ $? -eq 0 ] && pass "Graders deterministic" || fail "Graders NOT deterministic"

# 6. Scores vary
hdr "6. Scores vary across agents"
python3 - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from soc_env import SOCEnv, Action
from soc_env.models import ActionType
def trivial(t):
    env = SOCEnv(task_id=t, seed=42); env.reset()
    env.step(Action(action_type=ActionType.CREATE_TICKET, priority="P3", summary="x")); return env.grade()
def active(t):
    env = SOCEnv(task_id=t, seed=42); env.reset()
    for _ in range(8):
        s = env.state()
        if s.done: break
        alerts = s.observation.active_alerts
        a = (Action(action_type=ActionType.ENRICH_ALERT, alert_id=alerts[0].alert_id, source="threat_intel")
             if alerts else Action(action_type=ActionType.CREATE_TICKET, priority="P1", summary="done"))
        _, _, done, _ = env.step(a); 
        if done: break
    return env.grade()
pairs = [(trivial(t), active(t)) for t in SOCEnv.TASK_IDS]
if all(a == b for a, b in pairs): print("  WARN: all scores identical"); sys.exit(1)
else: [print(f"  OK trivial={a:.3f} active={b:.3f}") for a, b in pairs]
sys.exit(0)
PYEOF
[ $? -eq 0 ] && pass "Scores vary" || fail "Scores don't vary — check graders"

# 7. inference.py requirements
hdr "7. inference.py spec compliance"
grep -q "API_BASE_URL" inference.py && pass "API_BASE_URL" || fail "API_BASE_URL missing"
grep -q "MODEL_NAME"   inference.py && pass "MODEL_NAME"   || fail "MODEL_NAME missing"
grep -q "HF_TOKEN"     inference.py && pass "HF_TOKEN"     || fail "HF_TOKEN missing"
grep -q "OpenAI"       inference.py && pass "OpenAI client" || fail "OpenAI client missing"

# 8. Dockerfile
hdr "8. Dockerfile"
grep -q "7860"        Dockerfile && pass "Port 7860"  || fail "Port 7860 not exposed"
grep -q "HEALTHCHECK" Dockerfile && pass "HEALTHCHECK" || warn "No HEALTHCHECK"
grep -q "^CMD"        Dockerfile && pass "CMD present" || fail "No CMD"
if command -v docker &>/dev/null; then
  echo "  Building Docker image (may take 1-2 min)..."
  docker build -t soc-openenv-validate . -q 2>/dev/null \
    && pass "docker build succeeded" \
    && docker rmi soc-openenv-validate -f &>/dev/null \
    || fail "docker build FAILED — run 'docker build .' for details"
else
  warn "Docker not installed — skipping build. Install before final submission."
fi

# 9. HF Space (optional)
hdr "9. HF Space ping"
if [ -z "$PING_URL" ]; then
  warn "Skipped — run: ./validate.sh https://your-space.hf.space"
else
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
         -d '{"task_id":"alert_triage"}' "$PING_URL/reset" --max-time 30 2>/dev/null || echo "000")
  [ "$CODE" = "200" ] && pass "HF Space /reset returned 200" || fail "HF Space returned $CODE (need 200)"
fi

# Summary
echo ""
echo -e "${BOLD}========================================${NC}"
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  ALL CHECKS PASSED ($PASS passed)${NC}"
  echo -e "${GREEN}${BOLD}  Ready to submit!${NC}"
else
  echo -e "${RED}${BOLD}  $FAIL FAILED, $PASS passed — fix before submitting${NC}"
fi
echo -e "${BOLD}========================================${NC}"
exit $FAIL
