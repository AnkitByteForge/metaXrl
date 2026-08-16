# Real-World Scenario Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert real Splunk "Boss of the SOC" (BOTS v1) log data into many varied, typed scenario episodes, exposed as a new 4th OpenEnv task (`real_world_incident`) with zero changes to the 3 existing tasks.

**Architecture:** An offline pipeline (`data_pipeline/`) parses raw JSON log lines into a common `RawEvent` shape, labels each against a small hand-curated IOC table, maps labeled events into existing `SIEMAlert`/`NetworkHost` pydantic models, and slices them into time-window episodes with a synthesized `AttackChain`. A one-time build script (`tools/build_real_world_scenarios.py`) writes these episodes to JSON files under `scenarios/data/real_world/`. A thin loader (`scenarios/real_world_scenarios.py`) reads a file per `seed` at game-time — no raw-data I/O during play.

**Tech Stack:** Python 3.10+, existing `soc_env` pydantic v2 models, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-16-real-world-scenario-pipeline-design.md`

## Global Constraints

- No changes to the 3 existing tasks' behavior, scores, or scenario files.
- Ground truth labeling is driven only by the curated IOC table (`data_pipeline/known_iocs.json`) — never inferred/detected. Do not add heuristic detection logic.
- Raw BOTS log files are never committed to the repo (gitignored) — only the small, already-converted `episode_*.json` files are committed.
- `reset()` / gameplay must never read the raw data directory — only the pre-built episode bank.
- Reuse existing pydantic models (`SIEMAlert`, `NetworkHost`, `AttackChain`, `Observation`) unchanged — do not add new fields to them.

---

## File Structure

```
data_pipeline/
  __init__.py
  parsers.py              # RawEvent + parse_suricata/parse_cloudtrail/parse_dns
  known_iocs.json          # curated ground-truth indicator table
  mapper.py                # labeling + RawEvent -> SIEMAlert/NetworkHost
  assembler.py              # time-window episode assembly + AttackChain synthesis
tools/
  build_real_world_scenarios.py   # one-time offline build script
scenarios/
  data/real_world/.gitkeep         # episode_*.json land here after a build run
  real_world_scenarios.py          # get_real_world_scenario(seed) loader
  __init__.py                      # +1 dispatch branch (modified)
soc_env/environment.py             # +1 task id, +1 grade() branch (modified)
openenv.yaml                       # +1 task entry (modified)
server/app.py                      # +1 TASK_METADATA entry (modified) [NOTE: this is root_server.py — see Task 6]
tests/
  fixtures/bots_samples/suricata_sample.jsonl
  fixtures/bots_samples/cloudtrail_sample.jsonl
  fixtures/bots_samples/dns_sample.jsonl
  fixtures/bots_samples/episode_0000.json
  test_data_pipeline_parsers.py
  test_data_pipeline_mapper.py
  test_data_pipeline_assembler.py
  test_build_real_world_scenarios.py
  test_real_world_scenarios.py
README.md                          # +1 section: downloading BOTS + running the build (modified)
.gitignore                         # +data_pipeline/raw/ (modified)
```

---

### Task 1: Parsers — RawEvent shape + 3 log-format parsers

**Files:**
- Create: `data_pipeline/__init__.py` (empty)
- Create: `data_pipeline/parsers.py`
- Create: `tests/fixtures/bots_samples/suricata_sample.jsonl`
- Create: `tests/fixtures/bots_samples/cloudtrail_sample.jsonl`
- Create: `tests/fixtures/bots_samples/dns_sample.jsonl`
- Test: `tests/test_data_pipeline_parsers.py`

**Interfaces:**
- Produces: `RawEvent` dataclass with fields `timestamp: str, host: str, user: Optional[str], event_type: str, indicators: List[Tuple[str, str]], raw_line: str`. Functions `parse_suricata(line: str) -> Optional[RawEvent]`, `parse_cloudtrail(line: str) -> Optional[RawEvent]`, `parse_dns(line: str) -> Optional[RawEvent]` — each returns `None` on malformed/unparseable input.

- [ ] **Step 1: Create the fixture files**

`tests/fixtures/bots_samples/suricata_sample.jsonl`:
```
{"timestamp":"2024-03-15T08:14:00.000000+0000","event_type":"alert","src_ip":"203.0.113.42","dest_ip":"10.0.2.10","alert":{"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak"},"dest_port":22,"proto":"TCP"}
{"timestamp":"2024-03-15T08:20:00.000000+0000","event_type":"alert","src_ip":"10.0.1.5","dest_ip":"8.8.8.8","alert":{"signature":"DNS Query Observed","category":"Not Suspicious"},"dest_port":53,"proto":"UDP"}
not valid json at all
```

`tests/fixtures/bots_samples/cloudtrail_sample.jsonl`:
```
{"eventTime":"2024-03-15T09:28:00Z","eventName":"ConsoleLogin","userIdentity":{"userName":"svc_finance"},"sourceIPAddress":"198.51.100.77"}
{"eventTime":"2024-03-15T09:30:00Z","eventName":"DescribeInstances","userIdentity":{"userName":"alee"},"sourceIPAddress":"10.0.1.20"}
{"eventTime": "missing eventName field"}
```

`tests/fixtures/bots_samples/dns_sample.jsonl`:
```
{"_time":"2024-03-15T09:47:00Z","src":"10.0.1.11","query":"file-share-quick.net","query_type":"A","answer":"198.51.100.77"}
{"_time":"2024-03-15T09:48:00Z","src":"10.0.1.12","query":"microsoft.com","query_type":"A","answer":"20.1.2.3"}
{}
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_data_pipeline_parsers.py
from pathlib import Path
from data_pipeline.parsers import parse_suricata, parse_cloudtrail, parse_dns, RawEvent

FIXTURES = Path(__file__).parent / "fixtures" / "bots_samples"


def _lines(name):
    return (FIXTURES / name).read_text().splitlines()


def test_parse_suricata_valid_line():
    event = parse_suricata(_lines("suricata_sample.jsonl")[0])
    assert isinstance(event, RawEvent)
    assert event.host == "10.0.2.10"
    assert event.event_type == "ET SCAN Potential SSH Scan"
    assert ("ip", "203.0.113.42") in event.indicators
    assert ("ip", "10.0.2.10") in event.indicators


def test_parse_suricata_malformed_line_returns_none():
    assert parse_suricata(_lines("suricata_sample.jsonl")[2]) is None


def test_parse_cloudtrail_valid_line():
    event = parse_cloudtrail(_lines("cloudtrail_sample.jsonl")[0])
    assert event.host == "198.51.100.77"
    assert event.user == "svc_finance"
    assert event.event_type == "ConsoleLogin"
    assert ("user", "svc_finance") in event.indicators
    assert ("ip", "198.51.100.77") in event.indicators


def test_parse_cloudtrail_malformed_line_returns_none():
    assert parse_cloudtrail(_lines("cloudtrail_sample.jsonl")[2]) is None


def test_parse_dns_valid_line():
    event = parse_dns(_lines("dns_sample.jsonl")[0])
    assert event.host == "10.0.1.11"
    assert event.event_type == "dns_query"
    assert ("domain", "file-share-quick.net") in event.indicators
    assert ("ip", "198.51.100.77") in event.indicators


def test_parse_dns_malformed_line_returns_none():
    assert parse_dns(_lines("dns_sample.jsonl")[2]) is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_data_pipeline_parsers.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'data_pipeline'`

- [ ] **Step 4: Implement `data_pipeline/parsers.py`**

```python
"""Parsers converting raw BOTS-style JSON log lines into a common RawEvent shape."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class RawEvent:
    timestamp: str
    host: str
    user: Optional[str]
    event_type: str
    indicators: List[Tuple[str, str]]
    raw_line: str


def parse_suricata(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        signature = d["alert"]["signature"]
        dest_ip = d["dest_ip"]
        src_ip = d["src_ip"]
        return RawEvent(
            timestamp=d["timestamp"],
            host=dest_ip,
            user=None,
            event_type=signature,
            indicators=[("ip", src_ip), ("ip", dest_ip)],
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def parse_cloudtrail(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        event_name = d["eventName"]
        source_ip = d["sourceIPAddress"]
        user_name = d["userIdentity"]["userName"]
        return RawEvent(
            timestamp=d["eventTime"],
            host=source_ip,
            user=user_name,
            event_type=event_name,
            indicators=[("user", user_name), ("ip", source_ip)],
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def parse_dns(line: str) -> Optional[RawEvent]:
    try:
        d = json.loads(line)
        src = d["src"]
        query = d["query"]
        answer = d.get("answer")
        indicators: List[Tuple[str, str]] = [("domain", query)]
        if answer:
            indicators.append(("ip", answer))
        return RawEvent(
            timestamp=d["_time"],
            host=src,
            user=None,
            event_type="dns_query",
            indicators=indicators,
            raw_line=line,
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
```

Also create `data_pipeline/__init__.py` (empty file).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_data_pipeline_parsers.py -v`
Expected: PASS (7 tests)

- [ ] **Step 6: Commit**

```bash
git add data_pipeline/__init__.py data_pipeline/parsers.py tests/fixtures/bots_samples/ tests/test_data_pipeline_parsers.py
git commit -m "Add BOTS log parsers (Suricata, CloudTrail, DNS) with RawEvent shape"
```

---

### Task 2: Curated IOC table + labeling/schema mapper

**Files:**
- Create: `data_pipeline/known_iocs.json`
- Create: `data_pipeline/mapper.py`
- Test: `tests/test_data_pipeline_mapper.py`

**Interfaces:**
- Consumes: `RawEvent` from Task 1 (`data_pipeline.parsers.RawEvent`).
- Produces: `load_ioc_table(path) -> Dict[str, set]`, `is_malicious(event: RawEvent, ioc_table: Dict[str, set]) -> bool`, `to_siem_alert(event: RawEvent, index: int, ioc_table: Dict[str, set]) -> SIEMAlert`, `to_network_host(host_id: str, compromised: bool = False) -> NetworkHost`. Both consumed directly by `data_pipeline.assembler` (Task 3).

- [ ] **Step 1: Create `data_pipeline/known_iocs.json`**

```json
{
  "ip": ["203.0.113.42", "198.51.100.77"],
  "hash": ["a3f4b2c1d9e8f7a6b5c4d3e2f1a0b9c8"],
  "domain": ["file-share-quick.net"],
  "user": ["svc_finance"]
}
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_data_pipeline_mapper.py
from data_pipeline.parsers import RawEvent
from data_pipeline.mapper import load_ioc_table, is_malicious, to_siem_alert, to_network_host
from soc_env.models import AlertSeverity, HostStatus, MITRETactic

IOC_PATH = "data_pipeline/known_iocs.json"


def test_load_ioc_table_returns_sets():
    table = load_ioc_table(IOC_PATH)
    assert "203.0.113.42" in table["ip"]
    assert "svc_finance" in table["user"]


def test_is_malicious_true_when_indicator_matches():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("t", "h", None, "et", [("ip", "203.0.113.42")], "raw")
    assert is_malicious(event, table) is True


def test_is_malicious_false_when_no_match():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("t", "h", None, "et", [("ip", "1.2.3.4")], "raw")
    assert is_malicious(event, table) is False


def test_to_siem_alert_malicious_event():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent(
        "2024-03-15T08:14:00Z", "10.0.2.10", None,
        "ET SCAN Potential SSH Scan", [("ip", "203.0.113.42")], "raw-line",
    )
    alert = to_siem_alert(event, 0, table)
    assert alert.alert_id == "ALT-RW-0000"
    assert alert.ground_truth is True
    assert alert.severity == AlertSeverity.HIGH
    assert alert.host_id == "HOST-10-0-2-10"
    assert alert.mitre_tactic == MITRETactic.DISCOVERY
    assert alert.raw_log == "raw-line"


def test_to_siem_alert_benign_event():
    table = load_ioc_table(IOC_PATH)
    event = RawEvent("2024-03-15T08:20:00Z", "10.0.1.5", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw")
    alert = to_siem_alert(event, 1, table)
    assert alert.ground_truth is False
    assert alert.severity == AlertSeverity.LOW
    assert alert.mitre_tactic is None


def test_to_network_host_compromised_is_suspicious():
    host = to_network_host("HOST-10-0-2-10", compromised=True)
    assert host.status == HostStatus.SUSPICIOUS
    assert host.host_id == "HOST-10-0-2-10"


def test_to_network_host_clean_by_default():
    host = to_network_host("HOST-10-0-1-5")
    assert host.status == HostStatus.CLEAN
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_data_pipeline_mapper.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'data_pipeline.mapper'`

- [ ] **Step 4: Implement `data_pipeline/mapper.py`**

```python
"""Ground-truth labeling and RawEvent -> SIEMAlert/NetworkHost schema mapping."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Set

from soc_env.models import (
    AlertSeverity, HostStatus, MITRETactic, NetworkHost, SIEMAlert, ThreatIndicator,
)
from .parsers import RawEvent


def load_ioc_table(path: str | Path) -> Dict[str, Set[str]]:
    with open(path) as f:
        raw = json.load(f)
    return {k: set(v) for k, v in raw.items()}


def is_malicious(event: RawEvent, ioc_table: Dict[str, Set[str]]) -> bool:
    for kind, value in event.indicators:
        if value in ioc_table.get(kind, set()):
            return True
    return False


def _host_id(raw_host: str) -> str:
    return "HOST-" + raw_host.replace(".", "-")


def _tactic_for(event: RawEvent, malicious: bool):
    if not malicious:
        return None
    et = event.event_type.lower()
    if "scan" in et:
        return MITRETactic.DISCOVERY
    if "login" in et:
        return MITRETactic.CREDENTIAL_ACCESS
    if event.event_type == "dns_query":
        return MITRETactic.EXFILTRATION
    return None


def to_siem_alert(event: RawEvent, index: int, ioc_table: Dict[str, Set[str]]) -> SIEMAlert:
    malicious = is_malicious(event, ioc_table)
    return SIEMAlert(
        alert_id=f"ALT-RW-{index:04d}",
        timestamp=event.timestamp,
        severity=AlertSeverity.HIGH if malicious else AlertSeverity.LOW,
        rule_name=event.event_type,
        description=f"Auto-converted from real log data: {event.event_type}",
        host_id=_host_id(event.host),
        user_id=event.user,
        mitre_tactic=_tactic_for(event, malicious),
        indicators=[
            ThreatIndicator(type=kind, value=value, reputation="malicious" if malicious else "unknown")
            for kind, value in event.indicators
            if kind in ("ip", "hash", "domain", "user")
        ],
        raw_log=event.raw_line,
        ground_truth=malicious,
    )


def to_network_host(host_id: str, compromised: bool = False) -> NetworkHost:
    ip = host_id.replace("HOST-", "").replace("-", ".")
    return NetworkHost(
        host_id=host_id,
        hostname=host_id.lower(),
        ip_address=ip,
        subnet="0.0.0.0/0",
        os="unknown",
        role="unknown",
        is_critical=False,
        status=HostStatus.SUSPICIOUS if compromised else HostStatus.CLEAN,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_data_pipeline_mapper.py -v`
Expected: PASS (7 tests)

- [ ] **Step 6: Commit**

```bash
git add data_pipeline/known_iocs.json data_pipeline/mapper.py tests/test_data_pipeline_mapper.py
git commit -m "Add curated IOC table and RawEvent-to-SIEMAlert schema mapper"
```

---

### Task 3: Assembler — time-window episodes + AttackChain synthesis

**Files:**
- Create: `data_pipeline/assembler.py`
- Test: `tests/test_data_pipeline_assembler.py`

**Interfaces:**
- Consumes: `RawEvent` (Task 1), `is_malicious`/`to_siem_alert`/`to_network_host`/`load_ioc_table` (Task 2).
- Produces: `assemble_episodes(events: List[RawEvent], ioc_table: Dict[str, set], window_minutes: int = 45) -> List[Dict[str, Any]]`. Each returned dict has keys `"alerts"`, `"hosts"`, `"attack_chain"` (all JSON-serializable via `model_dump(mode="json")`), consumed by `tools/build_real_world_scenarios.py` (Task 4).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_data_pipeline_assembler.py
from data_pipeline.parsers import RawEvent
from data_pipeline.mapper import load_ioc_table
from data_pipeline.assembler import assemble_episodes

IOC_PATH = "data_pipeline/known_iocs.json"


def _events():
    return [
        RawEvent("2024-03-15T08:00:00Z", "10.0.2.10", None, "ET SCAN Potential SSH Scan", [("ip", "203.0.113.42")], "raw1"),
        RawEvent("2024-03-15T08:05:00Z", "10.0.1.5", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw2"),
        RawEvent("2024-03-15T08:10:00Z", "10.0.3.20", None, "ConsoleLogin", [("user", "svc_finance")], "raw3"),
        # far outside the first window -> separate episode
        RawEvent("2024-03-15T11:00:00Z", "10.0.4.1", None, "ET SCAN Potential SSH Scan", [("ip", "198.51.100.77")], "raw4"),
        RawEvent("2024-03-15T11:02:00Z", "10.0.4.2", None, "DNS Query Observed", [("ip", "1.1.1.1")], "raw5"),
    ]


def test_assemble_episodes_groups_by_window():
    table = load_ioc_table(IOC_PATH)
    episodes = assemble_episodes(_events(), table, window_minutes=45)
    assert len(episodes) == 2


def test_episode_has_alerts_hosts_and_attack_chain():
    table = load_ioc_table(IOC_PATH)
    episodes = assemble_episodes(_events(), table, window_minutes=45)
    ep = episodes[0]
    assert len(ep["alerts"]) == 3
    assert len(ep["hosts"]) == 3
    assert ep["attack_chain"]["patient_zero_host"] == "HOST-10-0-2-10"
    assert "HOST-10-0-3-20" in ep["attack_chain"]["lateral_movement_targets"]


def test_episode_dropped_if_all_malicious_or_all_benign():
    table = load_ioc_table(IOC_PATH)
    all_benign = [
        RawEvent("2024-03-15T08:00:00Z", "10.0.1.1", None, "DNS Query Observed", [("ip", "8.8.8.8")], "raw1"),
        RawEvent("2024-03-15T08:01:00Z", "10.0.1.2", None, "DNS Query Observed", [("ip", "1.1.1.1")], "raw2"),
    ]
    episodes = assemble_episodes(all_benign, table, window_minutes=45)
    assert episodes == []


def test_assemble_episodes_empty_input_returns_empty_list():
    table = load_ioc_table(IOC_PATH)
    assert assemble_episodes([], table) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_data_pipeline_assembler.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'data_pipeline.assembler'`

- [ ] **Step 3: Implement `data_pipeline/assembler.py`**

```python
"""Groups labeled RawEvents into time-window episodes with a synthesized AttackChain."""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from .mapper import to_network_host, to_siem_alert
from .parsers import RawEvent


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def assemble_episodes(
    events: List[RawEvent], ioc_table: Dict[str, Set[str]], window_minutes: int = 45
) -> List[Dict[str, Any]]:
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: _parse_ts(e.timestamp))
    episodes: List[Dict[str, Any]] = []
    bucket: List[RawEvent] = []
    window_end = _parse_ts(sorted_events[0].timestamp) + timedelta(minutes=window_minutes)

    for event in sorted_events:
        ts = _parse_ts(event.timestamp)
        if ts > window_end:
            episode = _build_episode(bucket, ioc_table)
            if episode:
                episodes.append(episode)
            bucket = []
            window_end = ts + timedelta(minutes=window_minutes)
        bucket.append(event)

    episode = _build_episode(bucket, ioc_table)
    if episode:
        episodes.append(episode)
    return episodes


def _build_episode(bucket: List[RawEvent], ioc_table: Dict[str, Set[str]]) -> Optional[Dict[str, Any]]:
    if not bucket:
        return None

    alerts = [to_siem_alert(e, i, ioc_table) for i, e in enumerate(bucket)]
    malicious_alerts = [a for a in alerts if a.ground_truth]
    benign_alerts = [a for a in alerts if not a.ground_truth]
    if not malicious_alerts or not benign_alerts:
        return None

    host_ids = sorted({a.host_id for a in alerts})
    malicious_hosts = sorted({a.host_id for a in malicious_alerts})
    hosts = [to_network_host(h, compromised=h in malicious_hosts) for h in host_ids]

    patient_zero = malicious_hosts[0]
    lateral_targets = malicious_hosts[1:]
    crown_jewel = host_ids[-1]
    stages = sorted({a.mitre_tactic.value for a in malicious_alerts if a.mitre_tactic})

    return {
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "hosts": [h.model_dump(mode="json") for h in hosts],
        "attack_chain": {
            "patient_zero_host": patient_zero,
            "stages": stages,
            "lateral_movement_targets": lateral_targets,
            "crown_jewel_host": crown_jewel,
            "exfiltration_complete": False,
            "attacker_dwell_minutes": 45,
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_data_pipeline_assembler.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add data_pipeline/assembler.py tests/test_data_pipeline_assembler.py
git commit -m "Add episode assembler with AttackChain synthesis"
```

---

### Task 4: Build script — orchestrates the offline pipeline

**Files:**
- Create: `tools/build_real_world_scenarios.py`
- Create: `scenarios/data/real_world/.gitkeep`
- Modify: `.gitignore` — add `data_pipeline/raw/`
- Test: `tests/test_build_real_world_scenarios.py`

**Interfaces:**
- Consumes: `parse_suricata`/`parse_cloudtrail`/`parse_dns` (Task 1), `load_ioc_table` (Task 2), `assemble_episodes` (Task 3).
- Produces: `main() -> int` (exit code), writes `episode_XXXX.json` files to `scenarios/data/real_world/`, consumed at load-time by `scenarios/real_world_scenarios.py` (Task 5).

- [ ] **Step 1: Add `.gitignore` entry**

Modify `.gitignore`, append:
```
data_pipeline/raw/
```

- [ ] **Step 2: Create `scenarios/data/real_world/.gitkeep`** (empty file, so the directory exists in git before any build has run)

- [ ] **Step 3: Write the failing test**

```python
# tests/test_build_real_world_scenarios.py
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "bots_samples"


def _run_build(raw_dir: Path, out_dir: Path) -> subprocess.CompletedProcess:
    env = {
        "BOTS_RAW_DIR": str(raw_dir),
        "BOTS_OUT_DIR": str(out_dir),
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "build_real_world_scenarios.py")],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )


def test_build_fails_cleanly_when_raw_dir_missing(tmp_path):
    missing_dir = tmp_path / "does_not_exist"
    out_dir = tmp_path / "out"
    result = _run_build(missing_dir, out_dir)
    assert result.returncode == 1
    assert "missing or empty" in result.stdout


def test_build_writes_episode_files(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "suricata_eve.json").write_text((FIXTURES / "suricata_sample.jsonl").read_text())
    (raw_dir / "cloudtrail.json").write_text((FIXTURES / "cloudtrail_sample.jsonl").read_text())
    (raw_dir / "dns_stream.json").write_text((FIXTURES / "dns_sample.jsonl").read_text())
    out_dir = tmp_path / "out"

    result = _run_build(raw_dir, out_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    written = sorted(out_dir.glob("episode_*.json"))
    assert len(written) >= 1
    episode = json.loads(written[0].read_text())
    assert "alerts" in episode and "hosts" in episode and "attack_chain" in episode
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest tests/test_build_real_world_scenarios.py -v`
Expected: FAIL — `tools/build_real_world_scenarios.py` does not exist

- [ ] **Step 5: Implement `tools/build_real_world_scenarios.py`**

```python
#!/usr/bin/env python3
"""One-time offline build script: raw BOTS logs -> scenarios/data/real_world/*.json

Usage:
    python tools/build_real_world_scenarios.py

Env vars:
    BOTS_RAW_DIR  Directory containing suricata_eve.json / cloudtrail.json / dns_stream.json
                  (default: data_pipeline/raw)
    BOTS_OUT_DIR  Directory to write episode_*.json files to
                  (default: scenarios/data/real_world)
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from data_pipeline.assembler import assemble_episodes
from data_pipeline.mapper import load_ioc_table
from data_pipeline.parsers import parse_cloudtrail, parse_dns, parse_suricata

RAW_DIR = Path(os.environ.get("BOTS_RAW_DIR", REPO_ROOT / "data_pipeline" / "raw"))
OUT_DIR = Path(os.environ.get("BOTS_OUT_DIR", REPO_ROOT / "scenarios" / "data" / "real_world"))
IOC_PATH = REPO_ROOT / "data_pipeline" / "known_iocs.json"

SOURCES = [
    ("suricata_eve.json", parse_suricata),
    ("cloudtrail.json", parse_cloudtrail),
    ("dns_stream.json", parse_dns),
]


def main() -> int:
    if not RAW_DIR.exists() or not any(RAW_DIR.iterdir()):
        print(f"ERROR: raw data directory {RAW_DIR} is missing or empty.")
        print("Download BOTS v1 and place its log files there before running this script.")
        return 1

    ioc_table = load_ioc_table(IOC_PATH)
    events = []
    skipped = 0
    for filename, parser in SOURCES:
        path = RAW_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parser(line)
                if event is None:
                    skipped += 1
                else:
                    events.append(event)

    print(f"Parsed {len(events)} events, skipped {skipped} malformed lines.")

    episodes = assemble_episodes(events, ioc_table)
    if not episodes:
        print("ERROR: no valid episodes assembled (need windows with both real threats and noise).")
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("episode_*.json"):
        old.unlink()
    for i, episode in enumerate(episodes):
        with open(OUT_DIR / f"episode_{i:04d}.json", "w") as f:
            json.dump(episode, f, indent=2)

    print(f"Wrote {len(episodes)} episodes to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_build_real_world_scenarios.py -v`
Expected: PASS (2 tests)

- [ ] **Step 7: Commit**

```bash
git add tools/build_real_world_scenarios.py scenarios/data/real_world/.gitkeep .gitignore tests/test_build_real_world_scenarios.py
git commit -m "Add offline build script orchestrating the real-world scenario pipeline"
```

---

### Task 5: Scenario loader — `get_real_world_scenario(seed)`

**Files:**
- Create: `scenarios/real_world_scenarios.py`
- Create: `tests/fixtures/bots_samples/episode_0000.json`
- Test: `tests/test_real_world_scenarios.py`

**Interfaces:**
- Produces: `get_real_world_scenario(seed: int = 42) -> Dict[str, Any]` returning `{"observation": Observation, "attack_chain": AttackChain}` — same return shape as `get_easy_scenario`/`get_medium_scenario`/`get_hard_scenario`, consumed by `scenarios/__init__.py` (Task 6).

- [ ] **Step 1: Create a fixture episode file for the loader test**

`tests/fixtures/bots_samples/episode_0000.json`:
```json
{
  "alerts": [
    {
      "alert_id": "ALT-RW-0000",
      "timestamp": "2024-03-15T08:00:00Z",
      "severity": "high",
      "rule_name": "ET SCAN Potential SSH Scan",
      "description": "Auto-converted from real log data: ET SCAN Potential SSH Scan",
      "host_id": "HOST-10-0-2-10",
      "user_id": null,
      "mitre_tactic": "discovery",
      "mitre_technique": null,
      "indicators": [{"type": "ip", "value": "203.0.113.42", "reputation": "malicious", "context": null}],
      "raw_log": "raw1",
      "status": "pending",
      "enrichment": null,
      "ground_truth": true
    },
    {
      "alert_id": "ALT-RW-0001",
      "timestamp": "2024-03-15T08:05:00Z",
      "severity": "low",
      "rule_name": "DNS Query Observed",
      "description": "Auto-converted from real log data: DNS Query Observed",
      "host_id": "HOST-10-0-1-5",
      "user_id": null,
      "mitre_tactic": null,
      "mitre_technique": null,
      "indicators": [{"type": "ip", "value": "8.8.8.8", "reputation": "unknown", "context": null}],
      "raw_log": "raw2",
      "status": "pending",
      "enrichment": null,
      "ground_truth": false
    }
  ],
  "hosts": [
    {"host_id": "HOST-10-0-2-10", "hostname": "host-10-0-2-10", "ip_address": "10.0.2.10", "subnet": "0.0.0.0/0", "os": "unknown", "role": "unknown", "owner": null, "is_critical": false, "is_vip": false, "status": "suspicious", "active_sessions": [], "running_processes": []},
    {"host_id": "HOST-10-0-1-5", "hostname": "host-10-0-1-5", "ip_address": "10.0.1.5", "subnet": "0.0.0.0/0", "os": "unknown", "role": "unknown", "owner": null, "is_critical": false, "is_vip": false, "status": "clean", "active_sessions": [], "running_processes": []}
  ],
  "attack_chain": {
    "patient_zero_host": "HOST-10-0-2-10",
    "stages": ["discovery"],
    "lateral_movement_targets": [],
    "crown_jewel_host": "HOST-10-0-2-10",
    "exfiltration_complete": false,
    "attacker_dwell_minutes": 45
  }
}
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_real_world_scenarios.py
import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "bots_samples" / "episode_0000.json"
DATA_DIR = Path(__file__).resolve().parents[1] / "scenarios" / "data" / "real_world"


@pytest.fixture
def with_one_episode():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = list(DATA_DIR.glob("episode_*.json"))
    dest = DATA_DIR / "episode_0000.json"
    shutil.copy(FIXTURE, dest)
    yield
    dest.unlink(missing_ok=True)


def test_get_real_world_scenario_returns_observation_and_chain(with_one_episode):
    from scenarios.real_world_scenarios import get_real_world_scenario
    result = get_real_world_scenario(seed=0)
    assert result["observation"].task_id == "real_world_incident"
    assert len(result["observation"].active_alerts) == 2
    assert result["attack_chain"].patient_zero_host == "HOST-10-0-2-10"


def test_get_real_world_scenario_raises_if_no_episodes(tmp_path, monkeypatch):
    import scenarios.real_world_scenarios as mod
    monkeypatch.setattr(mod, "_DATA_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="build_real_world_scenarios"):
        mod.get_real_world_scenario(seed=0)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_real_world_scenarios.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scenarios.real_world_scenarios'`

- [ ] **Step 4: Implement `scenarios/real_world_scenarios.py`**

```python
"""Real-world scenario loader — reads pre-built episodes derived from Splunk BOTS logs."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

from soc_env.models import AttackChain, NetworkHost, Observation, SIEMAlert

_DATA_DIR = Path(__file__).resolve().parent / "data" / "real_world"


def _load_episode(seed: int) -> Dict[str, Any]:
    files = sorted(_DATA_DIR.glob("episode_*.json"))
    if not files:
        raise RuntimeError(
            "No real-world episodes found. Run tools/build_real_world_scenarios.py first."
        )
    path = files[seed % len(files)]
    with open(path) as f:
        return json.load(f)


def get_real_world_scenario(seed: int = 42) -> Dict[str, Any]:
    episode = _load_episode(seed)
    alerts = [SIEMAlert(**a) for a in episode["alerts"]]
    hosts = [NetworkHost(**h) for h in episode["hosts"]]
    chain = AttackChain(**episode["attack_chain"])

    obs = Observation(
        step=0,
        task_id="real_world_incident",
        task_description=(
            "ACTIVE INCIDENT — alerts derived from real security log data. "
            "Correlate alerts across hosts, identify the attack chain, and "
            "contain the threat before it reaches the crown jewel host."
        ),
        active_alerts=alerts,
        hosts=hosts,
        business_constraints=[],
        elapsed_minutes=0,
        max_minutes=120,
        steps_remaining=25,
    )
    return {"observation": obs, "attack_chain": chain}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_real_world_scenarios.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add scenarios/real_world_scenarios.py tests/fixtures/bots_samples/episode_0000.json tests/test_real_world_scenarios.py
git commit -m "Add real_world_incident scenario loader"
```

---

### Task 6: Wire the 4th task into the environment, config, and server

**Files:**
- Modify: `scenarios/__init__.py`
- Modify: `soc_env/environment.py`
- Modify: `openenv.yaml`
- Modify: `root_server.py` (the file `server/app.py` loads — has `TASK_METADATA`)
- Test: `tests/test_environment.py` (existing parametrized tests already cover new task ids automatically via `SOCEnv.TASK_IDS`)

**Interfaces:**
- Consumes: `get_real_world_scenario` (Task 5).
- Produces: `SOCEnv.TASK_IDS` includes `"real_world_incident"`; `SOCEnv(task_id="real_world_incident").grade()` returns a float via `grade_task_medium`.

- [ ] **Step 1: Modify `scenarios/__init__.py`**

Read the file first (it uses tab indentation — match it exactly). New full content:

```python
"""Scenario loader dispatcher for SOC OpenEnv tasks."""
from __future__ import annotations

from typing import Any, Dict

from .easy_scenarios import get_easy_scenario
from .medium_scenarios import get_medium_scenario
from .hard_scenarios import get_hard_scenario
from .real_world_scenarios import get_real_world_scenario


def load_scenario(task_id: str, seed: int = 42) -> Dict[str, Any]:
	"""Return the scenario payload for a given task id."""
	if task_id == "alert_triage":
		return get_easy_scenario(seed=seed)
	if task_id == "attack_chain_reconstruction":
		return get_medium_scenario(seed=seed)
	if task_id == "constrained_incident_response":
		return get_hard_scenario(seed=seed)
	if task_id == "real_world_incident":
		return get_real_world_scenario(seed=seed)
	raise ValueError(f"Unknown task_id: {task_id}")


__all__ = ["load_scenario"]
```

(Keep the tab characters before `if`/`return` lines — match the file's existing indentation style exactly.)

- [ ] **Step 2: Modify `soc_env/environment.py`**

In the `TASK_IDS`, `MAX_STEPS`, `MAX_MINUTES`, `MINUTES_PER_STEP` class attributes near the top of `SOCEnv`, change:

```python
    TASK_IDS = [
        "alert_triage",
        "attack_chain_reconstruction",
        "constrained_incident_response",
    ]
    MAX_STEPS = {
        "alert_triage": 10,
        "attack_chain_reconstruction": 25,
        "constrained_incident_response": 40,
    }
    MAX_MINUTES = {
        "alert_triage": 30,
        "attack_chain_reconstruction": 120,
        "constrained_incident_response": 240,
    }
    MINUTES_PER_STEP = {
        "alert_triage": 3,
        "attack_chain_reconstruction": 5,
        "constrained_incident_response": 6,
    }
```

to:

```python
    TASK_IDS = [
        "alert_triage",
        "attack_chain_reconstruction",
        "constrained_incident_response",
        "real_world_incident",
    ]
    MAX_STEPS = {
        "alert_triage": 10,
        "attack_chain_reconstruction": 25,
        "constrained_incident_response": 40,
        "real_world_incident": 25,
    }
    MAX_MINUTES = {
        "alert_triage": 30,
        "attack_chain_reconstruction": 120,
        "constrained_incident_response": 240,
        "real_world_incident": 120,
    }
    MINUTES_PER_STEP = {
        "alert_triage": 3,
        "attack_chain_reconstruction": 5,
        "constrained_incident_response": 6,
        "real_world_incident": 5,
    }
```

And in the `grade()` method, change:

```python
        if self.task_id == "alert_triage":
            return grade_task_easy(s)
        elif self.task_id == "attack_chain_reconstruction":
            return grade_task_medium(s)
        else:
            return grade_task_hard(s)
```

to:

```python
        if self.task_id == "alert_triage":
            return grade_task_easy(s)
        elif self.task_id in ("attack_chain_reconstruction", "real_world_incident"):
            return grade_task_medium(s)
        else:
            return grade_task_hard(s)
```

- [ ] **Step 3: Modify `openenv.yaml`**

Add a new entry under `tasks:`, after `constrained_incident_response`:

```yaml
  - id: real_world_incident
    name: "Real-world incident (data-driven)"
    description: >
      Alerts derived from real security log data (Splunk Boss of the SOC
      dataset), auto-labeled against a curated indicator table. Correlate
      alerts across hosts and contain the threat, same as the attack-chain
      task but backed by real data instead of a fixed hand-written scenario.
    difficulty: medium
    max_steps: 25
    score_range: [0.0, 1.0]
```

- [ ] **Step 4: Modify `root_server.py`**

In `TASK_METADATA`, add an entry after the `constrained_incident_response` dict:

```python
    {
        "id": "real_world_incident",
        "difficulty": "medium",
        "max_steps": 25,
        "name": "Real-world incident",
        "description": "Same attack-chain task, backed by real log data converted from the Splunk BOTS dataset instead of a fixed scenario.",
    },
```

- [ ] **Step 5: Ensure at least one episode exists for tests, then run the full suite**

The parametrized tests in `tests/test_environment.py` and `tests/test_graders.py` iterate `SOCEnv.TASK_IDS`, so they now include `"real_world_incident"` automatically — this requires `scenarios/data/real_world/` to contain at least one real episode file when the suite runs. Generate one from the test fixtures for local/CI use:

```bash
BOTS_RAW_DIR=tests/fixtures/bots_raw_for_ci BOTS_OUT_DIR=scenarios/data/real_world python tools/build_real_world_scenarios.py
```

First create `tests/fixtures/bots_raw_for_ci/` with copies of the three sample files (reuse Task 1's fixtures, renamed to match the source filenames the build script expects):

```bash
mkdir -p tests/fixtures/bots_raw_for_ci
cp tests/fixtures/bots_samples/suricata_sample.jsonl tests/fixtures/bots_raw_for_ci/suricata_eve.json
cp tests/fixtures/bots_samples/cloudtrail_sample.jsonl tests/fixtures/bots_raw_for_ci/cloudtrail.json
cp tests/fixtures/bots_samples/dns_sample.jsonl tests/fixtures/bots_raw_for_ci/dns_stream.json
python tools/build_real_world_scenarios.py  # uses default BOTS_RAW_DIR, so instead run:
BOTS_RAW_DIR=tests/fixtures/bots_raw_for_ci python tools/build_real_world_scenarios.py
```

Run: `pytest tests -v`
Expected: PASS — all existing tests (now parametrized over 4 task ids) plus the new pipeline tests.

- [ ] **Step 6: Commit**

```bash
git add scenarios/__init__.py soc_env/environment.py openenv.yaml root_server.py tests/fixtures/bots_raw_for_ci scenarios/data/real_world/episode_0000.json
git commit -m "Wire real_world_incident up as the 4th OpenEnv task"
```

---

### Task 7: Documentation — how to get real BOTS data and rebuild

**Files:**
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Add a new section to `README.md`**, after the existing "## Tasks" section:

```markdown
## Real-World Task Data (`real_world_incident`)

The 4th task's alerts are converted from Splunk's public "Boss of the SOC"
(BOTS v1) dataset rather than hand-written. The raw dataset (~8GB) is not
included in this repo. To (re)build the episode bank:

1. Download BOTS v1 from Splunk's public dataset registry.
2. Place `suricata_eve.json`, `cloudtrail.json`, and `dns_stream.json` (one
   JSON object per line) into `data_pipeline/raw/`.
3. Run:
   ```bash
   python tools/build_real_world_scenarios.py
   ```
4. Commit the generated `scenarios/data/real_world/episode_*.json` files —
   these are small (converted/summarized alerts, not raw logs) and are what
   the environment actually reads at game-time.

Ground truth (real threat vs. noise) comes from `data_pipeline/known_iocs.json`
— a small, hand-curated list of indicators sourced from BOTS' own public
answer key, not from automatic detection.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Document how to build the real_world_incident scenario data"
```

---

## Self-Review Notes

- **Spec coverage:** Parser (Task 1), curated IOC table + mapper (Task 2), assembler (Task 3), build script + error handling for missing raw dir (Task 4), scenario loader with seed-wrap (Task 5), all 4 integration points from the spec — `scenarios/__init__.py`, `soc_env/environment.py`, `openenv.yaml`, server `TASK_METADATA` (Task 6), external-download documentation (Task 7). All covered.
- **Degenerate-episode guard:** implemented in `_build_episode` (Task 3) and covered by `test_episode_dropped_if_all_malicious_or_all_benign`.
- **Seed wraparound:** implemented via `files[seed % len(files)]` in Task 5.
- **No existing task changed:** verified — Tasks 1-5 only add new files; Task 6 only *adds* dict entries and one `elif` branch, never modifies existing branches' behavior.
