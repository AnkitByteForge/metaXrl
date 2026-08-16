# Real-World Scenario Pipeline — Design Spec

## Problem

All current scenarios (`scenarios/easy_scenarios.py`, `medium_scenarios.py`,
`hard_scenarios.py`) are hand-written, fixed, fictional data. This is fine for
a hackathon demo, but it means:

- An agent can memorize the fixed answer instead of reasoning.
- There isn't enough variety to eventually train a model with RL (a future
  stage, not part of this spec).

This spec covers **Stage 1 only**: building an offline pipeline that converts
a real security dataset (Splunk's "Boss of the SOC" / BOTS v1) into many
varied, typed scenario episodes that plug into the existing environment
exactly like the other 3 tasks do.

## Goals

- Add a 4th task, `real_world_incident`, backed by real log data.
- Automate the conversion (parsing + assembly) end to end.
- Ground truth (real threat vs. noise) comes from a small, hand-curated table
  of known-malicious indicators sourced from BOTS' public answer key — not
  from an auto-built detector (see Non-Goals).
- Reuse the existing `SOCEnv` / `SIEMAlert` / grader contracts unchanged.
- Runs entirely offline, ahead of time — game-time `reset()` just picks a
  pre-built episode. No behavior change to the 3 existing tasks.

## Non-Goals

- No automatic threat detection/heuristics — labeling is fact-table-driven,
  not inferred. Being upfront about this avoids quietly building (and
  trusting) an unvalidated detector.
- No support for binary/EVTX Windows event logs in this stage — only the
  JSON-friendly BOTS sources (Suricata `eve.json`, AWS CloudTrail, DNS/Stream
  logs). EVTX parsing is a separate, later effort if needed.
- No changes to the 3 existing tasks or their scenario files.
- No RL training loop (that's Stage 2, separately designed later).
- Raw BOTS files are not committed to the repo (multi-GB) — documented as an
  external download step, gitignored.

## Architecture

```
raw BOTS log files (downloaded separately by the user, gitignored)
        |
        v
[1] Parser         reads Suricata / CloudTrail / DNS JSON into one common
                    intermediate record shape
        |
        v
[2] Labeler         looks up each record's indicators (IP, hash, domain,
                    user) against the curated IOC table -> True/False
        |
        v
[3] Schema mapper   converts labeled records into SIEMAlert / NetworkHost
                    objects (existing pydantic models, unchanged)
        |
        v
[4] Assembler       groups records into many time-window episodes, and for
                    each episode synthesizes an AttackChain (patient zero =
                    earliest malicious event's host, stages = distinct MITRE
                    tactics seen, lateral_movement_targets = other hosts
                    touched by malicious events, crown_jewel_host = from IOC
                    table config)
        |
        v
episode bank (JSON files on disk, one per episode, checked into the repo —
              small, since these are converted/summarized, not raw logs)
        |
        v
scenarios/real_world_scenarios.py: get_real_world_scenario(seed) loads
episode `seed % N` from the bank and returns {"observation", "attack_chain"}
exactly like the other 3 scenario modules.
```

Everything above the "episode bank" line is a one-time, manually-run build
script (`tools/build_real_world_scenarios.py`). It is never invoked during
normal `reset()/step()` play — matching how the other 3 tasks work (fast,
deterministic, no I/O to raw data at play-time).

## Components

**1. Parser** (`data_pipeline/parsers.py`)
One function per log source (`parse_suricata`, `parse_cloudtrail`,
`parse_dns`), each yielding a common `RawEvent` dataclass: `timestamp, host,
user, event_type, indicators: list[(type, value)], raw_line`. Malformed
lines are skipped and counted, not fatal.

**2. Curated IOC table** (`data_pipeline/known_iocs.json`)
Hand-built once, from BOTS' public answer key/write-ups. Example shape:
```json
{
  "ip": ["203.0.113.42"],
  "hash": ["a3f4b2c1d9e8f7a6b5c4d3e2f1a0b9c8"],
  "domain": ["file-share-quick.net"],
  "user": ["svc_api"]
}
```
A `RawEvent` is labeled `ground_truth=True` if any of its indicators appear
in this table, else `False`. This table is the only manually-authored
artifact in the whole pipeline — everything else is code.

**3. Schema mapper** (`data_pipeline/mapper.py`)
Converts a labeled `RawEvent` into a `SIEMAlert` (severity derived from a
simple rule: malicious -> high/critical, else low/medium; `mitre_tactic`
from a small technique-ID lookup table keyed by event_type) and ensures a
`NetworkHost` exists for every host seen.

**4. Assembler** (`data_pipeline/assembler.py`)
Slices the full labeled event stream into overlapping time windows (e.g.
30-60 min each), keeps windows with a minimum mix of signal/noise, and
writes each as one `episode_XXXX.json` file under
`scenarios/data/real_world/`. This is what gives us the "many varied
scenarios" needed later for RL — different seeds genuinely see different
alerts, unlike the 3 fixed hand-written tasks.

## File Layout (new)

```
data_pipeline/
  __init__.py
  parsers.py
  known_iocs.json
  mapper.py
  assembler.py
tools/
  build_real_world_scenarios.py      # the one-time offline build script
scenarios/
  data/real_world/episode_0000.json  # ... generated output, committed
  real_world_scenarios.py            # get_real_world_scenario(seed) loader
```

## Integration points (existing files touched)

- `scenarios/__init__.py`: add `real_world_incident` branch to
  `load_scenario()`.
- `soc_env/environment.py`: add `real_world_incident` to `TASK_IDS`,
  `MAX_STEPS`, `MAX_MINUTES`, `MINUTES_PER_STEP`; `grade()` dispatches it to
  the existing `grade_task_medium` (best fit — reuses chain-coverage +
  containment scoring, no new grader code needed).
- `openenv.yaml`: add the 4th task entry.
- `server/app.py` (`root_server.py`)'s `TASK_METADATA`: add the 4th task's
  display metadata.

No existing task's behavior, files, or scores change.

## Error Handling

- Raw data directory missing/empty at build time -> the build script exits
  with a clear message pointing to the download instructions; it never
  silently produces an empty scenario bank.
- A malformed log line -> skipped and counted, logged as a summary at the
  end of the build run (not a per-line crash).
- An assembled window with zero real-threat events (all noise) -> dropped,
  since it wouldn't be a useful/gradeable episode.
- `get_real_world_scenario(seed)` with a seed beyond the bank size -> wraps
  via `seed % len(bank)` rather than erroring, matching how a game keeps
  working with any seed value.

## Testing

- Unit tests for `parsers.py` / `mapper.py` using a handful of small, fixture
  JSON log lines committed to the repo (not the real 8GB dataset) —
  verifies correct field mapping and labeling logic in isolation.
- `test_environment.py`-style tests extended to cover `real_world_incident`
  in the existing parametrized tests (reset returns Observation, ground
  truth hidden, reproducible per seed, episode terminates).
- One test asserting every generated episode file has at least one TP and
  one FP alert (guards against the empty/degenerate-episode case).

## Dependencies / external setup

The user must separately download BOTS v1 raw data from its public source
and place it at a documented path (e.g. `data_pipeline/raw/`, gitignored)
before running `tools/build_real_world_scenarios.py`. This is a manual,
one-time step — documented in the README, not automated (redistributing the
dataset ourselves is out of scope and unnecessary).
