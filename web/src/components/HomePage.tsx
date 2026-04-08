import { useEffect, useMemo, useState } from "react";

type TaskId = "alert_triage" | "attack_chain_reconstruction" | "constrained_incident_response";
type Difficulty = "easy" | "medium" | "hard";

type TaskDefinition = {
  id: TaskId;
  name: string;
  difficulty: Difficulty;
  max_steps: number;
  description: string;
};

type AlertRecord = {
  alert_id?: string;
  severity?: string;
  host_id?: string;
  user_id?: string | null;
  rule_name?: string;
  mitre_tactic?: string | null;
  status?: string;
  enrichment?: unknown;
  indicators?: Array<{
    type?: string;
    value?: string;
    reputation?: string;
  }>;
};

type HostRecord = {
  host_id?: string;
  hostname?: string;
  status?: string;
  role?: string;
  is_critical?: boolean;
  is_vip?: boolean;
};

type ConstraintRecord = {
  host_id?: string | null;
  user_id?: string | null;
  constraint_type?: string;
  severity?: string;
  reason?: string;
};

type NoteRecord = {
  step?: number;
  action_taken?: string;
  finding?: string;
  timestamp?: string;
};

type Observation = {
  step: number;
  task_id: string;
  task_description: string;
  active_alerts: AlertRecord[];
  acknowledged_alerts?: AlertRecord[];
  hosts: HostRecord[];
  business_constraints: ConstraintRecord[];
  notes: NoteRecord[];
  elapsed_minutes: number;
  steps_remaining: number;
  last_action_result?: string | null;
  last_action_success?: boolean;
};

type EnvState = {
  task_id: string;
  step: number;
  done: boolean;
  cumulative_reward: number;
  observation: Observation;
  attack_chain?: Record<string, unknown> | null;
  identified_stages?: string[];
  isolated_hosts?: string[];
  disabled_accounts?: string[];
  forensics_collected?: Record<string, string[]>;
  escalated?: boolean;
  ticket_created?: boolean;
};

type StepReward = {
  total?: number;
  classification_delta?: number;
  chain_coverage_delta?: number;
  containment_delta?: number;
  dwell_penalty?: number;
  fp_penalty?: number;
  compliance_delta?: number;
  info?: string;
};

type StepResponse = {
  observation?: Observation;
  reward?: StepReward;
  done?: boolean;
  info?: Record<string, unknown>;
};

type GradeResponse = {
  task_id?: string;
  score?: number;
  breakdown?: Record<string, unknown>;
};

type RunTrace = {
  id: string;
  kind: "reset" | "step" | "grade" | "error" | "info";
  title: string;
  detail: string;
  reward?: number;
  done?: boolean;
  actionType?: string;
  createdAt: string;
};

type TaskSeed = {
  action_type: string;
  alert_id?: string;
  alert_ids?: string[];
  host_id?: string;
  user_id?: string;
  artifact_types?: string[];
  source?: string;
  priority?: "P1" | "P2" | "P3";
  summary?: string;
  correlation_hypothesis?: string;
};

const FALLBACK_TASKS: TaskDefinition[] = [
  {
    id: "alert_triage",
    name: "Alert triage",
    difficulty: "easy",
    max_steps: 10,
    description: "Classify noisy SIEM alerts, enrich the useful ones, and contain the true positives."
  },
  {
    id: "attack_chain_reconstruction",
    name: "Attack chain reconstruction",
    difficulty: "medium",
    max_steps: 25,
    description: "Correlate alerts across hosts, identify the ATT&CK chain, and stop lateral movement."
  },
  {
    id: "constrained_incident_response",
    name: "Constrained incident response",
    difficulty: "hard",
    max_steps: 40,
    description:
      "Respond to an active breach while respecting legal hold, customer-facing, and hard-block constraints."
  }
];

const API_ROOT = import.meta.env.VITE_API_BASE_URL ?? window.location.origin;

const createSuggestedAction = (taskId: TaskId, observation: Observation | null): TaskSeed => {
  const activeAlerts = observation?.active_alerts ?? [];
  const hosts = observation?.hosts ?? [];
  const constraints = observation?.business_constraints ?? [];

  const firstAlertId = typeof activeAlerts[0]?.alert_id === "string" ? activeAlerts[0].alert_id : "ALT-001";
  const secondAlertId = typeof activeAlerts[1]?.alert_id === "string" ? activeAlerts[1].alert_id : firstAlertId;
  const criticalHost = hosts.find((host) => host.is_critical && typeof host.host_id === "string")?.host_id;
  const legalHoldHost = constraints.find(
    (constraint) => constraint.constraint_type === "legal_hold" && typeof constraint.host_id === "string"
  )?.host_id;
  const preferredHost = criticalHost ?? legalHoldHost ?? hosts[0]?.host_id ?? "HOST-001";

  if (taskId === "alert_triage") {
    return {
      action_type: "enrich_alert",
      alert_id: firstAlertId,
      source: "threat_intel"
    };
  }

  if (taskId === "attack_chain_reconstruction") {
    return {
      action_type: "correlate_alerts",
      alert_ids: [firstAlertId, secondAlertId],
      correlation_hypothesis: "Linked intrusion activity across multiple hosts"
    };
  }

  if (constraints.some((constraint) => constraint.constraint_type === "legal_hold")) {
    return {
      action_type: "collect_forensics",
      host_id: String(legalHoldHost ?? preferredHost),
      artifact_types: ["memory_dump", "event_logs"]
    };
  }

  return {
    action_type: "create_ticket",
    priority: "P1",
    summary: "Critical incident requires immediate senior analyst review"
  };
};

const buildGuidedScript = (taskId: TaskId, observation: Observation | null): TaskSeed[] => {
  const activeAlerts = observation?.active_alerts ?? [];
  const hosts = observation?.hosts ?? [];
  const constraints = observation?.business_constraints ?? [];
  const firstAlertId = typeof activeAlerts[0]?.alert_id === "string" ? activeAlerts[0].alert_id : "ALT-001";
  const secondAlertId = typeof activeAlerts[1]?.alert_id === "string" ? activeAlerts[1].alert_id : firstAlertId;
  const criticalHost = hosts.find((host) => host.is_critical && typeof host.host_id === "string")?.host_id;
  const legalHoldHost = constraints.find(
    (constraint) => constraint.constraint_type === "legal_hold" && typeof constraint.host_id === "string"
  )?.host_id;
  const customerFacingHost = constraints.find(
    (constraint) => constraint.constraint_type === "customer_facing" && typeof constraint.host_id === "string"
  )?.host_id;
  const hostTarget = criticalHost ?? legalHoldHost ?? customerFacingHost ?? hosts[0]?.host_id ?? "HOST-001";

  if (taskId === "alert_triage") {
    return [
      {
        action_type: "enrich_alert",
        alert_id: firstAlertId,
        source: "threat_intel"
      },
      {
        action_type: "create_ticket",
        priority: "P2",
        summary: "Escalate the triage outcome and document containment evidence"
      }
    ];
  }

  if (taskId === "attack_chain_reconstruction") {
    return [
      {
        action_type: "enrich_alert",
        alert_id: firstAlertId,
        source: "asset_db"
      },
      {
        action_type: "correlate_alerts",
        alert_ids: [firstAlertId, secondAlertId],
        correlation_hypothesis: "Single intrusion spanning multiple hosts and stages"
      },
      {
        action_type: "isolate_endpoint",
        host_id: String(hostTarget)
      },
      {
        action_type: "create_ticket",
        priority: "P1",
        summary: "Attack chain identified and containment actions executed"
      }
    ];
  }

  return [
    {
      action_type: "collect_forensics",
      host_id: String(legalHoldHost ?? hostTarget),
      artifact_types: ["memory_dump", "event_logs", "network_capture"]
    },
    {
      action_type: "escalate_to_tier2",
      summary: "Active breach with legal and business constraints requires senior review"
    },
    {
      action_type: "create_ticket",
      priority: "P1",
      summary: "Open incident record and preserve evidence chain"
    }
  ];
};

const formatJson = (value: unknown) => JSON.stringify(value, null, 2);

function HomePage() {
  const [tasks, setTasks] = useState<TaskDefinition[]>(FALLBACK_TASKS);
  const [selectedTaskId, setSelectedTaskId] = useState<TaskId>("alert_triage");
  const [busy, setBusy] = useState<string | null>(null);
  const [statusText, setStatusText] = useState<string>("Ready to reset an episode.");
  const [draftAction, setDraftAction] = useState<string>(formatJson(createSuggestedAction("alert_triage", null)));
  const [observation, setObservation] = useState<Observation | null>(null);
  const [stateData, setStateData] = useState<EnvState | null>(null);
  const [gradeData, setGradeData] = useState<GradeResponse | null>(null);
  const [trace, setTrace] = useState<RunTrace[]>([]);
  const [backendError, setBackendError] = useState<string>("");

  const selectedTask = tasks.find((task) => task.id === selectedTaskId) ?? tasks[0];
  const activeAlerts = observation?.active_alerts ?? [];
  const acknowledgedAlerts = observation?.acknowledged_alerts ?? [];
  const hosts = observation?.hosts ?? [];
  const constraints = observation?.business_constraints ?? [];
  const notes = observation?.notes ?? [];

  const counts = useMemo(() => {
    return {
      alerts: activeAlerts.length,
      acknowledged: acknowledgedAlerts.length,
      hosts: hosts.length,
      constraints: constraints.length,
      notes: notes.length
    };
  }, [activeAlerts.length, acknowledgedAlerts.length, hosts.length, constraints.length, notes.length]);

  useEffect(() => {
    const loadTasks = async () => {
      try {
        const response = await fetch(`${API_ROOT}/api/tasks`);
        if (!response.ok) {
          throw new Error(`Task list request failed with status ${response.status}`);
        }
        const payload = (await response.json()) as { tasks?: TaskDefinition[] };
        if (Array.isArray(payload.tasks) && payload.tasks.length > 0) {
          setTasks(payload.tasks);
          if (!payload.tasks.some((task) => task.id === selectedTaskId) && payload.tasks[0]) {
            setSelectedTaskId(payload.tasks[0].id);
          }
        }
        setBackendError("");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to load tasks";
        setBackendError(message);
      }
    };

    void loadTasks();
  }, []);

  useEffect(() => {
    setDraftAction(formatJson(createSuggestedAction(selectedTaskId, observation)));
  }, [selectedTaskId]);

  useEffect(() => {
    if (!tasks.some((task) => task.id === selectedTaskId) && tasks[0]) {
      setSelectedTaskId(tasks[0].id);
    }
  }, [tasks, selectedTaskId]);

  const pushTrace = (
    entry: Omit<RunTrace, "id" | "createdAt">
  ) => {
    setTrace((current) => [
      {
        ...entry,
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createdAt: new Date().toISOString()
      },
      ...current
    ].slice(0, 32));
  };

  const syncState = async (taskId: TaskId) => {
    const response = await fetch(`${API_ROOT}/state?task_id=${taskId}`);
    if (!response.ok) {
      throw new Error(`State request failed with status ${response.status}`);
    }
    const payload = (await response.json()) as EnvState;
    setStateData(payload);
    return payload;
  };

  const resetEpisode = async (taskId: TaskId = selectedTaskId) => {
    setBusy("reset");
    setStatusText(`Resetting ${taskId}...`);
    try {
      const response = await fetch(`${API_ROOT}/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: taskId, seed: 42 })
      });

      if (!response.ok) {
        const details = await response.text();
        throw new Error(`Reset failed (${response.status}): ${details}`);
      }

      const payload = (await response.json()) as Observation;
      setObservation(payload);
      const state = await syncState(taskId);
      setGradeData(null);
      setBackendError("");
      setDraftAction(formatJson(createSuggestedAction(taskId, payload)));
      setStatusText(`Episode reset for ${taskId}. Ready for the next action.`);
      pushTrace({
        kind: "reset",
        title: "Episode reset",
        detail: `Loaded ${taskId} with ${payload.active_alerts.length} active alerts and ${payload.hosts.length} hosts.`
      });
      return { observation: payload, state };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown reset error";
      setBackendError(message);
      setStatusText("Reset failed.");
      pushTrace({
        kind: "error",
        title: "Reset error",
        detail: message
      });
      throw error;
    } finally {
      setBusy(null);
    }
  };

  const parseDraft = () => {
    const parsed = JSON.parse(draftAction) as TaskSeed;
    if (!parsed || typeof parsed !== "object" || typeof parsed.action_type !== "string") {
      throw new Error("Action JSON must include action_type.");
    }
    return parsed;
  };

  const sendStep = async (action: TaskSeed, label: string) => {
    setBusy("step");
    setStatusText(`${label}...`);

    try {
      const response = await fetch(`${API_ROOT}/step`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: selectedTaskId, action })
      });

      if (!response.ok) {
        const details = await response.text();
        throw new Error(`Step failed (${response.status}): ${details}`);
      }

      const payload = (await response.json()) as StepResponse;
      const nextObservation = payload.observation ?? null;
      setObservation(nextObservation);
      const state = await syncState(selectedTaskId);
      setBackendError("");
      const reward = payload.reward?.total ?? 0;
      const done = Boolean(payload.done);
      const actionType = action.action_type;
      setStatusText(`${label} complete. Reward ${reward.toFixed(3)}. Done: ${done ? "yes" : "no"}.`);
      pushTrace({
        kind: "step",
        title: label,
        detail: payload.reward?.info ?? `Action ${actionType} executed.`,
        reward,
        done,
        actionType
      });
      return { payload, state };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown step error";
      setBackendError(message);
      setStatusText("Action failed.");
      pushTrace({
        kind: "error",
        title: "Step error",
        detail: message
      });
      throw error;
    } finally {
      setBusy(null);
    }
  };

  const gradeEpisode = async () => {
    setBusy("grade");
    setStatusText(`Grading ${selectedTaskId}...`);

    try {
      const response = await fetch(`${API_ROOT}/grade?task_id=${selectedTaskId}`, {
        method: "POST"
      });

      if (!response.ok) {
        const details = await response.text();
        throw new Error(`Grade failed (${response.status}): ${details}`);
      }

      const payload = (await response.json()) as GradeResponse;
      setGradeData(payload);
      setBackendError("");
      const score = typeof payload.score === "number" ? payload.score : 0;
      setStatusText(`Grade complete. Score ${score.toFixed(3)}.`);
      pushTrace({
        kind: "grade",
        title: "Episode graded",
        detail: `Task ${selectedTaskId} scored ${score.toFixed(3)}.`,
        reward: score
      });
      return payload;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown grade error";
      setBackendError(message);
      setStatusText("Grade failed.");
      pushTrace({
        kind: "error",
        title: "Grade error",
        detail: message
      });
      throw error;
    } finally {
      setBusy(null);
    }
  };

  const runGuidedDemo = async () => {
    setBusy("demo");
    setBackendError("");
    try {
      const resetResult = await resetEpisode(selectedTaskId);
      const script = buildGuidedScript(selectedTaskId, resetResult.observation);
      for (const [index, action] of script.entries()) {
        const response = await sendStep(action, `Guided step ${index + 1}`);
        if (response.payload.done) {
          break;
        }
      }
      await gradeEpisode();
      setStatusText(`Guided demo completed for ${selectedTaskId}.`);
    } catch {
      // errors already surfaced in trace and status
    } finally {
      setBusy(null);
    }
  };

  const loadSuggestedAction = () => {
    setDraftAction(formatJson(createSuggestedAction(selectedTaskId, observation)));
  };

  const submitDraftAction = async () => {
    const action = parseDraft();
    await sendStep(action, `Manual step for ${selectedTaskId}`);
  };

  return (
    <section className="page page-home">
      <div className="hero-card hero-console reveal">
        <div className="hero-copy">
          <p className="section-label">OpenEnv hackathon demo</p>
          <h2>Security Operations Center simulation with live reset, step, state, and grade flows.</h2>
          <p>
            The environment is the simulator. The model is only the policy that emits JSON actions. This
            console shows both sides clearly so judges can inspect the episode, the response, the reward, and
            the final score without reading code.
          </p>
        </div>

        <div className="hero-stats" aria-label="Environment summary">
          <div className="stat-card">
            <span>Tasks</span>
            <strong>{tasks.length}</strong>
            <small>easy → hard</small>
          </div>
          <div className="stat-card">
            <span>Backend</span>
            <strong>FastAPI</strong>
            <small>/reset /step /state /grade</small>
          </div>
          <div className="stat-card">
            <span>Baseline</span>
            <strong>HF router</strong>
            <small>OpenAI client compatible</small>
          </div>
        </div>
      </div>

      <div className="console-layout">
        <aside className="console-sidebar">
          <article className="panel reveal">
            <p className="section-label">Tasks</p>
            <h3>Available scenarios</h3>
            <div className="task-list">
              {tasks.map((task, index) => (
                <button
                  key={task.id}
                  type="button"
                  className={`task-card ${selectedTaskId === task.id ? "active" : ""} reveal`}
                  style={{ animationDelay: `${index * 0.08}s` }}
                  onClick={() => setSelectedTaskId(task.id)}
                >
                  <div className="task-card-head">
                    <strong>{task.name}</strong>
                    <span>{task.difficulty.toUpperCase()}</span>
                  </div>
                  <p>{task.description}</p>
                  <small>{task.max_steps} max steps</small>
                </button>
              ))}
            </div>
          </article>

          <article className="panel reveal" style={{ animationDelay: "0.08s" }}>
            <p className="section-label">Controls</p>
            <h3>Episode actions</h3>
            <div className="control-stack">
              <button type="button" className="primary-button" onClick={() => void resetEpisode()} disabled={busy !== null}>
                {busy === "reset" ? "Resetting..." : "Reset episode"}
              </button>
              <button type="button" className="primary-button ghost" onClick={loadSuggestedAction} disabled={busy !== null}>
                Load suggested action
              </button>
              <button type="button" className="primary-button" onClick={() => void submitDraftAction()} disabled={busy !== null}>
                {busy === "step" ? "Sending action..." : "Run draft action"}
              </button>
              <button type="button" className="primary-button ghost" onClick={() => void gradeEpisode()} disabled={busy !== null}>
                {busy === "grade" ? "Grading..." : "Grade current episode"}
              </button>
              <button type="button" className="primary-button accent" onClick={() => void runGuidedDemo()} disabled={busy !== null}>
                {busy === "demo" ? "Running demo..." : "Run guided demo"}
              </button>
            </div>

            <div className="status-block">
              <span>Status</span>
              <strong>{statusText}</strong>
              <small>{backendError || `Connected to ${API_ROOT}`}</small>
            </div>
          </article>
        </aside>

        <section className="console-main">
          <article className="panel reveal">
            <div className="panel-head">
              <div>
                <p className="section-label">Active episode</p>
                <h3>{selectedTask?.name ?? selectedTaskId}</h3>
              </div>
              <div className="score-pill-row">
                <span className="score-pill">Reward {stateData?.cumulative_reward?.toFixed(3) ?? "0.000"}</span>
                <span className="score-pill">Step {stateData?.step ?? observation?.step ?? 0}</span>
                <span className="score-pill">Done {stateData?.done ? "yes" : "no"}</span>
              </div>
            </div>

            <p className="panel-note">
              {selectedTask?.description ?? "Select a task to inspect the current incident."}
            </p>

            <div className="metric-grid">
              <div className="metric-card">
                <span>Active alerts</span>
                <strong>{counts.alerts}</strong>
              </div>
              <div className="metric-card">
                <span>Acknowledged</span>
                <strong>{counts.acknowledged}</strong>
              </div>
              <div className="metric-card">
                <span>Hosts</span>
                <strong>{counts.hosts}</strong>
              </div>
              <div className="metric-card">
                <span>Constraints</span>
                <strong>{counts.constraints}</strong>
              </div>
            </div>

            <div className="json-grid">
              <div className="json-card">
                <div className="json-card-head">
                  <h4>Current observation</h4>
                  <small>Visible to the agent</small>
                </div>
                <pre>{formatJson(observation ?? { note: "Reset an episode to load data." })}</pre>
              </div>

              <div className="json-card">
                <div className="json-card-head">
                  <h4>Backend state</h4>
                  <small>Includes hidden grading state</small>
                </div>
                <pre>{formatJson(stateData ?? { note: "State appears after the first reset." })}</pre>
              </div>
            </div>
          </article>

          <article className="panel reveal" style={{ animationDelay: "0.08s" }}>
            <div className="panel-head">
              <div>
                <p className="section-label">Action draft</p>
                <h3>JSON action submitted to /step</h3>
              </div>
              <div className="score-pill-row">
                <span className="score-pill">HF client</span>
                <span className="score-pill">Deterministic grader</span>
              </div>
            </div>

            <textarea
              className="draft-editor"
              value={draftAction}
              onChange={(event) => setDraftAction(event.target.value)}
              spellCheck={false}
            />

            <div className="panel-actions">
              <button type="button" className="secondary-button" onClick={loadSuggestedAction} disabled={busy !== null}>
                Load suggested JSON
              </button>
              <button type="button" className="secondary-button accent" onClick={() => void submitDraftAction()} disabled={busy !== null}>
                Execute draft action
              </button>
            </div>

            {gradeData && (
              <div className="grade-card">
                <strong>Final score: {typeof gradeData.score === "number" ? gradeData.score.toFixed(4) : "n/a"}</strong>
                <pre>{formatJson(gradeData.breakdown ?? {})}</pre>
              </div>
            )}
          </article>

          <article className="panel reveal" style={{ animationDelay: "0.16s" }}>
            <div className="panel-head">
              <div>
                <p className="section-label">Trace</p>
                <h3>Episode timeline</h3>
              </div>
              <div className="score-pill-row">
                <span className="score-pill">Max {selectedTask?.max_steps ?? 0} steps</span>
                <span className="score-pill">{trace.length} events</span>
              </div>
            </div>

            <div className="trace-list">
              {trace.length === 0 && <p className="empty-state">Run reset, step, or grade to populate the trace.</p>}
              {trace.map((entry) => (
                <div className={`trace-item ${entry.kind}`} key={entry.id}>
                  <div>
                    <strong>{entry.title}</strong>
                    <p>{entry.detail}</p>
                    <small>{new Date(entry.createdAt).toLocaleTimeString()}</small>
                  </div>
                  <div className="trace-meta">
                    {entry.actionType && <span>{entry.actionType}</span>}
                    {typeof entry.reward === "number" && <span>reward {entry.reward.toFixed(3)}</span>}
                    {typeof entry.done === "boolean" && <span>done {entry.done ? "yes" : "no"}</span>}
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="panel reveal" style={{ animationDelay: "0.24s" }}>
            <div className="panel-head">
              <div>
                <p className="section-label">Incident snapshot</p>
                <h3>Alerts, hosts, constraints, and notes</h3>
              </div>
            </div>

            <div className="detail-grid">
              <div className="detail-column">
                <h4>Active alerts</h4>
                {activeAlerts.length === 0 && <p className="empty-state">No active alerts yet.</p>}
                {activeAlerts.map((alert, index) => (
                  <div className="detail-card" key={alert.alert_id ?? index}>
                    <strong>{alert.alert_id ?? `Alert ${index + 1}`}</strong>
                    <p>{alert.rule_name ?? "No rule name"}</p>
                    <small>
                      Host {alert.host_id ?? "n/a"} | Severity {alert.severity ?? "n/a"} | Tactic {alert.mitre_tactic ?? "n/a"}
                    </small>
                  </div>
                ))}
              </div>

              <div className="detail-column">
                <h4>Hosts</h4>
                {hosts.length === 0 && <p className="empty-state">No hosts loaded yet.</p>}
                {hosts.map((host, index) => (
                  <div className="detail-card" key={host.host_id ?? index}>
                    <strong>{host.hostname ?? host.host_id ?? `Host ${index + 1}`}</strong>
                    <p>{host.role ?? "Unknown role"}</p>
                    <small>
                      {host.host_id ?? "n/a"} | {host.status ?? "n/a"} | critical {host.is_critical ? "yes" : "no"} | vip {host.is_vip ? "yes" : "no"}
                    </small>
                  </div>
                ))}
              </div>

              <div className="detail-column">
                <h4>Constraints</h4>
                {constraints.length === 0 && <p className="empty-state">No business constraints loaded yet.</p>}
                {constraints.map((constraint, index) => (
                  <div className="detail-card" key={`${constraint.constraint_type ?? "constraint"}-${index}`}>
                    <strong>{constraint.constraint_type ?? "Constraint"}</strong>
                    <p>{constraint.reason ?? "No reason provided"}</p>
                    <small>
                      Severity {constraint.severity ?? "n/a"} | host {constraint.host_id ?? "n/a"} | user {constraint.user_id ?? "n/a"}
                    </small>
                  </div>
                ))}
              </div>

              <div className="detail-column">
                <h4>Recent notes</h4>
                {notes.length === 0 && <p className="empty-state">No investigation notes yet.</p>}
                {notes.map((note, index) => (
                  <div className="detail-card" key={`${note.step ?? index}-${index}`}>
                    <strong>Step {note.step ?? index + 1}</strong>
                    <p>{note.action_taken ?? "No action"}</p>
                    <small>{note.finding ?? "No finding"}</small>
                  </div>
                ))}
              </div>
            </div>
          </article>
        </section>
      </div>
    </section>
  );
}

export default HomePage;