import { useState } from "react";

type Action = {
  taskId: "alert_triage" | "attack_chain_reconstruction" | "constrained_incident_response";
  title: string;
  description: string;
  endpoint: string;
};

type ResetResponse = {
  active_alerts?: Array<{ alert_id?: string }>;
};

type StepResponse = {
  reward?: { total?: number };
  done?: boolean;
};

const actions: Action[] = [
  {
    taskId: "alert_triage",
    title: "Alert Triage",
    description: "Review mixed true/false positive alerts and contain the verified threats.",
    endpoint: "POST /reset + /step (task: alert_triage)"
  },
  {
    taskId: "attack_chain_reconstruction",
    title: "Attack Chain Reconstruction",
    description: "Correlate multi-host signals and map attacker behavior across ATT&CK stages.",
    endpoint: "POST /step (task: attack_chain_reconstruction)"
  },
  {
    taskId: "constrained_incident_response",
    title: "Constrained Incident Response",
    description: "Respond under legal and business restrictions while minimizing operational impact.",
    endpoint: "POST /step (task: constrained_incident_response)"
  }
];

function HomePage() {
  const [busyTask, setBusyTask] = useState<Action["taskId"] | null>(null);
  const [resultText, setResultText] = useState<string>("");
  const apiBase = import.meta.env.VITE_API_BASE_URL ?? window.location.origin;

  const buildActionPayload = (taskId: Action["taskId"], resetData: ResetResponse) => {
    const firstAlertId = resetData.active_alerts?.[0]?.alert_id ?? "ALT-001";
    const firstTwoAlertIds = (resetData.active_alerts ?? [])
      .map((a) => a.alert_id)
      .filter((id): id is string => Boolean(id))
      .slice(0, 2);

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
        alert_ids: firstTwoAlertIds.length > 0 ? firstTwoAlertIds : [firstAlertId],
        correlation_hypothesis: "Potential linked attacker activity across hosts"
      };
    }

    return {
      action_type: "create_ticket",
      priority: "P1",
      summary: "Critical incident initiated via web console"
    };
  };

  const runScenario = async (taskId: Action["taskId"], title: string) => {
    setBusyTask(taskId);
    setResultText(`Running ${title}...`);

    try {
      const resetResponse = await fetch(`${apiBase}/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: taskId, seed: 42 })
      });

      if (!resetResponse.ok) {
        throw new Error(`Reset failed with status ${resetResponse.status}`);
      }

      const resetData = (await resetResponse.json()) as ResetResponse;
      const action = buildActionPayload(taskId, resetData);

      const stepResponse = await fetch(`${apiBase}/step`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: taskId, action })
      });

      if (!stepResponse.ok) {
        const details = await stepResponse.text();
        throw new Error(`Step failed (${stepResponse.status}): ${details}`);
      }

      const stepData = (await stepResponse.json()) as StepResponse;
      const reward = stepData.reward?.total ?? 0;
      const done = stepData.done ? "yes" : "no";
      setResultText(`${title} completed. Reward: ${reward.toFixed(3)} | Done: ${done}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown request error";
      setResultText(`Request error: ${message}`);
    } finally {
      setBusyTask(null);
    }
  };

  return (
    <section className="page page-home">
      <div className="hero-card reveal">
        <p className="section-label">Mission Control</p>
        <h2>Train and evaluate autonomous SOC decision-making.</h2>
        <p>
          This interface highlights the three core actions your environment supports. Each button is styled
          as a high-contrast command switch with tactile pop animation and hover lift.
        </p>
      </div>

      <div className="actions-grid">
        {actions.map((action, index) => (
          <article className="action-card reveal" style={{ animationDelay: `${index * 0.12}s` }} key={action.title}>
            <h3>{action.title}</h3>
            <p>{action.description}</p>
            <button
              type="button"
              className="pop-button"
              onClick={() => runScenario(action.taskId, action.title)}
              disabled={busyTask !== null}
            >
              {busyTask === action.taskId ? "Running..." : `Run ${action.title}`}
            </button>
            <span>{action.endpoint}</span>
          </article>
        ))}
      </div>

      <div className="hero-card reveal" style={{ marginTop: "1rem" }}>
        <p className="section-label">Live API Result</p>
        <h2>Execution Output</h2>
        <p>{resultText || "Click any action button to call the backend endpoints."}</p>
      </div>
    </section>
  );
}

export default HomePage;
