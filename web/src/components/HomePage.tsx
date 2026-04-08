import { useMemo, useState } from "react";

type Action = {
  taskId: "alert_triage" | "attack_chain_reconstruction" | "constrained_incident_response";
  difficulty: "easy" | "medium" | "hard";
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

type GradeResponse = {
  score?: number;
};

type RunRecord = {
  id: string;
  title: string;
  taskId: Action["taskId"];
  difficulty: Action["difficulty"];
  reward: number;
  gradeScore: number | null;
  done: boolean;
  success: boolean;
  message: string;
  createdAt: string;
};

const actions: Action[] = [
  {
    taskId: "alert_triage",
    difficulty: "easy",
    title: "Alert Triage",
    description: "Review mixed true/false positive alerts and contain the verified threats.",
    endpoint: "POST /reset + /step (task: alert_triage)"
  },
  {
    taskId: "attack_chain_reconstruction",
    difficulty: "medium",
    title: "Attack Chain Reconstruction",
    description: "Correlate multi-host signals and map attacker behavior across ATT&CK stages.",
    endpoint: "POST /step (task: attack_chain_reconstruction)"
  },
  {
    taskId: "constrained_incident_response",
    difficulty: "hard",
    title: "Constrained Incident Response",
    description: "Respond under legal and business restrictions while minimizing operational impact.",
    endpoint: "POST /step (task: constrained_incident_response)"
  }
];

function HomePage() {
  const initialHistory = (() => {
    try {
      const raw = localStorage.getItem("soc-openenv-run-history");
      return raw ? (JSON.parse(raw) as RunRecord[]) : [];
    } catch {
      return [];
    }
  })();

  const [busyTask, setBusyTask] = useState<Action["taskId"] | null>(null);
  const [resultText, setResultText] = useState<string>("");
  const [showHistory, setShowHistory] = useState<boolean>(false);
  const [runHistory, setRunHistory] = useState<RunRecord[]>(initialHistory);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [fromDate, setFromDate] = useState<string>("");
  const [toDate, setToDate] = useState<string>("");
  const [difficultyFilters, setDifficultyFilters] = useState<Array<Action["difficulty"]>>([
    "easy",
    "medium",
    "hard"
  ]);
  const apiBase = import.meta.env.VITE_API_BASE_URL ?? window.location.origin;

  const getRewardMood = (value: number) => {
    if (value > 0) return "positive";
    if (value < 0) return "negative";
    return "neutral";
  };

  const filteredHistory = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const from = fromDate ? new Date(fromDate).getTime() : null;
    const to = toDate ? new Date(toDate).getTime() : null;

    return runHistory.filter((record) => {
      const time = new Date(record.createdAt).getTime();
      const matchesQuery =
        query.length === 0 ||
        record.title.toLowerCase().includes(query) ||
        record.taskId.toLowerCase().includes(query) ||
        record.message.toLowerCase().includes(query);
      const matchesFrom = from === null || time >= from;
      const matchesTo = to === null || time <= to;
      const matchesDifficulty = difficultyFilters.includes(record.difficulty);
      return matchesQuery && matchesFrom && matchesTo && matchesDifficulty;
    });
  }, [runHistory, searchQuery, fromDate, toDate, difficultyFilters]);

  const toggleDifficultyFilter = (difficulty: Action["difficulty"]) => {
    setDifficultyFilters((current) => {
      if (current.includes(difficulty)) {
        const next = current.filter((d) => d !== difficulty);
        return next.length === 0 ? current : next;
      }
      return [...current, difficulty];
    });
  };

  const rankedResults = useMemo(() => {
    return [...filteredHistory]
      .filter((r) => r.success)
      .sort((a, b) => {
        const aScore = a.gradeScore ?? Number.NEGATIVE_INFINITY;
        const bScore = b.gradeScore ?? Number.NEGATIVE_INFINITY;
        if (bScore !== aScore) return bScore - aScore;
        return b.reward - a.reward;
      });
  }, [filteredHistory]);

  const groupedHistory = useMemo(() => {
    return {
      easy: filteredHistory.filter((r) => r.difficulty === "easy"),
      medium: filteredHistory.filter((r) => r.difficulty === "medium"),
      hard: filteredHistory.filter((r) => r.difficulty === "hard")
    };
  }, [filteredHistory]);

  const saveHistory = (records: RunRecord[]) => {
    setRunHistory(records);
    localStorage.setItem("soc-openenv-run-history", JSON.stringify(records));
  };

  const addRecord = (record: RunRecord) => {
    const records = [record, ...runHistory].slice(0, 50);
    saveHistory(records);
  };

  const exportHistoryJson = () => {
    const data = JSON.stringify(filteredHistory, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "soc-openenv-history.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportHistoryCsv = () => {
    const headers = [
      "id",
      "createdAt",
      "title",
      "taskId",
      "difficulty",
      "reward",
      "gradeScore",
      "rewardMood",
      "done",
      "success",
      "message"
    ];

    const escapeCell = (value: string | number | boolean | null) => {
      const text = String(value ?? "");
      if (text.includes(",") || text.includes("\n") || text.includes('"')) {
        return `"${text.split('"').join('""')}"`;
      }
      return text;
    };

    const rows = filteredHistory.map((r) => [
      r.id,
      r.createdAt,
      r.title,
      r.taskId,
      r.difficulty,
      r.reward,
      r.gradeScore,
      getRewardMood(r.reward),
      r.done,
      r.success,
      r.message
    ]);

    const csv = [headers, ...rows]
      .map((row) => row.map((cell) => escapeCell(cell as string | number | boolean | null)).join(","))
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "soc-openenv-history.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

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

  const runScenario = async (actionMeta: Action) => {
    const { taskId, title, difficulty } = actionMeta;
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
      const done = Boolean(stepData.done);
      const gradeResponse = await fetch(`${apiBase}/grade?task_id=${taskId}`, {
        method: "POST"
      });
      const gradeData = gradeResponse.ok ? ((await gradeResponse.json()) as GradeResponse) : null;
      const gradeScore = typeof gradeData?.score === "number" ? gradeData.score : null;
      const message =
        `${title} completed. Reward: ${reward.toFixed(3)} | ` +
        `Grade: ${gradeScore === null ? "n/a" : gradeScore.toFixed(3)} | Done: ${done ? "yes" : "no"}`;
      setResultText(message);
      addRecord({
        id: `${Date.now()}-${taskId}`,
        title,
        taskId,
        difficulty,
        reward,
        gradeScore,
        done,
        success: true,
        message,
        createdAt: new Date().toISOString()
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown request error";
      const finalMessage = `Request error: ${message}`;
      setResultText(finalMessage);
      addRecord({
        id: `${Date.now()}-${taskId}`,
        title,
        taskId,
        difficulty,
        reward: 0,
        gradeScore: null,
        done: false,
        success: false,
        message: finalMessage,
        createdAt: new Date().toISOString()
      });
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
              onClick={() => runScenario(action)}
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

        <div className="results-toolbar">
          <button
            type="button"
            className="pop-button small"
            onClick={() => setShowHistory((v) => !v)}
          >
            {showHistory ? "Hide History" : "History"}
          </button>
          <button
            type="button"
            className="pop-button small ghost"
            onClick={() => saveHistory([])}
            disabled={runHistory.length === 0}
          >
            Clear Results
          </button>
          <button
            type="button"
            className="pop-button small ghost"
            onClick={exportHistoryJson}
            disabled={filteredHistory.length === 0}
          >
            Export JSON
          </button>
          <button
            type="button"
            className="pop-button small ghost"
            onClick={exportHistoryCsv}
            disabled={filteredHistory.length === 0}
          >
            Export CSV
          </button>
        </div>

        <div className="history-filters">
          <input
            type="text"
            placeholder="Search task, title, or message"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          <input
            type="datetime-local"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
          />
          <input
            type="datetime-local"
            value={toDate}
            onChange={(e) => setToDate(e.target.value)}
          />
        </div>

        <div className="chip-row">
          {(["easy", "medium", "hard"] as const).map((difficulty) => (
            <button
              key={difficulty}
              type="button"
              className={`chip ${difficultyFilters.includes(difficulty) ? "active" : ""}`}
              onClick={() => toggleDifficultyFilter(difficulty)}
            >
              {difficulty.toUpperCase()}
            </button>
          ))}
        </div>

        <div className="ranking-grid">
          <article className="output-card">
            <h3>Ranked Results</h3>
            {rankedResults.length === 0 && <p>No successful runs yet.</p>}
            {rankedResults.map((result, index) => (
              <div className="rank-row" key={result.id}>
                <span>#{index + 1}</span>
                <strong>{result.title}</strong>
                <em>G:{result.gradeScore === null ? "n/a" : result.gradeScore.toFixed(3)} | R:{result.reward.toFixed(3)}</em>
              </div>
            ))}
          </article>

          {showHistory && (
            <article className="output-card">
              <h3>History</h3>
              {(["easy", "medium", "hard"] as const).map((difficulty) => (
                <div key={difficulty} className="history-group">
                  <h4>{difficulty.toUpperCase()}</h4>
                  {groupedHistory[difficulty].length === 0 && <p>No runs.</p>}
                  {groupedHistory[difficulty].map((item) => (
                    <div className="history-row" key={item.id}>
                      <span>{new Date(item.createdAt).toLocaleTimeString()}</span>
                      <strong>{item.title}</strong>
                      <em>{item.success ? item.reward.toFixed(3) : "ERR"}</em>
                      <i className={`reward-mood ${getRewardMood(item.reward)}`}>
                        {getRewardMood(item.reward)}
                      </i>
                    </div>
                  ))}
                </div>
              ))}
            </article>
          )}
        </div>
      </div>
    </section>
  );
}

export default HomePage;
