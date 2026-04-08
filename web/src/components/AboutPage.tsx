function AboutPage() {
  return (
    <section className="page page-about">
      <div className="about-grid">
        <article className="about-card reveal">
          <p className="section-label">What this is</p>
          <h2>SOC Incident Response OpenEnv</h2>
          <p>
            This project models a real security operations workflow: an analyst receives SIEM alerts, inspects
            hosts and constraints, applies containment actions, and closes the episode with a graded outcome.
          </p>
          <p>
            The environment is the simulator. The model is the decision policy. The grader is the benchmark.
            That separation is what makes the repository usable for OpenEnv evaluation, HF Space deployment, and
            reproducible baseline runs.
          </p>
        </article>

        <article className="about-card reveal" style={{ animationDelay: "0.08s" }}>
          <p className="section-label">What the agent sees</p>
          <h2>Structured observations and typed actions</h2>
          <p>
            Each step exposes alerts, hosts, business constraints, recent notes, and timing data. The agent can
            submit one JSON action per turn, such as enriching alerts, correlating incidents, isolating endpoints,
            collecting forensics, escalating, or creating a ticket.
          </p>
          <p>
            The backend enforces the rules. For example, hard-block constraints prevent unsafe isolation, and the
            observation returned to the agent never includes hidden ground-truth fields.
          </p>
        </article>

        <article className="about-card reveal" style={{ animationDelay: "0.16s" }}>
          <p className="section-label">How scoring works</p>
          <h2>Dense rewards plus deterministic graders</h2>
          <p>
            Step rewards give partial credit for useful actions and penalties for wasteful or unsafe ones. At the
            end of the episode, deterministic graders score the final state in the 0.0–1.0 range for easy,
            medium, and hard tasks.
          </p>
          <p>
            This gives the environment both learning signal and evaluation signal, which is exactly what the
            hackathon rubric asks for.
          </p>
        </article>

        <article className="about-card reveal" style={{ animationDelay: "0.24s" }}>
          <p className="section-label">How to demo it</p>
          <h2>Backend, frontend, and baseline</h2>
          <p>
            The FastAPI backend exposes /reset, /step, /state, /grade, and /api/tasks. The React frontend is a
            judge-facing console that visualizes the live episode. The inference script uses the OpenAI client
            against a Hugging Face-compatible endpoint, reading API_BASE_URL, MODEL_NAME, and HF_TOKEN from the
            environment.
          </p>
          <p>
            That setup keeps secrets out of the browser and makes the baseline reproducible across local runs,
            Docker, and HF Spaces.
          </p>
        </article>
      </div>
    </section>
  );
}

export default AboutPage;