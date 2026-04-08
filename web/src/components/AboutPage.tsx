function AboutPage() {
  return (
    <section className="page page-about">
      <div className="about-grid">
        <article className="about-card reveal">
          <p className="section-label">About The Project</p>
          <h2>SOC OpenEnv</h2>
          <p>
            SOC OpenEnv is a simulation-driven security operations environment where AI agents practice
            triage, investigation, and containment workflows in realistic incident scenarios.
          </p>
          <p>
            It combines deterministic grading, reproducible tasks, and operational constraints so teams can
            benchmark model quality and response behavior with confidence.
          </p>
          <p>
            Reward behavior: positive reward is given for useful investigative and containment actions, negative
            reward is applied for false-positive containment and invalid actions, and neutral reward appears when
            actions produce little net effect. Each step score is clipped between -1.0 and 1.0.
          </p>
        </article>

        <article className="about-card reveal" style={{ animationDelay: "0.14s" }}>
          <p className="section-label">About The Users</p>
          <h2>Who Uses It</h2>
          <p>
            Security researchers use it to evaluate autonomous defenders, SOC engineers use it to test playbook
            logic, and AI teams use it to compare model safety and containment decisions.
          </p>
          <p>
            It is also useful for learners building practical intuition around alert quality, false positive
            handling, and attack-chain context across enterprise systems.
          </p>
        </article>
      </div>
    </section>
  );
}

export default AboutPage;
