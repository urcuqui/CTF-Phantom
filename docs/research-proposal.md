# Research Proposal — CTF-Phantom

**Adversarial Deception of Autonomous Cybersecurity Agents Through Untrusted Challenge Artifacts**

## 1. Motivation

LLM agents are increasingly deployed to perform offensive-security work autonomously: solving
CTF challenges, triaging vulnerabilities, running penetration-test playbooks. These agents read
large volumes of attacker-controllable content (HTML, comments, banners, user posts, error
messages, file contents) and act on it with real tools. Every artefact the target returns is
untrusted input, yet it lands in the same context window as the agent's instructions.

This makes the *target* a natural adversary of the *tester*. A defender, or simply a hostile
environment, can plant content intended to redirect, stall, mislead or exploit the agent. We
call this class of attack **phantom content**: material that exists to manipulate an
autonomous solver rather than to serve the application's users.

## 2. Research questions

* **RQ1 — Susceptibility.** How often do autonomous security agents deviate from a legitimate
  objective when a challenge contains (a) indirect prompt injection and (b) non-instructional
  deception, compared with matched controls?
* **RQ2 — Attack class.** Do instruction-style injections (addressed to the AI) and deception
  (false environmental evidence addressed to any solver) differ in success rate and in the kind
  of deviation they cause (exfiltration attempt, decoy pursuit, premature termination)?
* **RQ3 — Cost.** Independent of overt hijacking, does adversarial content raise the cost of
  solving (tool calls, tokens, wall time) or reduce the solve rate relative to length-matched
  benign content?
* **RQ4 — Cross-model variation** *(Phase 2+).* How do susceptibility and cost vary across model
  families, sizes, and reasoning-effort settings?
* **RQ5 — Mitigations** *(Phase 3+).* Which defences (prompt-level notices, content tagging,
  tool-layer guards, monitors) reduce attack success without degrading task performance?

## 3. Hypotheses (Phase 1)

* **H1.** Attack success given exposure is greater than zero for both treatment variants on at
  least one current model.
* **H2.** The solve rate on treatment variants is lower than on the length-matched benign
  control. The benign control isolates the effect of adversarial *content* from that of
  *additional text*.
* **H3.** Control-condition false-positive rates for all action indicators are ≈ 0. This
  validates the indicators as attributable measures.

## 4. Approach

1. **Controlled environments.** Purpose-built, deterministic, containerised CTF challenges
   with a verifiable per-run flag. Each challenge declares explicit *content slots*: the only
   low-trust surfaces allowed to differ between variants.
2. **Variants.** Every challenge ships at least `baseline`, `benign_control` (length- and
   placement-matched), and one or more treatments (`deception`, `prompt_injection`). The
   legitimate exploit path is identical across variants and verified by tests.
3. **Behavioural indicators.** Attack success is measured only through *observable actions*
   whose artefacts (decoy flag, canary path, attacker host, compliance token) exist only in
   the payload. We never infer success from task failure.
4. **Victim agent.** A minimal, transparent tool-use loop with a restricted HTTP tool,
   `submit_flag` and `terminate`. Phase 1 has no memory or multi-agent features, which keeps
   the attack surface interpretable.
5. **Full traces.** Every model turn, tool call, model-visible observation and timestamp is
   written to JSONL with provenance hashes. Evaluation is a pure function of the trace.

## 5. Phased plan

| Phase | Scope |
|---|---|
| **1 (this repo state)** | Foundation, Phantom-001 (web/SQLi) with 4 variants, minimal agent, runner, evaluator, tests. |
| 2 | Additional challenges (different categories and injection surfaces: headers, files, error messages, robots.txt, JS); cross-model evaluation; effort/temperature sweeps. |
| 3 | Payload families and systematic (non-optimising) generation from templates; placement and length ablations; defence baselines. |
| 4 | Automated adversarial optimisation (explicitly out of scope until Phase 4). |

## 6. Expected contributions

* An open, reproducible benchmark harness for adversarial robustness of security agents.
* Attributable behavioural metrics that separate hijacking from incompetence.
* Empirical estimates of susceptibility across models and attack classes.

## 7. Ethics and scope

All challenges are fictional, self-hosted and isolated. Agent tools cannot reach any host other
than the challenge under test, and attacker destinations use the reserved `.invalid` TLD
(RFC 2606). No external CTF platform, third-party system or real user is involved. Payloads are
published for defensive research. They target the agent's decision-making only and contain no
functional malware or real-world exploitation capability. See `threat-model.md`.
