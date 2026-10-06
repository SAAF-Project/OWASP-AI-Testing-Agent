# OWASP AI Testing Agent

Part of the [SAAF Project](https://github.com/SAAF-Project).

An agent that operationalises the **OWASP AI Testing Guide v1.0** for internal audit: it profiles a target AI system, maps it to the guide's test categories, generates test procedures (and, in opt-in live mode, runs prompt injection tests against an authorised endpoint), and produces a scored OWASP AI security audit report with per-category findings.

## Status: plan only, not built

This repository currently contains the design, nothing else. There is no code to run yet. The plan is a **Draft** (PDCA "Do" phase pending), and its OWASP LLM control table records planned mitigations, not implemented ones.

- Plan (revised, current): [`plans/owasp-ai-testing-agent.md`](plans/owasp-ai-testing-agent.md) — includes the fixes from a review; see its section 14
- Plan (original Hackathon 3 draft, unmodified): [`plans/hackathon-3/owasp-ai-testing-agent.md`](plans/hackathon-3/owasp-ai-testing-agent.md) — kept for reference; it marks every OWASP LLM control PASS and has the issues the revised plan fixes

## What it will do

| Aspect | Design |
|---|---|
| **Input** | A description of the AI system under test (model, deployment context, data inputs, API exposure) |
| **Output** | Scored audit report (JSON + Markdown), per-category findings (`F-<category_id>`, e.g. `F-AT-01`), remediation priority matrix |
| **Default mode** | Static: generates test procedures and scripts; sends nothing to any target |
| **Live mode** | Opt-in: requires `--live`, a written authorisation token naming the target host, and human approval of the payload set |
| **Overall rating** | Proposed: highest-severity-wins across categories, with the weighted average as a secondary score only. Differs from the count-based rules of the SAAF OWASP LLM methodology; undecided (plan open question 8) |
| **Human oversight** | A human auditor must sign off before a report is treated as final |

## Open questions

The plan lists the decisions still to make (category list, model choice, dependency pins, live-test authorisation format). See section 12 of the plan.

## Related

- [SAAF-Project/OWASP-top-10-LLM-assessment](https://github.com/SAAF-Project/OWASP-top-10-LLM-assessment) — assesses agent code against the OWASP Top 10 for LLM Applications
- [SAAF-Project/SAAF-Project](https://github.com/SAAF-Project/SAAF-Project) — the main SAAF workspace, including the related plans referenced from the plan

No license has been chosen yet.
