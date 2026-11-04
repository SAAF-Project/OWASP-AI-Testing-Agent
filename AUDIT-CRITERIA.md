# AUDIT-CRITERIA.md — OWASP AI Testing Agent

> What this agent must be judged against as an auditee: its control objectives, testable acceptance criteria and known limits. The [README](README.md) says what the agent does and how to run it. This file follows the SAAF A2 template (`docs/conventions/audit-criteria-template.md` in the main SAAF-Project repo).
>
> **Draft scaffold.** The 2026-11 SAAF standards audit created this file. Facts were taken only from this repository (README, code, tests, plans). Everything else is marked `TODO(owner)`. The control objectives are *candidates* that the owner must confirm, change or delete.

---

## Metadata

| Field | Value |
|---|---|
| **Agent** | OWASP AI Testing Agent |
| **Repository** | https://github.com/SAAF-Project/OWASP-AI-Testing-Agent |
| **Maintainer(s)** | TODO(owner): name the maintainer(s). The plan's submitter is Mathijs Schouten (`plans/owasp-ai-testing-agent.md`). |
| **Last reviewed** | TODO(owner): YYYY-MM-DD |
| **Status** | Draft |

**Does this agent make model calls?** Yes. It calls the Anthropic Claude API (default model `claude-opus-4-6`, set by `OWASP_AI_AGENT_MODEL`) for profiling, procedures, payloads, judging and synthesis (README, "How it works"). AI-specific frameworks therefore apply.

## 1. What the agent does

The agent operationalises the OWASP AI Testing Guide for internal audit. Input is a JSON description of a target AI system (`examples/system.json`) and a hash-verified copy of the guide (`fetch-guide`). Output is a static `plan` with a profile, test procedures and prompt-injection payloads (`payloads.json`). Only when a system owner has issued a signed token and an auditor has approved the payload hash does `execute --live` send the payloads to a chat endpoint. It then judges the recorded responses and writes a scored report (`report-live.json|md`, `report-live-findings.json`) and a tamper-evident `audit_log.jsonl`. It supports the audit task of testing an AI system against the guide. Only `AITG-APP-01` and `AITG-APP-02` are tested live; the other 30 guide tests get static procedures.

## 2. Control objectives & framework mapping (≥3)

| Control objective | Framework + clause/area | Why relevant |
|---|---|---|
| CO-1 — Nothing is sent to a target system without written authorisation for that host and human approval of the exact payloads. TODO(owner): candidate proposed by the 2026-11 standards audit — confirm, change or delete | EU AI Act Art. 14 (human oversight) | The agent sends attack payloads to a live system; that must stay a human decision (README, "Safety model"). |
| CO-2 — Every finding is grounded in recorded evidence (a verbatim quote from the target response, cross-checked against the canary), and ratings are bounded by rules in code. TODO(owner): candidate proposed by the 2026-11 standards audit — confirm, change or delete | OWASP Top 10 for LLM Applications 2025 — LLM09 Misinformation | A model-judged finding that is not tied to evidence could mislead the auditor. |
| CO-3 — Every LLM call and target request can be reconstructed afterwards from a tamper-evident log, and secrets are never logged. TODO(owner): candidate proposed by the 2026-11 standards audit — confirm, change or delete | EU AI Act Art. 12 (record-keeping), used as a benchmark; ISO/IEC 27001:2022 Annex A 8.15 (logging) | An audit test must be re-performable and its log trustworthy. |

TODO(owner): add or replace objectives. *Framework menu: `docs/reference/domains-and-frameworks.md` in SAAF-Project.*

## 3. Acceptance criteria (testable, pass/fail)

The criteria below restate behaviour that the README documents. TODO(owner): confirm each one and add any that are missing.

**CO-1**
- Given `execute` without `--live`, the agent sends nothing to the target.
- Given a `payloads.json` changed after approval, so that its SHA-256 differs from `--approve`, the live run is refused.
- Given a token that is missing, tampered with, expired, or issued for another host, no request is sent.
- Given a redirect from the target, the runner does not follow it.

**CO-2**
- Given a judgement without a verbatim quote from the recorded response, it is not accepted as a definitive verdict.
- Given a "success" verdict whose response lacks the payload's canary, or a "failure" whose response contains it, the verdict becomes `unverified`.
- Given a category with no definitive verdicts, it is rated `Not Rated` and raises no SAAF finding.
- Given a category profiled as applicable but without procedures, the report lists it as "Not tested" with the reason.

**CO-3**
- Given an `audit_log.jsonl` with an edited, deleted or reordered line, `verify-log` reports the break.
- Given request headers that use `${ENV_VAR}` values, those values do not appear in any log or output.
- Given a completed run, the log holds one `llm_call` record per model call (purpose, model, token counts, stop reason) and one `target_request` record per payload sent.

## 4. Good output / never do

| A correct output MUST contain | The agent must NEVER |
|---|---|
| ✓ The corpus version, commit and licence of the guide used | ✕ Send payloads without `--live`, a valid token and a matching approval hash |
| ✓ "Not tested" for every category without live evidence, with the reason | ✕ Report a category as tested or rated without definitive verdicts |
| ✓ A verbatim quote from the recorded response behind every live verdict | ✕ Reproduce the guide's data-exfiltration or credential-request examples as real payloads |
| ✓ Findings in `report-live-findings.json` validated against `schemas/finding-schema.json` | ✕ Present the report as audit-ready without auditor sign-off |
| ✓ Model wording marked "AI commentary (not verified)" | ✕ Pass payloads or model output to a shell, `eval`, `exec` or `subprocess` |
| ✓ A human sign-off before the report is used | ✕ Hard-code credentials, or log header values or secrets |

Note on `outputs/schemas/finding-schema.json`: the agent emits finding IDs of the form `F-<category id>` (`owasp_ai_testing_agent/report.py:51`). The SAAF schema requires `F-\d{2,4}`, and the local copy in `schemas/finding-schema.json` has no ID pattern. TODO(owner): align the IDs or document the deviation.

## 5. Coverage gaps

From the README "Limitations" section:

- Only 2 of the guide's 32 tests run live (`AITG-APP-01`, `AITG-APP-02`). Most categories are "Not tested", which is not a clean bill of health.
- The model still proposes each tested category's rating, recommendation and confidence. Code bounds these, but they are not ground truth.
- Encoded canaries (base64, ROT13) and indicator-style checks rely on the model's judgement plus the verbatim-quote check.
- Repeatability is not guaranteed: `temperature=0` is requested, but the API does not guarantee deterministic output.
- Chat-style JSON targets only. Multi-turn attacks, streaming, tool-using agents and non-JSON APIs are not covered.
- HMAC tokens prove that a token was minted by a holder of the shared secret, not who that person is.
- Behaviour on guide versions other than the pinned commit is untested.
- TODO(owner): add gaps an auditor would expect (for example, data protection of target responses held in `exchanges.json`).

## 6. Status / validation

The README states that 79 tests pass on Python 3.10–3.14 and that one real-model verification run took place. The 2026-11 standards audit did **not** re-run them. The tests named below exist in `tests/`.

| Acceptance criterion | Verified? | Evidence |
|---|---|---|
| CO-1 — refused when payloads changed after approval | ☐ | `tests/test_pipeline.py::test_live_run_is_refused_when_payloads_changed_after_approval` — TODO(owner): confirm |
| CO-1 — refused with a bad token / unauthorised host | ☐ | `tests/test_pipeline.py::test_live_run_is_refused_with_a_bad_token`, `tests/test_live.py::test_runner_refuses_an_unauthorised_host_before_sending` — TODO(owner): confirm |
| CO-1 — redirects not followed | ☐ | `tests/test_live.py::test_runner_does_not_follow_redirects` — TODO(owner): confirm |
| CO-2 — verbatim quote required | ☐ | `tests/test_live.py::test_judgement_needs_a_verbatim_quote` — TODO(owner): confirm |
| CO-2 — unrated categories raise no finding | ☐ | `tests/test_live.py::test_unrated_categories_raise_no_finding` — TODO(owner): confirm |
| CO-3 — log tampering detected | ☐ | `tests/test_foundations.py::test_audit_log_detects_edit_deletion_and_reorder` — TODO(owner): confirm |
| CO-3 — env header values never logged | ☐ | `tests/test_live.py::test_runner_expands_env_headers_but_never_logs_them` — TODO(owner): confirm |
| Real-model behaviour | ☐ | README "What has been verified" describes one run against a local gullible chatbot. TODO(owner): link the evidence |

## 7. Observability

**Logged today** (from `owasp_ai_testing_agent/audit_log.py`, `llm.py`, `runner.py`, `pipeline.py`): a hash-chained `audit_log.jsonl` per run directory with events such as `plan_start`, `plan_done` (payload SHA-256), `live_start` (target host, authorised by), `live_refused`, `llm_call` (purpose, model, input/output tokens, stop reason, temperature), `target_request`, `rating_adjusted`, `injection_pattern_detected`, `cost_alert` and `run_interrupted`. A daily token ledger records model and token counts. Target responses and judgements are written to `exchanges.json` and `judgements.json`. Header values and secrets are not logged.

**Missing / limits:** the log is tamper-*evident*, not tamper-proof; someone with write access can rewrite the whole file (`audit_log.py` docstring). The `llm_call` record does not include the prompt text or the raw model response. TODO(owner): confirm, and list any further gaps (retention of run directories, central log shipping).
