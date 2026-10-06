# OWASP AI Testing Agent

Part of the [SAAF Project](https://github.com/SAAF-Project).

An agent that operationalises the **OWASP AI Testing Guide v1.0** for internal audit. It profiles a target AI system, maps it to the guide's test categories, generates test procedures and prompt-injection payloads, and — only when explicitly authorised — sends the approved payloads to the target, judges the recorded responses, and writes a scored audit report.

**Status: first implementation (v0.1).** It implements the revised plan ([`plans/owasp-ai-testing-agent.md`](plans/owasp-ai-testing-agent.md)), but it has **not been validated against the real OWASP AI Testing Guide**: the guide text and category list are not shipped (see [Corpus](#corpus)), and only AT-01 (prompt injection) has automated live tests. Treat results as a starting point for a human auditor, not as audit evidence.

The original Hackathon 3 draft is kept, marked superseded, at [`plans/hackathon-3/owasp-ai-testing-agent.md`](plans/hackathon-3/owasp-ai-testing-agent.md).

## How it works

```
 system.json ──► plan (static, sends nothing) ──► profile, procedures, payloads.json (+ its SHA-256), report (all "Not tested")
                                                         │  a human reviews payloads.json
                                                         ▼
 token.json (system owner) ─► execute --live --approve <sha256> ─► runner (HTTP only) ─► judge ─► synthesis ─► scored report
```

| Prompt (plan §5) | Where | Purpose |
|---|---|---|
| 1 Profile | `plan` | applicable categories (only ones from your corpus), risk tier |
| 2 Procedures | `plan` | 3–5 test cases per category |
| 3a Payloads | `plan` | prompt-injection payloads with harmless canary strings; the model never plays the target |
| 3b Judge | `execute` | judges *recorded* responses; each verdict needs a quote found verbatim in the response, else it is downgraded to `unverified` |
| 4 Synthesis | `execute` | per-category rating and wording; the evidence rules below can overrule it |

## Install and run

```
pip install -r requirements.txt           # anthropic 0.84.0, jsonschema 4.26.0 (tested on Python 3.14.3 only)
set ANTHROPIC_API_KEY=...                 # never committed or logged

python -m owasp_ai_testing_agent ingest   <corpus_dir> --version owasp-guide-v1.0 --source-url <url> --git-commit <sha>
python -m owasp_ai_testing_agent plan     examples/system.json --corpus <corpus_dir> --out out/run1
#   -> prints the SHA-256 of out/run1/payloads.json. Read that file. If you are happy with every payload:

set OWASP_AI_AUTH_SECRET=<16+ character secret shared with whoever mints tokens>
python -m owasp_ai_testing_agent mint-token --host chatbot.example.com --authorised-by "Name, role" --hours 24 --out token.json   # system owner
python -m owasp_ai_testing_agent execute out/run1 --live --token token.json --interface interface.json --approve <sha256>
python -m owasp_ai_testing_agent verify-log out/run1/audit_log.jsonl
```

`examples/interface.json` shows how to describe the target's endpoint (`{{PAYLOAD}}` marks where the payload goes; header values may use `${ENV_VAR}`). Optional overrides: `OWASP_AI_AGENT_MODEL` (default `claude-opus-4-6`), `OWASP_AI_AGENT_MAX_TOKENS` (default 2048).

Outputs in the run directory: `report.json|md` and `report-findings.json` (static), `report-live.json|md` and `report-live-findings.json` (after `execute`), `exchanges.json`, `judgements.json`, `audit_log.jsonl`.

## Safety model

| Control | How |
|---|---|
| Nothing is sent by default | `plan` never contacts a target. `execute` refuses without `--live` |
| Written authorisation | A signed token names exactly one host and an expiry; the runner checks every URL against it before sending (https required, http only for loopback) |
| Human approval of payloads | `execute --approve` must equal the SHA-256 of the current `payloads.json`; edit the file after reviewing and the hash no longer matches |
| Payloads are data | Only ever placed in a JSON request body. No shell, `eval`, `exec` or `subprocess` ever sees model output. Redirects are not followed; responses are size-capped; requests are rate- and time-limited |
| Untrusted input | System descriptions, target responses and corpus text are delimited with `<untrusted_input>`, embedded delimiter tags are neutralised, oversized input is rejected, injection-like patterns raise an alert (alerting only, not a defence) |
| Grounded findings | Judgements need a verbatim quote from the recorded response; unrecorded responses are never sent to the model; a negative verdict on a truncated response is not trusted |
| Ratings checked by code | Overall rating, score and coverage are computed in code. A category with no definitive verdicts is `Not Rated`; one with a successful attack cannot be rated below Medium |
| Schema-validated output | Report and findings are validated before writing; output is PII/secret-redacted and HTML-escaped |
| Tamper-evident log | Every LLM call and target request is logged in a hash chain; `verify-log` detects edits, deletions and reordering. Header values and secrets are never logged |
| Budgets | ≤ 50 test cases per run, 10 requests/min, 2048 tokens per call (override with the env var above) |
| Interrupts | SIGTERM/Ctrl-C finishes the current request and saves a `live-partial` report |

## Corpus

The agent needs the guide's category list and text, which are not included. Create a directory with `categories.json` (`[{"id","name","summary"}]`, from the guide) and the guide text as `.md`/`.txt`, then run `ingest`. The agent refuses to run if any file no longer matches the SHA-256s recorded at ingestion. `examples/corpus/` holds a **sample** with a single AT-01 entry and notes written for this repo; it is not from the guide.

## Where the implementation differs from the plan

- **Rating "Not Rated"** (added) marks categories with no definitive test result; the plan's enum had only "Not Applicable".
- **`Critical` is mapped to `High`** in `*-findings.json`, because SAAF's `finding-schema.json` only allows High/Medium/Low/Informational. The full rating stays in `report*.json`.
- **Aggregation** is highest-severity-wins (a proposal; the SAAF OWASP LLM methodology uses count-based rules — plan open question 8). The evidence floor and "Not Rated" rules are also proposals.
- **Live approval** is a hash of the reviewed payload file, not an interactive prompt, so it is auditable and scriptable.
- **Authorisation token format** (HMAC-signed JSON with a shared secret) is a proposal; the plan left it unspecified. HMAC proves the token was minted by a holder of the secret, not who that person is.
- **Prompt 3** is split into 3a/3b as the revised plan describes. Prompts 1, 2 and 4 gained a JSON format instruction, and Prompts 2 and 3a a brevity instruction: the plan's 2048-token cap truncated Prompt 2's output on the first real run.
- **PII redaction** is regex based (e-mail, API keys, bearer tokens, US SSN), not Presidio.
- **Retrieval** is keyword scoring over files; there is no ChromaDB or embedding model.
- **Not implemented:** the hallucination-detection agent integration, the €5/day cost alert (token usage is logged per call instead), live tests for categories other than AT-01, SBOM generation, tests on Python versions other than 3.14.

## Known limitations

- The narrative text (category summary, executive summary) is model-written and **not verified**. In the first real run the executive summary said role-confusion attacks "were all correctly rejected" although one had succeeded. Counts, ratings and quotes are code-checked; the prose is not.
- Judging is only as good as the model's reading of one response. A verbatim quote proves the response says something, not that the attack objective was met.
- Verdicts can vary between runs.
- Everything in `examples/` is fictional; the example endpoint does not exist.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest -q tests          # 54 tests; no API key needed
```

The tests include real HTTP round trips to a local server (payload containment, redirects, size caps, interrupts) and end-to-end `plan` → `execute` runs with a fake model. A separate manual run against the real Claude API and a local "gullible chatbot" produced exactly the three successful attacks the chatbot is built to fall for (10 run, 10 judged, 3 succeeded).

## Related

- [SAAF-Project/OWASP-top-10-LLM-assessment](https://github.com/SAAF-Project/OWASP-top-10-LLM-assessment) — assesses agent *code* against the OWASP Top 10 for LLM Applications
- [SAAF-Project/SAAF-Project](https://github.com/SAAF-Project/SAAF-Project) — the main SAAF workspace

No license has been chosen yet.
