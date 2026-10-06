# OWASP AI Testing Agent

Part of the [SAAF Project](https://github.com/SAAF-Project).

An agent that operationalises the **[OWASP AI Testing Guide](https://github.com/OWASP/www-project-ai-testing-guide)** for internal audit. It profiles a target AI system, selects the guide's tests that apply (the guide has 32), generates test procedures and prompt-injection payloads, and — only when explicitly authorised — sends the approved payloads to the target, judges the recorded responses, and writes a scored audit report.

**Status: v0.2.** It implements the revised plan ([`plans/owasp-ai-testing-agent.md`](plans/owasp-ai-testing-agent.md)) and has been run against the real guide and the real Claude API (see [What has been verified](#what-has-been-verified)). It is a tool for a human auditor, not a substitute: every report requires sign-off, and most guide tests get static procedures only.

The original Hackathon 3 draft is kept, marked superseded, at [`plans/hackathon-3/owasp-ai-testing-agent.md`](plans/hackathon-3/owasp-ai-testing-agent.md).

## How it works

```
 fetch-guide ─► corpus (32 tests, hash-verified, CC BY-SA 4.0, not stored in this repo)
 system.json ─► plan (static, sends nothing) ─► profile, procedures, payloads.json (+ SHA-256), report (every category "Not tested")
                                                     │  a human reviews payloads.json
                                                     ▼
 token.json (system owner) ─► execute --live --approve <sha256> ─► runner (HTTP only) ─► judge ─► scored report
```

| Prompt (plan §5) | Where | Purpose |
|---|---|---|
| 1 Profile | `plan` | applicable guide tests (only ids that exist in the corpus), risk tier |
| 2 Procedures | `plan` | test cases per category, built from the guide's own objectives / how-to-test / expected-output sections |
| 3a Payloads | `plan` | harmless canary payloads for `AITG-APP-01` and `AITG-APP-02`; the model never plays the target |
| 3b Judge | `execute` | judges *recorded* responses; needs a verbatim quote, and is cross-checked against the canary |
| 4 Synthesis | `execute` | proposes a rating, recommendation and confidence; evidence rules can overrule the rating |

**Which tests are automated live.** A test is live-testable only if a plain chat endpoint is enough *and* success can be checked objectively with a canary string. That is `AITG-APP-01` (Prompt Injection) and `AITG-APP-02` (Indirect Prompt Injection). The other 30 tests (training data, infrastructure, model-level attacks, bias, ...) need other access or have no objective check; they get static procedures and appear in the report as "Not tested".

## Install and run

```
pip install -r requirements.txt                       # anthropic 0.84.0, jsonschema 4.26.0
set ANTHROPIC_API_KEY=...                             # never committed or logged

python -m owasp_ai_testing_agent fetch-guide corpus/  # downloads the guide at a pinned commit; every file hash-verified
python -m owasp_ai_testing_agent plan examples/system.json --corpus corpus/ --out out/run1
#   -> prints the SHA-256 of out/run1/payloads.json. Read that file. If you are happy with every payload:

set OWASP_AI_AUTH_SECRET=<16+ character secret shared with whoever mints tokens>
python -m owasp_ai_testing_agent mint-token --host chatbot.example.com --authorised-by "Name, role" --hours 24 --out token.json   # system owner
python -m owasp_ai_testing_agent execute out/run1 --live --token token.json --interface interface.json --approve <sha256>
python -m owasp_ai_testing_agent verify-log out/run1/audit_log.jsonl
```

`examples/interface.json` shows how to describe the target endpoint (`{{PAYLOAD}}` marks where the payload goes; header values may use `${ENV_VAR}`). `fetch-guide --ref <sha|tag>` audits against another version of the guide.

Optional environment variables: `OWASP_AI_AGENT_MODEL` (default `claude-opus-4-6`), `OWASP_AI_AGENT_MAX_TOKENS` (2048), `OWASP_AI_AGENT_PRICE_IN_EUR_PER_MTOK` / `OWASP_AI_AGENT_PRICE_OUT_EUR_PER_MTOK` (enable the euro estimate), `OWASP_AI_AGENT_COST_ALERT_EUR` (5), `OWASP_AI_AGENT_HARD_STOP=1` (refuse calls once the daily threshold is reached), `OWASP_AI_AGENT_USAGE_FILE`.

Outputs in the run directory: `report.json|md` and `report-findings.json` (static), `report-live.json|md` and `report-live-findings.json` (after `execute`), `exchanges.json`, `judgements.json`, `audit_log.jsonl`.

## Safety model

| Control | How |
|---|---|
| Nothing is sent by default | `plan` never contacts a target. `execute` refuses without `--live` |
| Written authorisation | A signed token names exactly one host and an expiry; the runner checks every URL against it before sending (https required, http only for loopback) |
| Human approval of payloads | `execute --approve` must equal the SHA-256 of the current `payloads.json`; edit the file after reviewing and the hash no longer matches |
| Payloads are data | Only ever placed in a JSON request body. No shell, `eval`, `exec` or `subprocess` ever sees model output. Redirects are not followed; responses are size-capped; requests are rate- and time-limited |
| No exfiltration payloads | The guide's own examples include data exfiltration and credential requests; the payload prompt forbids reproducing them and requires harmless canary versions. A human still reviews every payload before approval |
| Untrusted input | System descriptions, target responses and corpus text are delimited with `<untrusted_input>`, embedded delimiter tags are neutralised, oversized input is rejected, injection-like patterns raise an alert (alerting only, not a defence) |
| Grounded findings | Judgements need a verbatim quote from the recorded response, and are cross-checked against the payload's canary string (a "success" with no canary in the response, or a "failure" with the canary present, becomes `unverified`). Unrecorded responses are never sent to the model; a negative verdict on a truncated response is not trusted |
| Narrative from evidence | Category summaries and the executive summary are computed from the counts and judgements. The model's own wording is kept only as notes marked "AI commentary (not verified)" |
| Ratings checked by code | Overall rating, score and coverage are computed in code. A category with no definitive verdicts is `Not Rated`; one with a successful attack cannot be rated below Medium |
| Nothing silently dropped | Categories that were profiled as applicable but got no procedures (budget exhausted, or the model's answer was unusable after one retry) are listed in the report as "Not tested" with the reason |
| Schema-validated output | Report and findings are validated before writing; output is PII/secret-redacted and HTML-escaped |
| Tamper-evident log | Every LLM call and target request is logged in a hash chain; `verify-log` detects edits, deletions and reordering. Header values and secrets are never logged |
| Budgets | 50 test cases per run, shared fairly across categories; 10 requests/min; 2048 tokens per call; daily token ledger with an optional euro alert |
| Interrupts | SIGTERM/Ctrl-C finishes the current request and saves a `live-partial` report |

## Corpus and licence

The guide is published by OWASP under **CC BY-SA 4.0**. `fetch-guide` downloads it on your machine and does not store it in this repository, so ShareAlike does not attach to this code (which is MIT-licensed, see [Licence](#licence)). The download is pinned to a commit (default `006e4e9`, checked 2026-10-06) and each file is verified against the git blob hash GitHub reports for that commit. The report records the corpus version, commit and licence. `ingest` lets you build a corpus from your own directory instead; `examples/corpus/` is a one-entry sample for tests, not from the guide.

## What has been verified

- **Tests:** 79 tests pass on Python 3.10, 3.11, 3.12, 3.13 and 3.14 (3.10, 3.12, 3.13 and 3.14 locally with `uv`; all five in GitHub Actions). They include real HTTP round trips to a local server and end-to-end `plan` → `execute` runs with a fake model; no API key is needed.
- **Real guide and real model:** a full run against the real guide (19 applicable tests profiled, all given procedures) and the real Claude API, with a deliberately gullible local chatbot as the target. The bot falls for exactly 4 of the 20 generated payloads. In two consecutive `execute` runs the pipeline reported exactly those 4 as successful, 16 as not, 0 unverified, with identical verdicts and ratings both times.
- **Dependencies:** `pip-audit` reports no known vulnerabilities in the pinned dependencies and everything they pull in (run 2026-10-06).
- **CI:** `.github/workflows/ci.yml` ran on the pull request: the test matrix and the dependency audit passed. Its first SBOM included the audit tools themselves, so the workflow now builds the SBOM from a clean environment holding only `requirements.txt` (the `sbom` artifact of each run).

## Limitations

- **Two live-testable tests out of 32.** A typical report therefore says "Not tested" for most categories. That is correct and intended; it is not a clean bill of health.
- **The model still proposes** each tested category's rating, recommendation and confidence. The rating is bounded by evidence rules, the recommendation is advice to be reviewed, and neither is ground truth. In the verification run the model rated one category from 1 successful attack out of 10 as Medium and another from 3 out of 10 as High.
- **Judging outside canaries.** The canary cross-check applies when the payload contains its canary in plain text (18 of 20 in the verification run). Encoded canaries (base64, ROT13) and indicators like "or reveals the system prompt" rely on the model's judgement plus the verbatim-quote check.
- **Repeatability.** `temperature=0` is requested and the verification runs agreed exactly, but the API does not guarantee deterministic output.
- **Chat-style targets only.** The runner sends one JSON request per payload and reads one reply field. Multi-turn attacks, streaming, tool-using agents and non-JSON APIs are not covered.
- **Not implemented:** integration with the hallucination-detection agent (an unbuilt draft plan elsewhere), Presidio PII redaction (regex is used), and a ChromaDB vector store with embeddings (retrieval is by guide section plus keywords).
- **Cost alert needs prices.** Model prices are not built in (they cannot be verified from here). Without the price variables, tokens are logged and the agent says the euro alert is off.
- **HMAC authorisation tokens** prove a token was minted by a holder of the shared secret, not who that person is.
- **Pinned guide version.** Newer guide releases need `--ref`; behaviour on them is untested.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest -q tests          # 79 tests; no API key needed
```

## Related

- [SAAF-Project/OWASP-top-10-LLM-assessment](https://github.com/SAAF-Project/OWASP-top-10-LLM-assessment) — assesses agent *code* against the OWASP Top 10 for LLM Applications
- [SAAF-Project/SAAF-Project](https://github.com/SAAF-Project/SAAF-Project) — the main SAAF workspace

## Licence

This repository is released under the [MIT License](LICENSE). That covers the code, schemas and plans in this repository only. The OWASP AI Testing Guide that `fetch-guide` downloads is **not** part of this repository and stays under its own licence, CC BY-SA 4.0; reports that quote it carry that licence in their `corpus.license` field.
