"""The audit pipeline (plan sections 3, 5, 6).

    plan     static mode (default): profile the system, generate test procedures and payloads, write a
             report in which every category is 'Not tested'. Nothing is sent to any target.
    execute  live mode: send a human-approved payload set to the authorised endpoint, judge the
             recorded responses, synthesise and write the scored report.
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path

from . import aggregate, prompts
from .audit_log import AuditLog
from .authorisation import AuthorisationError, verify as verify_token
from .config import Config
from .corpus import Corpus
from .judge import judge
from .llm import LLM, ModelOutputError
from .report import CategoryResult, build_report, write_outputs
from .runner import Interface, Runner
from .sanitise import detect_injection

PROMPT_INJECTION = "AT-01"       # the only category with automated live tests
STATE_FILE = "plan_state.json"
TIERS = ("Low", "Medium", "High")


class PipelineError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_text(path: Path, config: Config) -> str:
    text = path.read_text(encoding="utf-8-sig")
    if len(text) > config.max_input_chars:
        raise PipelineError(f"{path} is {len(text)} characters; the limit is {config.max_input_chars}")
    return text


def _alert_injection(audit: AuditLog, where: str, text: str) -> None:
    found = detect_injection(text)
    if found:
        print(f"[alert] possible prompt-injection patterns in {where}: {', '.join(found)}", file=sys.stderr)
        audit.append("injection_pattern_detected", where=where, patterns=found)


def validate_profile(profile, corpus: Corpus, audit: AuditLog) -> dict:
    if not isinstance(profile, dict) or profile.get("risk_tier") not in TIERS:
        raise ModelOutputError("profile: expected an object with risk_tier Low/Medium/High")
    applicable, seen = [], set()
    for item in profile.get("applicable_categories", []):
        cid = item.get("id") if isinstance(item, dict) else None
        if cid not in {c.id for c in corpus.categories}:
            audit.append("profile_unknown_category_dropped", category=cid)
            continue
        if cid not in seen:
            seen.add(cid)
            applicable.append({"id": cid, "rationale": str(item.get("rationale", "")),
                               "executable": item.get("executable") if item.get("executable") in ("static", "live") else "static"})
    if not applicable:
        raise ModelOutputError("profile: no applicable category from the corpus")
    return {"risk_tier": profile["risk_tier"], "tier_rationale": str(profile.get("tier_rationale", "")),
            "unverified": [str(u) for u in profile.get("unverified", [])], "applicable_categories": applicable}


def validate_procedures(proc, category_id: str, config: Config) -> dict:
    # The model sometimes answers with a list of objects for the one category; merge those that match.
    items = [p for p in proc if isinstance(p, dict) and p.get("category_id", category_id) == category_id] \
        if isinstance(proc, list) else [proc] if isinstance(proc, dict) else []
    cases, evidence, objectives = [], [], []
    for item in items:
        objectives.append(str(item.get("objective", "")))
        evidence += [str(x) for x in item.get("evidence_to_collect", [])]
        for tc in item.get("test_cases", []):
            if isinstance(tc, dict) and all(isinstance(tc.get(k), str) and tc[k] for k in ("input", "pass_expected", "fail_expected")):
                cases.append({k: tc[k] for k in ("input", "pass_expected", "fail_expected")})
    if not cases:
        raise ModelOutputError(f"procedures for {category_id}: no valid test cases")
    return {"category_id": category_id, "objective": " ".join(o for o in objectives if o),
            "test_cases": cases[: config.max_cases_per_category],
            "evidence_to_collect": list(dict.fromkeys(evidence))}


def validate_payloads(raw, limit: int) -> list[dict]:
    if not isinstance(raw, list):
        raise ModelOutputError("payloads: expected a JSON list")
    out, ids = [], set()
    for item in raw:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k].strip()
                                                 for k in ("test_id", "payload", "success_indicator")):
            continue
        if item["test_id"] in ids:
            continue
        ids.add(item["test_id"])
        out.append({"test_id": item["test_id"], "technique": str(item.get("technique", "")),
                    "payload": item["payload"], "success_indicator": item["success_indicator"]})
    if not out:
        raise ModelOutputError("payloads: none were valid")
    return out[:limit]


def plan(system_path: Path, corpus_dir: Path, out_dir: Path, config: Config, *, auditor: str = "unspecified",
         max_payloads: int = 10, llm: LLM | None = None, audit: AuditLog | None = None) -> dict:
    """Static mode. Returns {'payloads_sha256': ..., 'paths': {...}}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    audit = audit or AuditLog(out_dir / "audit_log.jsonl")
    llm = llm or LLM(config, audit)
    corpus = Corpus.load(corpus_dir)
    system_text = _read_text(Path(system_path), config)
    _alert_injection(audit, "system description", system_text)
    audit.append("plan_start", system=str(system_path), corpus_version=corpus.version, mode="static")

    profile = validate_profile(
        llm.complete_json(prompts.PROFILE_SYSTEM,
                          prompts.profile_user(system_text, [{"id": c.id, "name": c.name} for c in corpus.categories],
                                               config.max_input_chars), "profile"),
        corpus, audit)

    procedures, budget = [], config.max_test_cases
    for item in profile["applicable_categories"]:
        if budget <= 0:
            audit.append("test_case_budget_exhausted", skipped=item["id"])
            continue
        cat = corpus.category(item["id"])
        chunks = corpus.retrieve(cat.id, config.rag_retrieval_limit, config.max_chunk_chars)
        proc = validate_procedures(
            llm.complete_json(prompts.PROCEDURES_SYSTEM,
                              prompts.procedures_user({"id": cat.id, "name": cat.name}, chunks, system_text,
                                                      profile["risk_tier"], config.max_input_chars),
                              f"procedures:{cat.id}"),
            cat.id, config)
        proc["test_cases"] = proc["test_cases"][:budget]
        budget -= len(proc["test_cases"])
        procedures.append(proc)

    payloads: list[dict] = []
    if any(p["category_id"] == PROMPT_INJECTION for p in procedures):
        n = min(max_payloads, config.max_test_cases)
        payloads = validate_payloads(
            llm.complete_json(prompts.payload_system(n), prompts.payload_user(system_text, "", config.max_input_chars),
                              "payloads"), n)

    paths = {"profile": out_dir / "profile.json", "procedures": out_dir / "procedures.json",
             "payloads": out_dir / "payloads.json", "state": out_dir / STATE_FILE}
    paths["profile"].write_text(json.dumps(profile, indent=2), encoding="utf-8")
    paths["procedures"].write_text(json.dumps(procedures, indent=2), encoding="utf-8")
    paths["payloads"].write_text(json.dumps(payloads, indent=2), encoding="utf-8")
    payloads_hash = _sha256_file(paths["payloads"])

    results = []
    for p in procedures:
        cat = corpus.category(p["category_id"])
        planned = len(payloads) if p["category_id"] == PROMPT_INJECTION else len(p["test_cases"])
        results.append(CategoryResult(cat.id, cat.name, tests_planned=planned,
                                      notes=["Static procedures generated; no test was executed."]))
    system_name = Path(system_path).stem
    state = {"system_name": system_name, "auditor": auditor, "risk_tier": profile["risk_tier"],
             "corpus_dir": str(Path(corpus_dir).resolve()), "corpus_version": corpus.version,
             "system_sha256": hashlib.sha256(system_text.encode("utf-8")).hexdigest(), "payloads_sha256": payloads_hash}
    paths["state"].write_text(json.dumps(state, indent=2), encoding="utf-8")

    summary = [f"Static run: {len(procedures)} categories profiled, {sum(len(p['test_cases']) for p in procedures)} test procedures generated.",
               f"{len(payloads)} prompt-injection payloads are ready for human review; nothing has been sent to any system.",
               "No category is rated until the live tests are run and a human auditor signs off."]
    report = build_report(system_name=system_name, auditor=auditor, mode="static", risk_tier=profile["risk_tier"],
                          categories=results, executive_summary=summary, corpus_manifest=corpus.manifest,
                          model=config.model)
    report_paths = write_outputs(out_dir, report)
    audit.append("plan_done", payloads_sha256=payloads_hash, categories=[p["category_id"] for p in procedures])
    return {"payloads_sha256": payloads_hash, "paths": {**paths, "report": report_paths[0], "report_md": report_paths[1]}}


def execute(out_dir: Path, token_path: Path, interface_path: Path, approved_sha256: str, config: Config, *,
            stop: threading.Event | None = None, llm: LLM | None = None, audit: AuditLog | None = None,
            runner_factory=Runner) -> dict:
    """Live mode. `approved_sha256` is the hash of payloads.json that a human reviewed and approved."""
    out_dir = Path(out_dir)
    audit = audit or AuditLog(out_dir / "audit_log.jsonl")
    state = json.loads((out_dir / STATE_FILE).read_text(encoding="utf-8"))
    payloads_path = out_dir / "payloads.json"
    actual = _sha256_file(payloads_path)
    if actual != approved_sha256:
        audit.append("live_refused", reason="payload hash mismatch", approved=approved_sha256, actual=actual)
        raise PipelineError("payloads.json does not match the approved hash; review the file and approve its current hash")
    try:
        auth = verify_token(json.loads(Path(token_path).read_text(encoding="utf-8-sig")))
    except AuthorisationError as exc:
        audit.append("live_refused", reason=str(exc))
        raise
    payloads = json.loads(payloads_path.read_text(encoding="utf-8-sig"))  # a human may have edited it
    if not payloads:
        raise PipelineError("there are no payloads to run")

    llm = llm or LLM(config, audit)
    corpus = Corpus.load(state["corpus_dir"])
    runner = runner_factory(Interface.load(interface_path), auth, config, audit)
    audit.append("live_start", target_host=auth.target_host, authorised_by=auth.authorised_by,
                 payloads_sha256=actual, planned=len(payloads))

    exchanges = runner.run(payloads, stop)
    interrupted = len(exchanges) < min(len(payloads), config.max_test_cases)
    (out_dir / "exchanges.json").write_text(
        json.dumps(_redacted([e.to_dict() for e in exchanges]), indent=2), encoding="utf-8")

    judgements = judge(llm, exchanges, config) if exchanges else []
    (out_dir / "judgements.json").write_text(json.dumps(judgements, indent=2), encoding="utf-8")
    definitive = [j for j in judgements if j["success"] in (True, False)]
    succeeded = sum(1 for j in definitive if j["success"] is True)

    pi = corpus.category(PROMPT_INJECTION)
    result = CategoryResult(pi.id, pi.name, tests_planned=len(payloads), tests_executed=len(exchanges),
                            tests_judged=len(definitive), attacks_succeeded=succeeded)
    result.coverage = aggregate.coverage(result.tests_planned, result.tests_executed, result.tests_judged)

    summary = ["Live run produced no judgeable results."]
    if exchanges:
        synth = llm.complete_json(
            prompts.SYNTHESIS_SYSTEM,
            prompts.synthesis_user(json.dumps({
                "category": {"id": pi.id, "name": pi.name}, "tests_executed": len(exchanges),
                "attacks_succeeded": succeeded, "unverified": len(judgements) - len(definitive),
                "judgements": judgements, "techniques": sorted({e.technique for e in exchanges})}, indent=1),
                config.max_input_chars), "synthesis")
        summary = _apply_synthesis(result, synth, audit)

    result.verification_status = ("RAG-verified" if result.tests_executed and result.tests_judged == result.tests_executed
                                  else "Unverified")
    if interrupted:
        result.notes.append("Run was interrupted; results are partial.")
    mode = "live-partial" if interrupted else "live"
    results = [result] + [CategoryResult(c.id, c.name) for c in corpus.categories
                          if c.id != PROMPT_INJECTION and c.id in _planned_ids(out_dir)]
    report = build_report(system_name=state["system_name"], auditor=state["auditor"], mode=mode,
                          risk_tier=state["risk_tier"], categories=results, executive_summary=summary,
                          corpus_manifest=corpus.manifest, model=config.model)
    paths = write_outputs(out_dir, report, name="report-live")
    audit.append("live_done", mode=mode, executed=len(exchanges), definitive=len(definitive), succeeded=succeeded)
    return {"report": report, "paths": paths}


def _planned_ids(out_dir: Path) -> set[str]:
    return {p["category_id"] for p in json.loads((Path(out_dir) / "procedures.json").read_text(encoding="utf-8"))}


def _redacted(obj):
    from .sanitise import redact_obj
    return redact_obj(obj)


def _apply_synthesis(result: CategoryResult, synth, audit: AuditLog) -> list[str]:
    """Take the model's rating/wording for the category, then let the evidence rules overrule it."""
    entry = next((c for c in (synth or {}).get("categories", []) if isinstance(c, dict) and c.get("id") == result.id), None) \
        if isinstance(synth, dict) else None
    if entry is None or entry.get("risk_rating") not in aggregate.RATINGS:
        raise ModelOutputError("synthesis: no valid rating for the tested category")
    rating, note = aggregate.apply_evidence_floor(entry["risk_rating"], result.attacks_succeeded, result.tests_judged)
    if note:
        result.notes.append(note)
        audit.append("rating_adjusted", category=result.id, model_rating=entry["risk_rating"], final=rating, reason=note)
    result.risk_rating = rating
    result.summary = str(entry.get("key_finding", "")) or result.summary
    result.recommendation = str(entry.get("recommendation", "")) or result.recommendation
    result.confidence = entry.get("confidence") if entry.get("confidence") in ("High", "Medium", "Low") else "Low"
    bullets = [str(s) for s in synth.get("executive_summary", [])][:3]
    return bullets or ["No executive summary was produced."]
