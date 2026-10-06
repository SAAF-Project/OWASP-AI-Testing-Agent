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
from .judge import extract_canary, judge
from .llm import LLM, ModelOutputError
from .report import CategoryResult, build_report, write_outputs
from .runner import Interface, Runner
from .sanitise import detect_injection

LIVE_CATEGORIES = tuple(prompts.TECHNIQUES)   # categories with automated live tests (see prompts.py for the rule)
STATE_FILE = "plan_state.json"
PRIORITY = {"Critical": "immediate", "High": "within 30 days", "Medium": "within 90 days", "Low": "routine",
            "Not Applicable": "none", "Not Rated": "cannot be set until a test produces a definitive result"}
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


def _normalise_case(tc) -> dict | None:
    """One test case as {input, pass_expected, fail_expected} (all non-empty strings), or None.

    Given the real guide text the model often returns `input_sequence` (a list of attempts) or a
    `title` alongside `input`; accept those shapes instead of discarding a good answer.
    """
    if not isinstance(tc, dict):
        return None
    raw = tc.get("input")
    if raw is None:   # any input-like key: input_sequence, input_scenarios, steps, attempts, prompts, ...
        raw = next((v for k, v in tc.items() if k not in ("pass_expected", "fail_expected", "id", "title")
                    and any(w in k.lower() for w in ("input", "scenario", "step", "prompt", "attempt"))
                    and (isinstance(v, str) or isinstance(v, list)) and v), None)
    if isinstance(raw, list):
        raw = "\n".join(f"{i}. {s}" for i, s in enumerate((str(x) for x in raw if str(x).strip()), 1))
    if not isinstance(raw, str) or not raw.strip():
        return None
    title = tc.get("title")
    if isinstance(title, str) and title.strip():
        raw = f"{title.strip()}: {raw}"
    pass_e, fail_e = tc.get("pass_expected"), tc.get("fail_expected")
    if not all(isinstance(v, str) and v.strip() for v in (pass_e, fail_e)):
        return None
    return {"input": raw, "pass_expected": pass_e, "fail_expected": fail_e}


def validate_procedures(proc, category_id: str, config: Config) -> dict:
    # The model sometimes answers with a list of objects for the one category; merge those that match.
    items = [p for p in proc if isinstance(p, dict) and p.get("category_id", category_id) == category_id] \
        if isinstance(proc, list) else [proc] if isinstance(proc, dict) else []
    cases, evidence, objectives = [], [], []
    for item in items:
        objectives.append(str(item.get("objective", "")))
        evidence += [str(x) for x in item.get("evidence_to_collect", [])]
        for tc in item.get("test_cases", []):
            case = _normalise_case(tc)
            if case:
                cases.append(case)
    if not cases:
        raise ModelOutputError(f"procedures for {category_id}: no valid test cases")
    return {"category_id": category_id, "objective": " ".join(o for o in objectives if o),
            "test_cases": cases[: config.max_cases_per_category],
            "evidence_to_collect": list(dict.fromkeys(evidence))}


def validate_payloads(raw, limit: int, category_id: str = "AITG-APP-01", taken: set | None = None) -> list[dict]:
    """Keep well-formed payloads, tag them with their category and canary, and keep test ids unique.

    `taken` holds test ids already used by other categories; a colliding id gets the category id appended.
    """
    if not isinstance(raw, list):
        raise ModelOutputError("payloads: expected a JSON list")
    taken = taken if taken is not None else set()
    seen_here: set[str] = set()
    out = []
    for item in raw:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k].strip()
                                                 for k in ("test_id", "payload", "success_indicator")):
            continue
        tid = item["test_id"]
        if tid in seen_here:            # the same id twice in one answer: keep the first
            continue
        seen_here.add(tid)
        if tid in taken:                # clashes with another category's id: disambiguate
            tid = f"{tid}~{category_id}"
            if tid in taken:
                continue
        taken.add(tid)
        out.append({"test_id": tid, "category_id": category_id, "technique": str(item.get("technique", "")),
                    "payload": item["payload"], "success_indicator": item["success_indicator"],
                    "canary": extract_canary(item["payload"], item["success_indicator"])})
    if not out:
        raise ModelOutputError(f"payloads for {category_id}: none were valid")
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

    # Share the test-case budget fairly: each remaining category may use at most budget // categories_left
    # (capped at max_cases_per_category), so early categories cannot starve later ones.
    procedures, budget, skipped = [], config.max_test_cases, {}
    applicable = profile["applicable_categories"]
    for idx, item in enumerate(applicable):
        if budget <= 0:
            skipped[item["id"]] = "budget"
            audit.append("test_case_budget_exhausted", skipped=item["id"])
            continue
        allowed = max(1, min(config.max_cases_per_category, budget // (len(applicable) - idx)))
        cat = corpus.category(item["id"])
        chunks = corpus.retrieve(cat.id, config.rag_retrieval_limit, config.max_chunk_chars)
        user = prompts.procedures_user({"id": cat.id, "name": cat.name}, chunks, system_text,
                                       profile["risk_tier"], config.max_input_chars, allowed)
        proc = None
        for attempt in (1, 2):   # one retry with a corrective instruction, then give up on this category only
            try:
                proc = validate_procedures(
                    llm.complete_json(prompts.PROCEDURES_SYSTEM, user + ("" if attempt == 1 else prompts.PROCEDURES_RETRY),
                                      f"procedures:{cat.id}"), cat.id, config)
                break
            except ModelOutputError as exc:
                audit.append("procedures_invalid", category=cat.id, attempt=attempt, error=str(exc))
        if proc is None:
            skipped[cat.id] = "invalid"
            continue
        proc["test_cases"] = proc["test_cases"][:allowed]
        budget -= len(proc["test_cases"])
        procedures.append(proc)

    payloads: list[dict] = []
    live_ids = [p["category_id"] for p in procedures if p["category_id"] in LIVE_CATEGORIES]
    taken: set[str] = set()
    for cid in live_ids:
        n = max(1, min(max_payloads, config.max_test_cases // len(live_ids)))
        cat = corpus.category(cid)
        chunks = corpus.retrieve(cid, config.rag_retrieval_limit, config.max_chunk_chars)
        payloads += validate_payloads(
            llm.complete_json(prompts.payload_system(n, cat.id, cat.name),
                              prompts.payload_user(system_text, "", chunks, config.max_input_chars),
                              f"payloads:{cid}"), n, cid, taken)

    paths = {"profile": out_dir / "profile.json", "procedures": out_dir / "procedures.json",
             "payloads": out_dir / "payloads.json", "state": out_dir / STATE_FILE}
    paths["profile"].write_text(json.dumps(profile, indent=2), encoding="utf-8")
    paths["procedures"].write_text(json.dumps(procedures, indent=2), encoding="utf-8")
    paths["payloads"].write_text(json.dumps(payloads, indent=2), encoding="utf-8")
    payloads_hash = _sha256_file(paths["payloads"])

    results = []
    for p in procedures:
        cat = corpus.category(p["category_id"])
        mine = [x for x in payloads if x["category_id"] == p["category_id"]]
        planned = len(mine) if p["category_id"] in LIVE_CATEGORIES else len(p["test_cases"])
        results.append(CategoryResult(cat.id, cat.name, tests_planned=planned,
                                      notes=["Static procedures generated; no test was executed."]))
    results += _skipped_results(corpus, skipped, config)
    system_name = Path(system_path).stem
    state = {"system_name": system_name, "auditor": auditor, "risk_tier": profile["risk_tier"],
             "skipped": skipped,
             "corpus_dir": str(Path(corpus_dir).resolve()), "corpus_version": corpus.version,
             "system_sha256": hashlib.sha256(system_text.encode("utf-8")).hexdigest(), "payloads_sha256": payloads_hash}
    paths["state"].write_text(json.dumps(state, indent=2), encoding="utf-8")

    summary = [f"Static run: {len(procedures)} categories profiled, {sum(len(p['test_cases']) for p in procedures)} test procedures generated.",
               f"{len(payloads)} payloads for {len(live_ids)} live-testable categories are ready for human review; nothing has been sent to any system.",
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
    verdict = {j["test_id"]: j["success"] for j in judgements}
    technique = {e.test_id: e.technique for e in exchanges}

    # One result per live category that had payloads, with counts computed from the recorded evidence.
    results: list[CategoryResult] = []
    for cid in dict.fromkeys(p.get("category_id", "") for p in payloads):
        cat = corpus.category(cid)
        if cat is None:
            raise PipelineError(f"payloads.json names category {cid!r}, which is not in the corpus")
        mine = [e for e in exchanges if e.category_id == cid]
        won = [e.test_id for e in mine if verdict.get(e.test_id) is True]
        judged = [e for e in mine if verdict.get(e.test_id) in (True, False)]
        r = CategoryResult(cid, cat.name, tests_planned=sum(1 for p in payloads if p.get("category_id") == cid),
                           tests_executed=len(mine), tests_judged=len(judged), attacks_succeeded=len(won))
        r.coverage = aggregate.coverage(r.tests_planned, r.tests_executed, r.tests_judged)
        r.verification_status = "RAG-verified" if r.tests_executed and r.tests_judged == r.tests_executed else "Unverified"
        r.summary = _facts(r, [f"{t} ({technique[t]})" for t in won])
        if interrupted:
            r.notes.append("Run was interrupted; results are partial.")
        results.append(r)

    ran = [r for r in results if r.tests_executed]
    if ran:
        synth = llm.complete_json(
            prompts.SYNTHESIS_SYSTEM,
            prompts.synthesis_user(json.dumps({"categories": [
                {"id": r.id, "name": r.name, "tests_executed": r.tests_executed, "attacks_succeeded": r.attacks_succeeded,
                 "unverified": r.tests_executed - r.tests_judged,
                 "judgements": [j for j in judgements if next((e.category_id for e in exchanges if e.test_id == j["test_id"]), "") == r.id],
                 "techniques": sorted({e.technique for e in exchanges if e.category_id == r.id})} for r in ran]}, indent=1),
                config.max_input_chars), "synthesis")
        for r in ran:
            _apply_synthesis(r, synth, audit)

    # Other categories profiled in `plan` stay unrated: they have procedures but no executed test.
    rated_ids = {r.id for r in results}
    results += [CategoryResult(c.id, c.name) for c in corpus.categories if c.id in _planned_ids(out_dir) and c.id not in rated_ids]
    results += _skipped_results(corpus, state.get("skipped", {}), config)

    mode = "live-partial" if interrupted else "live"
    overall = aggregate.overall_rating([r.risk_rating for r in results])
    report = build_report(system_name=state["system_name"], auditor=state["auditor"], mode=mode,
                          risk_tier=state["risk_tier"], categories=results,
                          executive_summary=_executive_summary(results, exchanges, verdict, technique, overall),
                          corpus_manifest=corpus.manifest, model=config.model)
    paths = write_outputs(out_dir, report, name="report-live")
    audit.append("live_done", mode=mode, executed=len(exchanges),
                 definitive=sum(r.tests_judged for r in results), succeeded=sum(r.attacks_succeeded for r in results))
    return {"report": report, "paths": paths}


def _skipped_results(corpus: Corpus, skipped: dict[str, str], config: Config) -> list[CategoryResult]:
    """Categories the profile found applicable but that got no procedures: reported, never silently dropped."""
    why = {"budget": f"the {config.max_test_cases}-test-case budget was exhausted. Raise it or run a separate audit for this category.",
           "invalid": "the model's answer was not usable, even after one retry (see procedures_invalid in the audit log). "
                      "Run `plan` again or review this category manually."}
    return [CategoryResult(c.id, c.name, notes=[f"Profiled as applicable, but no procedures were generated: {why[reason]}"])
            for c, reason in ((corpus.category(i), r) for i, r in skipped.items()) if c is not None]


def _facts(r: CategoryResult, won: list[str]) -> str:
    """Category summary built from counts only. No model-written claim can enter this sentence."""
    unverified = r.tests_executed - r.tests_judged
    text = (f"{r.attacks_succeeded} of {r.tests_judged} judged tests succeeded "
            f"({r.tests_executed} of {r.tests_planned} planned tests were run; {unverified} unverified).")
    text += f" Succeeded: {'; '.join(won)}." if won else " No attack succeeded in a verified test."
    return text


def _executive_summary(results: list[CategoryResult], exchanges, verdict: dict, technique: dict, overall: str) -> list[str]:
    """Three bullets computed from the evidence. The model's own summary is not used."""
    if not exchanges:
        return ["No test was run, so there are no results to summarise.",
                "No attack succeeded in a verified test.",
                f"Overall rating: {overall}; remediation priority {PRIORITY[overall]}."]
    run = [r for r in results if r.tests_executed]
    won = [t for t, v in verdict.items() if v is True]
    lost = sum(1 for v in verdict.values() if v is False)
    unverified = sum(1 for v in verdict.values() if v == "unverified")
    shown = [f"{t} ({technique.get(t, '?')})" for t in won[:5]] + ([f"and {len(won) - 5} more"] if len(won) > 5 else [])
    return [f"{len(exchanges)} test(s) run across {len(run)} categor{'y' if len(run) == 1 else 'ies'}: "
            f"{len(won)} attack(s) succeeded, {lost} did not, {unverified} unverified.",
            f"Successful attacks: {', '.join(shown)}." if won else "No attack succeeded in a verified test.",
            f"Overall rating: {overall}; remediation priority {PRIORITY[overall]}. "
            "Per-category recommendations are AI-written advice and need human review."]


def _planned_ids(out_dir: Path) -> set[str]:
    return {p["category_id"] for p in json.loads((Path(out_dir) / "procedures.json").read_text(encoding="utf-8"))}


def _redacted(obj):
    from .sanitise import redact_obj
    return redact_obj(obj)


def _apply_synthesis(result: CategoryResult, synth, audit: AuditLog) -> None:
    """Take the model's rating, recommendation and confidence, then let the evidence rules overrule the rating.

    The model's executive summary and key finding are NOT used as facts (see _facts, _executive_summary).
    """
    entry = next((c for c in (synth or {}).get("categories", []) if isinstance(c, dict) and c.get("id") == result.id), None) \
        if isinstance(synth, dict) else None
    if entry is None or entry.get("risk_rating") not in aggregate.RATINGS:
        raise ModelOutputError("synthesis: no valid rating for the tested category")
    rating, note = aggregate.apply_evidence_floor(entry["risk_rating"], result.attacks_succeeded, result.tests_judged)
    if note:
        result.notes.append(note)
        audit.append("rating_adjusted", category=result.id, model_rating=entry["risk_rating"], final=rating, reason=note)
    result.risk_rating = rating
    # The summary stays the code-written fact sentence; the model's wording is kept only as labelled commentary.
    if entry.get("key_finding"):
        result.notes.append(f"AI commentary (not verified): {entry['key_finding']}")
    result.recommendation = str(entry.get("recommendation", "")) or result.recommendation
    result.confidence = entry.get("confidence") if entry.get("confidence") in ("High", "Medium", "Low") else "Low"
