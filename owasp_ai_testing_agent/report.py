"""Build, validate and write the audit report (plan section 8)."""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from .aggregate import overall_rating, overall_score
from .sanitise import redact_obj

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

# SAAF's finding schema has no 'Critical' and no 'Not Rated'; these are mapped when findings are emitted.
_FINDING_RATING = {"Critical": "High", "High": "High", "Medium": "Medium", "Low": "Low", "Not Applicable": "Informational"}

LIMITATIONS = [
    "A human auditor must sign off before this report is treated as final.",
    "Findings are AI-assisted; judgements are accepted only with a verbatim evidence quote from the recorded response, "
    "and are cross-checked against the canary string where the test has one.",
    "Counts, summaries and the executive summary are computed from the recorded evidence. The per-category rating, "
    "recommendation and confidence are model-proposed (the rating is bounded by evidence rules); notes marked "
    "'AI commentary' are model-written and not verified.",
    "Automated live tests exist only for categories a plain chat endpoint can test with an objective canary check "
    "(AITG-APP-01, AITG-APP-02); every other category has static procedures only.",
    "Retrieval over the guide corpus is section- and keyword-based; no vector store is used.",
    "The hallucination-detection agent named in the plan is not integrated.",
]


@dataclass
class CategoryResult:
    id: str
    name: str
    tests_planned: int = 0
    tests_executed: int = 0
    tests_judged: int = 0           # tests with a definitive (non-'unverified') verdict
    attacks_succeeded: int = 0
    risk_rating: str = "Not Rated"
    coverage: str = "Not tested"
    summary: str = "Not tested in this run."
    recommendation: str = "Run the live tests, or review the static procedures manually."
    confidence: str = "Low"
    verification_status: str = "Unverified"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        finding = f"F-{self.id}" if self.risk_rating not in ("Not Rated",) else None
        d = {k: getattr(self, k) for k in ("id", "name", "risk_rating", "coverage", "summary", "recommendation",
                                           "confidence", "verification_status", "tests_planned", "tests_executed",
                                           "tests_judged", "attacks_succeeded")}
        d["finding"] = finding
        if self.notes:
            d["notes"] = self.notes
        return d


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")))


def build_report(*, system_name: str, auditor: str, mode: str, risk_tier: str, categories: list[CategoryResult],
                 executive_summary: list[str], corpus_manifest: dict, model: str, signed_off: bool = False,
                 now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ratings = [c.risk_rating for c in categories]
    return {
        "audit_id": f"OWASP-AUDIT-{now:%Y%m%d-%H%M%S}",
        "system_name": system_name,
        "audit_date": f"{now:%Y-%m-%d}",
        "auditor": auditor,
        "mode": mode,
        "risk_tier": risk_tier,
        "overall_score": overall_score(ratings),
        "overall_rating": overall_rating(ratings),
        "categories": [c.to_dict() for c in categories],
        "executive_summary": executive_summary[:3],
        "corpus": {"version": corpus_manifest["corpus_version"], "git_commit": corpus_manifest["git_commit"],
                   "source_url": corpus_manifest["source_url"],
                   **({"license": corpus_manifest["license"]} if "license" in corpus_manifest else {})},
        "model": model,
        "limitations": LIMITATIONS,
        "human_signoff": {"required": True, "signed_off": signed_off},
    }


def build_findings(report: dict) -> list[dict]:
    """SAAF findings (schemas/finding-schema.json), one per rated category."""
    findings = []
    for c in report["categories"]:
        if c["risk_rating"] == "Not Rated":
            continue
        findings.append({
            "id": c["finding"],
            "title": f"{c['id']} — {c['name']} ({c['risk_rating']})",
            "risk_rating": _FINDING_RATING[c["risk_rating"]],
            "observation": c["summary"],
            "recommendation": c["recommendation"],
            "ai_assisted": True,
            "status": "Open",
        })
    return findings


def validate(report: dict, findings: list[dict]) -> None:
    errors = [f"report: {e.message}" for e in _validator("audit-report-schema.json").iter_errors(report)]
    finding_validator = _validator("finding-schema.json")
    for f in findings:
        errors += [f"finding {f.get('id')}: {e.message}" for e in finding_validator.iter_errors(f)]
    if errors:
        raise ValueError("output failed schema validation:\n- " + "\n- ".join(errors))


def render_markdown(report: dict) -> str:
    """Markdown report. Every string is HTML-escaped (plan: LLM05)."""
    e = html.escape
    lines = [
        f"# OWASP AI Security Audit — {e(report['system_name'])}", "",
        f"- **Audit id:** {e(report['audit_id'])}  ·  **Date:** {e(report['audit_date'])}  ·  **Auditor:** {e(report['auditor'])}",
        f"- **Mode:** {e(report['mode'])}  ·  **Risk tier:** {e(report['risk_tier'])}  ·  **Model:** {e(report['model'])}",
        f"- **Overall rating:** **{e(report['overall_rating'])}**  ·  weighted score: {report['overall_score']}",
        f"- **Corpus:** {e(report['corpus']['version'])} (commit {e(report['corpus']['git_commit'])})"
        + (f", {e(report['corpus']['license'])}" if report["corpus"].get("license") else ""),
        f"- **Human sign-off:** {'done' if report['human_signoff']['signed_off'] else 'REQUIRED, not yet given'}", "",
        "## Executive summary", "",
        *[f"- {e(s)}" for s in report["executive_summary"]], "",
        "## Categories", "",
        "| Category | Rating | Coverage | Tests (planned/run/judged/attacks succeeded) | Finding |",
        "|---|---|---|---|---|",
    ]
    for c in report["categories"]:
        lines.append(f"| {e(c['id'])} {e(c['name'])} | {e(c['risk_rating'])} | {e(c['coverage'])} | "
                     f"{c['tests_planned']}/{c['tests_executed']}/{c['tests_judged']}/{c['attacks_succeeded']} | "
                     f"{e(c['finding'] or '—')} |")
    lines += ["", "## Findings and recommendations", ""]
    for c in report["categories"]:
        lines += [f"### {e(c['id'])} — {e(c['name'])} ({e(c['risk_rating'])})", "",
                  f"{e(c['summary'])}", "", f"**Recommendation (AI-assisted, review before use):** {e(c['recommendation'])}  ",
                  f"**Confidence:** {e(c['confidence'])}  ·  **Verification:** {e(c['verification_status'])}", ""]
        lines += [f"- _{e(n)}_" for n in c.get("notes", [])]
        lines.append("")
    lines += ["## Limitations", "", *[f"- {e(s)}" for s in report["limitations"]], ""]
    return "\n".join(lines)


def write_outputs(out_dir: Path, report: dict, name: str = "report") -> tuple[Path, Path, Path]:
    """Validate, redact PII/secrets, and write <name>.json, <name>.md and <name>-findings.json."""
    findings = build_findings(report)
    validate(report, findings)
    report, findings = redact_obj(report), redact_obj(findings)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = (out_dir / f"{name}.json", out_dir / f"{name}.md", out_dir / f"{name}-findings.json")
    paths[0].write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    paths[1].write_text(render_markdown(report), encoding="utf-8")
    paths[2].write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    return paths
