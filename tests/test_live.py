"""runner, judge, aggregate, report."""
import json
import threading

import pytest

from owasp_ai_testing_agent import aggregate, authorisation
from owasp_ai_testing_agent.audit_log import AuditLog
from owasp_ai_testing_agent.judge import judge, validate_judgement
from owasp_ai_testing_agent.report import CategoryResult, build_findings, build_report, validate, write_outputs
from owasp_ai_testing_agent.runner import Exchange, Interface, InterfaceError, Runner

MANIFEST = {"corpus_version": "v", "git_commit": "c", "source_url": "u"}


def _runner(interface_file, config, tmp_path, host="127.0.0.1"):
    auth = authorisation.verify(authorisation.mint(host, "me"))
    return Runner(Interface.load(interface_file), auth, config, AuditLog(tmp_path / "log.jsonl"))


# --- runner ------------------------------------------------------------------
def test_runner_puts_payload_only_in_the_json_body(interface_file, config, tmp_path, target):
    payload = 'x"; rm -rf / ; $(whoami) {{PAYLOAD}} \\n'
    ex = _runner(interface_file, config, tmp_path).send("t1", "direct", payload, "ind")
    assert ex.status == 200 and ex.response == "I can't help with that" and not ex.error
    assert target.requests[0]["body"] == {"message": payload}  # arrives byte-for-byte as data


def test_runner_expands_env_headers_but_never_logs_them(interface_file, config, tmp_path, target):
    _runner(interface_file, config, tmp_path).send("t1", "d", "hi", "i")
    assert target.requests[0]["headers"]["X-Test"] == "tok-should-never-be-logged"
    assert "tok-should-never-be-logged" not in (tmp_path / "log.jsonl").read_text(encoding="utf-8")


def test_runner_refuses_an_unauthorised_host_before_sending(interface_file, config, tmp_path, target):
    with pytest.raises(authorisation.AuthorisationError):
        _runner(interface_file, config, tmp_path, host="other.example.com")
    assert target.requests == []


def test_runner_does_not_follow_redirects(tmp_path, config, target):
    iface = tmp_path / "i.json"
    iface.write_text(json.dumps({"url": target.base + "/redirect", "body_template": {"m": "{{PAYLOAD}}"}}), encoding="utf-8")
    ex = _runner(iface, config, tmp_path).send("t1", "d", "hi", "i")
    assert ex.status == 302 and ex.error and ex.response is None


def test_runner_caps_response_size(interface_file, config, tmp_path, target):
    target.big_reply = True
    small = type(config)(**{**config.__dict__, "max_response_chars": 1000})
    ex = _runner(interface_file, small, tmp_path).send("t1", "d", "hi", "i")
    assert ex.truncated and len(ex.response) <= 1000


def test_runner_records_connection_errors_instead_of_raising(tmp_path, config):
    iface = tmp_path / "i.json"
    iface.write_text(json.dumps({"url": "http://127.0.0.1:1/x", "body_template": {"m": "{{PAYLOAD}}"}}), encoding="utf-8")
    ex = _runner(iface, config, tmp_path).send("t1", "d", "hi", "i")
    assert ex.error and ex.response is None


def test_runner_stops_early_and_logs_it(interface_file, config, tmp_path, target):
    stop = threading.Event()
    target.on_request = lambda n: stop.set()
    runner = _runner(interface_file, config, tmp_path)
    out = runner.run([{"test_id": f"t{i}", "payload": "p"} for i in range(5)], stop)
    assert len(out) == 1
    assert "run_interrupted" in (tmp_path / "log.jsonl").read_text(encoding="utf-8")


def test_runner_enforces_the_test_case_budget(interface_file, config, tmp_path, target):
    small = type(config)(**{**config.__dict__, "max_test_cases": 2})
    out = _runner(interface_file, small, tmp_path).run([{"test_id": f"t{i}", "payload": "p"} for i in range(5)])
    assert len(out) == 2 and len(target.requests) == 2


def test_interface_file_with_a_utf8_bom_is_accepted(tmp_path):
    p = tmp_path / "i.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"url": "https://x", "body_template": {"m": "{{PAYLOAD}}"}}).encode())
    assert Interface.load(p).url == "https://x"


def test_interface_validation(tmp_path):
    p = tmp_path / "i.json"
    p.write_text(json.dumps({"url": "https://x", "body_template": {"m": "no placeholder"}}), encoding="utf-8")
    with pytest.raises(InterfaceError, match="PAYLOAD"):
        Interface.load(p)
    p.write_text(json.dumps({"url": "https://x", "method": "GET", "body_template": {"m": "{{PAYLOAD}}"}}), encoding="utf-8")
    with pytest.raises(InterfaceError, match="POST or PUT"):
        Interface.load(p)


# --- judge -------------------------------------------------------------------
def _ex(response="Sure! PWNED-1", truncated=False, error=None, tid="t1"):
    return Exchange(tid, "direct", "p", "ind", status=200, response=response, truncated=truncated, error=error)


def test_judgement_needs_a_verbatim_quote():
    ok = validate_judgement({"success": True, "evidence_quote": "PWNED-1"}, _ex())
    assert ok["success"] is True
    for bad in ({"success": True, "evidence_quote": "PWNED-2"}, {"success": True, "evidence_quote": ""},
                {"success": False}, "garbage"):
        assert validate_judgement(bad, _ex())["success"] == "unverified"


def test_a_negative_judgement_on_a_truncated_response_is_not_trusted():
    j = validate_judgement({"success": False, "evidence_quote": "Sure"}, _ex(truncated=True))
    assert j["success"] == "unverified"
    assert validate_judgement({"success": True, "evidence_quote": "PWNED-1"}, _ex(truncated=True))["success"] is True


def test_judge_skips_unrecorded_responses_and_fills_missing_judgements(fake_llm, config):
    class LLM:
        calls = []

        def complete_json(self, system, user, purpose):
            self.calls.append(user)
            return [{"test_id": "t1", "success": True, "evidence_quote": "PWNED-1", "notes": ""},
                    {"test_id": "unknown", "success": True, "evidence_quote": "x"}]

    llm = LLM()
    out = judge(llm, [_ex(), _ex(response=None, error="HTTP 500", tid="t2"), _ex(tid="t3")], config)
    assert [j["success"] for j in out] == [True, "unverified", "unverified"]
    assert "t2" not in llm.calls[0]  # an exchange with no response is never sent to the model
    assert "no judgement" in out[2]["notes"]


# --- aggregate ---------------------------------------------------------------
def test_overall_rating_is_highest_severity_wins():
    assert aggregate.overall_rating(["Low", "High", "Medium", "High"]) == "High"
    assert aggregate.overall_rating(["Low", "Critical"]) == "Critical"
    assert aggregate.overall_rating(["Not Applicable", "Not Rated"]) == "Low"
    assert aggregate.overall_rating(["Not Rated"]) == "Not Rated"


def test_plan_example_three_high_categories_is_high_overall_not_medium():
    ratings = ["High", "High", "High"] + ["Low"] * 6 + ["Medium"] * 3
    assert aggregate.overall_rating(ratings) == "High"
    assert aggregate.overall_score(ratings) == 1.92 or aggregate.overall_score(ratings) < 3


def test_score_ignores_unrated_categories():
    assert aggregate.overall_score(["High", "Low", "Not Applicable", "Not Rated"]) == 2.0
    assert aggregate.overall_score(["Not Rated"]) is None


def test_coverage_and_evidence_floor():
    assert aggregate.coverage(5, 0, 0) == "Not tested"
    assert aggregate.coverage(5, 5, 5) == "Full"
    assert aggregate.coverage(5, 5, 3) == "Partial"
    assert aggregate.coverage(5, 2, 2) == "Partial"
    assert aggregate.apply_evidence_floor("Low", 1, 3)[0] == "Medium"
    assert aggregate.apply_evidence_floor("High", 0, 3) == ("High", None)
    assert aggregate.apply_evidence_floor("High", 0, 0)[0] == "Not Rated"


# --- report ------------------------------------------------------------------
def _report(**over):
    cats = [CategoryResult("AITG-APP-01", "Prompt Injection", 3, 3, 3, 1, "Critical", "Full", "Bad <script>alert(1)</script>",
                           "Fix it", "High", "RAG-verified")]
    kw = dict(system_name="s", auditor="a", mode="live", risk_tier="High", categories=cats,
              executive_summary=["one", "two", "three", "four"], corpus_manifest=MANIFEST, model="m")
    return build_report(**{**kw, **over})


def test_report_validates_and_truncates_summary_to_three():
    r = _report()
    validate(r, build_findings(r))
    assert len(r["executive_summary"]) == 3 and r["overall_rating"] == "Critical"


def test_critical_is_mapped_to_high_in_saaf_findings():
    f = build_findings(_report())[0]
    assert f["id"] == "F-AITG-APP-01" and f["risk_rating"] == "High" and f["ai_assisted"] is True


def test_unrated_categories_raise_no_finding():
    r = _report(categories=[CategoryResult("AITG-APP-01", "Prompt Injection")])
    assert build_findings(r) == [] and r["overall_rating"] == "Not Rated"


def test_invalid_output_is_rejected():
    r = _report()
    r["categories"][0]["risk_rating"] = "Catastrophic"
    with pytest.raises(ValueError, match="schema validation"):
        validate(r, [])


def test_outputs_are_html_escaped_and_redacted(tmp_path):
    cats = [CategoryResult("AITG-APP-01", "Prompt Injection", 1, 1, 1, 1, "High", "Full",
                           "Leaked <b>bob@example.com</b> key sk-abcdefghijklmnopqrstuvwxyz", "Fix", "High", "RAG-verified")]
    jp, mp, fp = write_outputs(tmp_path, _report(categories=cats))
    md = mp.read_text(encoding="utf-8")
    assert "<b>" not in md and "&lt;b&gt;" in md
    for p in (jp, mp, fp):
        text = p.read_text(encoding="utf-8")
        assert "bob@example.com" not in text and "sk-abcdefghijklmnopqrstuvwxyz" not in text
