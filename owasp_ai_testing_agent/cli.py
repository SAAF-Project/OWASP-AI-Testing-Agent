"""Command line interface.

    python -m owasp_ai_testing_agent ingest   <corpus_dir> --version V --source-url URL --git-commit SHA
    python -m owasp_ai_testing_agent plan     <system.json> --corpus <corpus_dir> --out <out_dir>
    python -m owasp_ai_testing_agent mint-token --host H --authorised-by WHO --out token.json     (system owner)
    python -m owasp_ai_testing_agent execute  <out_dir> --live --token token.json --interface i.json --approve <sha256>
    python -m owasp_ai_testing_agent verify-log <out_dir>/audit_log.jsonl
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from . import authorisation, corpus as corpus_mod
from .audit_log import verify_log
from .config import Config
from .llm import ModelOutputError
from .pipeline import PipelineError, execute, plan
from .sanitise import InputTooLarge


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="owasp_ai_testing_agent", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ingest", help="record corpus version, provenance and SHA-256 hashes")
    s.add_argument("corpus_dir")
    s.add_argument("--version", required=True, help="e.g. owasp-guide-v1.0")
    s.add_argument("--source-url", required=True)
    s.add_argument("--git-commit", required=True, help="commit SHA of the guide release you copied")

    s = sub.add_parser("plan", help="static mode: profile, procedures, payloads; sends nothing to any target")
    s.add_argument("system", help="file describing the AI system under test")
    s.add_argument("--corpus", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--auditor", default="unspecified")
    s.add_argument("--payloads", type=int, default=10, help="number of prompt-injection payloads to generate")

    s = sub.add_parser("mint-token", help="system owner: sign a live-test authorisation token")
    s.add_argument("--host", required=True)
    s.add_argument("--authorised-by", required=True)
    s.add_argument("--hours", type=float, default=24)
    s.add_argument("--out", required=True)

    s = sub.add_parser("execute", help="live mode: run the approved payloads against the authorised target")
    s.add_argument("out_dir", help="output directory of a previous `plan`")
    s.add_argument("--live", action="store_true", help="required: confirms you want requests sent to a real system")
    s.add_argument("--token", required=True)
    s.add_argument("--interface", required=True)
    s.add_argument("--approve", required=True, help="SHA-256 of the payloads.json you reviewed and approved")

    s = sub.add_parser("verify-log", help="check the audit log's hash chain")
    s.add_argument("log")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = Config.from_env()
    try:
        if args.cmd == "ingest":
            m = corpus_mod.ingest(args.corpus_dir, args.version, args.source_url, args.git_commit)
            print(f"ingested {len(m['files'])} files as {m['corpus_version']}")
        elif args.cmd == "plan":
            r = plan(Path(args.system), Path(args.corpus), Path(args.out), config, auditor=args.auditor,
                     max_payloads=args.payloads)
            print(f"report:  {r['paths']['report_md']}")
            print(f"payloads: {r['paths']['payloads']}")
            print(f"payloads sha256 (review the file, then pass this to `execute --approve`): {r['payloads_sha256']}")
        elif args.cmd == "mint-token":
            token = authorisation.mint(args.host, args.authorised_by, args.hours)
            Path(args.out).write_text(json.dumps(token, indent=2), encoding="utf-8")
            print(f"token for {token['target_host']} valid until {token['expires_at']} written to {args.out}")
        elif args.cmd == "execute":
            if not args.live:
                print("refusing to send anything without --live", file=sys.stderr)
                return 2
            stop = threading.Event()
            handler = lambda *_: stop.set()  # noqa: E731  (finish the current request, save a partial report)
            for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
                if hasattr(signal, name):
                    signal.signal(getattr(signal, name), handler)
            r = execute(Path(args.out_dir), Path(args.token), Path(args.interface), args.approve, config, stop=stop)
            rep = r["report"]
            print(f"{rep['mode']}: overall {rep['overall_rating']} (score {rep['overall_score']}); report {r['paths'][1]}")
            print("A human auditor must sign off before this report is treated as final.")
        elif args.cmd == "verify-log":
            ok, msg = verify_log(args.log)
            print(("OK: " if ok else "TAMPERED: ") + msg)
            return 0 if ok else 1
    except (PipelineError, InputTooLarge, corpus_mod.CorpusError, authorisation.AuthorisationError,
            ModelOutputError, RuntimeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
