"""Download the OWASP AI Testing Guide at a pinned commit and build a corpus from it.

The guide is published under CC BY-SA 4.0. It is fetched on the user's machine and not redistributed
by this repository, so ShareAlike does not attach to this code. Every file is checked against the git
blob hash GitHub reports for that commit, so a corrupted or substituted download is rejected.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path

from .corpus import CATEGORIES, CorpusError, ingest

REPO = "OWASP/www-project-ai-testing-guide"
# Head of `main` when this was written (2026-10-06). Override with --ref to audit against another version.
DEFAULT_REF = "006e4e9ee060f2ca2176037499b824e47af5360e"
LICENSE = "CC BY-SA 4.0"
_TEST_FILE = re.compile(r"^Document/content/tests/(AITG-[A-Z]+-\d+)_[^/]+\.md$")
_FRAMEWORK_FILE = "Document/content/3.0_OWASP_AI_Testing_Guide_Framework.md"
_TITLE = re.compile(r"^#\s*(AITG-[A-Z]+-\d+)\s*[-–—]\s*(.+?)\s*$", re.M)


def _http_get(url: str) -> bytes:
    headers = {"User-Agent": "owasp-ai-testing-agent", "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:
        return resp.read()


def git_blob_sha1(data: bytes) -> str:
    """The SHA-1 git assigns to a file's content: sha1(b'blob <size>\\0' + content)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _summary(text: str) -> str:
    m = re.search(r"###\s*Summary\s*\n(.*?)(?=\n#{1,3}\s|\Z)", text, re.S)
    para = (m.group(1) if m else "").strip().split("\n\n")[0]
    return re.sub(r"\s+", " ", para)[:400]


def fetch_guide(dest: Path | str, ref: str = DEFAULT_REF, get=_http_get) -> dict:
    """Download the framework overview and all AITG-* tests at `ref` into `dest` and ingest them.

    `get(url) -> bytes` is injectable for tests. Returns the corpus manifest.
    """
    dest = Path(dest)
    tree = json.loads(get(f"https://api.github.com/repos/{REPO}/git/trees/{ref}?recursive=1"))
    if tree.get("truncated"):
        raise CorpusError("GitHub returned a truncated file list; cannot guarantee the corpus is complete")
    commit = ref if re.fullmatch(r"[0-9a-f]{40}", ref) else None
    if commit is None:
        commit = json.loads(get(f"https://api.github.com/repos/{REPO}/commits/{ref}"))["sha"]

    wanted = {e["path"]: e["sha"] for e in tree["tree"]
              if e["type"] == "blob" and (_TEST_FILE.match(e["path"]) or e["path"] == _FRAMEWORK_FILE)}
    if not any(_TEST_FILE.match(p) for p in wanted):
        raise CorpusError(f"no AITG test files found in {REPO}@{ref}")

    dest.mkdir(parents=True, exist_ok=True)
    categories = []
    for path in sorted(wanted):
        data = get(f"https://raw.githubusercontent.com/{REPO}/{commit}/{path}")
        if git_blob_sha1(data) != wanted[path]:
            raise CorpusError(f"{path}: downloaded content does not match GitHub's recorded blob hash")
        (dest / Path(path).name).write_bytes(data)
        m = _TEST_FILE.match(path)
        if m:
            text = data.decode("utf-8", errors="replace")
            title = _TITLE.search(text)
            categories.append({"id": m.group(1), "name": title.group(2) if title else m.group(1),
                               "summary": _summary(text)})
    (dest / CATEGORIES).write_text(json.dumps(categories, indent=2, ensure_ascii=False), encoding="utf-8")
    return ingest(dest, f"owasp-ai-testing-guide@{commit[:7]}", f"https://github.com/{REPO}/tree/{commit}", commit,
                  extra={"license": LICENSE,
                         "attribution": "OWASP AI Testing Guide, OWASP Foundation, CC BY-SA 4.0 "
                                        "(https://creativecommons.org/licenses/by-sa/4.0/); fetched unmodified."})
