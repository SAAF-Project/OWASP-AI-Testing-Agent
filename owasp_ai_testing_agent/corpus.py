"""OWASP AI Testing Guide corpus: integrity-checked loading and retrieval (plan section 6).

The corpus is a directory you supply (the guide text is not shipped here):

    categories.json   [{"id": "AITG-APP-01", "name": "...", "summary": "..."}, ...]   (from the guide)
    *.md / *.txt      guide text
    manifest.json     written by `ingest`: corpus version, provenance, SHA-256 per file

`load` refuses to run if any file no longer matches the manifest. Retrieval is plain keyword
scoring; a vector store (ChromaDB + embeddings, as in the plan) is not implemented.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MANIFEST = "manifest.json"
CATEGORIES = "categories.json"
_DOC_SUFFIXES = {".md", ".txt"}


class CorpusError(ValueError):
    pass


class CorpusIntegrityError(CorpusError):
    pass


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    summary: str


_SECTION_PRIORITY = ["test objectives", "how to test", "expected output", "summary", "remediation"]
_SECTION_SKIP = ("reference", "suggested tools", "real example")


def _split_text(text: str, limit: int) -> list[str]:
    """Split at paragraph boundaries into pieces of at most `limit` characters."""
    pieces, current = [], ""
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        while len(para) > limit:                # a single oversized paragraph: cut at the last line break
            cut = para.rfind("\n", 0, limit) or limit
            cut = cut if cut > 0 else limit
            pieces.append(para[:cut].strip())
            para = para[cut:].strip()
        if current and len(current) + len(para) + 2 > limit:
            pieces.append(current)
            current = ""
        current = f"{current}\n\n{para}" if current else para
    if current:
        pieces.append(current)
    return [p for p in pieces if p]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tracked_files(directory: Path) -> list[Path]:
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and (p.suffix.lower() in _DOC_SUFFIXES or p.name == CATEGORIES)
    )


def ingest(directory: Path | str, version: str, source_url: str, git_commit: str, extra: dict | None = None) -> dict:
    """Record corpus version, provenance and per-file SHA-256 in manifest.json.

    `extra` adds provenance fields such as license and attribution (shown in the report).
    """
    directory = Path(directory)
    if not (directory / CATEGORIES).exists():
        raise CorpusError(f"{directory / CATEGORIES} is missing; list the guide's categories there first")
    manifest = {
        "corpus_version": version,
        "source_url": source_url,
        "git_commit": git_commit,
        "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {p.name: _sha256(p) for p in _tracked_files(directory)},
        **(extra or {}),
    }
    (directory / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


class Corpus:
    def __init__(self, directory: Path, manifest: dict, categories: list[Category], docs: dict[str, str]):
        self.directory, self.manifest, self.categories, self._docs = directory, manifest, categories, docs

    @property
    def version(self) -> str:
        return self.manifest["corpus_version"]

    def category(self, category_id: str) -> Category | None:
        return next((c for c in self.categories if c.id == category_id), None)

    @classmethod
    def load(cls, directory: Path | str) -> "Corpus":
        directory = Path(directory)
        manifest_path = directory / MANIFEST
        if not manifest_path.exists():
            raise CorpusError(f"{manifest_path} is missing; run `ingest` on this directory first")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for key in ("corpus_version", "source_url", "git_commit", "files"):
            if key not in manifest:
                raise CorpusError(f"manifest.json lacks '{key}'")

        current = {p.name: _sha256(p) for p in _tracked_files(directory)}
        if current != manifest["files"]:
            changed = sorted(set(current) ^ set(manifest["files"])
                             | {n for n in current if n in manifest["files"] and current[n] != manifest["files"][n]})
            raise CorpusIntegrityError(f"corpus does not match its manifest: {', '.join(changed)}")

        raw = json.loads((directory / CATEGORIES).read_text(encoding="utf-8-sig"))
        try:
            categories = [Category(c["id"], c["name"], c.get("summary", "")) for c in raw]
        except (KeyError, TypeError) as exc:
            raise CorpusError(f"{CATEGORIES} entries need 'id' and 'name': {exc}") from exc
        if not categories:
            raise CorpusError(f"{CATEGORIES} is empty")
        docs = {p.name: p.read_text(encoding="utf-8-sig") for p in _tracked_files(directory) if p.name != CATEGORIES}
        return cls(directory, manifest, categories, docs)

    def _own_file(self, category_id: str) -> tuple[str, str] | None:
        """The guide file for this test (e.g. AITG-APP-01_Testing_for_Prompt_Injection.md), if present."""
        for name, text in self._docs.items():
            if name.startswith(f"{category_id}_") or name.rsplit(".", 1)[0] == category_id:
                return name, text
        return None

    def sections(self, category_id: str) -> dict[str, str]:
        """Heading -> text for the category's own guide file ('Test Objectives', 'How to Test/Payloads', ...)."""
        own = self._own_file(category_id)
        if own is None:
            return {}
        out: dict[str, str] = {}
        current = "Preamble"
        for line in own[1].splitlines():
            heading = re.match(r"^#{1,3}\s+(.*\S)\s*$", line)
            if heading and not line.startswith("#### "):
                current = heading.group(1).strip()
                out.setdefault(current, "")
            else:
                out[current] = out.get(current, "") + line + "\n"
        return {k: v.strip() for k, v in out.items() if v.strip()}

    def retrieve(self, category_id: str, limit: int, max_chunk_chars: int) -> list[dict]:
        """Up to `limit` validated {source, text} chunks for the category.

        The category's own guide file comes first, in the order objectives -> how to test ->
        expected output -> summary -> remediation, split at paragraph boundaries to fit
        `max_chunk_chars`. Remaining slots are filled by keyword matches from other files.
        """
        cat = self.category(category_id)
        if cat is None:
            raise CorpusError(f"unknown category {category_id}")
        chunks: list[dict] = []
        own = self._own_file(category_id)
        if own is not None:
            sections = self.sections(category_id)
            order = sorted(sections, key=lambda h: next(
                (i for i, key in enumerate(_SECTION_PRIORITY) if key in h.lower()), len(_SECTION_PRIORITY)))
            for heading in order:
                if any(skip in heading.lower() for skip in _SECTION_SKIP):
                    continue
                for piece in _split_text(sections[heading], max_chunk_chars):
                    chunks.append({"source": f"{own[0]} § {heading}", "text": piece})
        chunks = chunks[:limit]
        if len(chunks) >= 3:      # the category's own guide text is enough; keyword filler would only add noise
            for ch in chunks:
                if not isinstance(ch["text"], str) or not ch["text"] or len(ch["text"]) > max_chunk_chars:
                    raise CorpusError(f"retrieved chunk from {ch['source']} fails validation (empty or > {max_chunk_chars} chars)")
            return chunks
        terms = {t for t in re.findall(r"[a-z0-9]+", f"{cat.id} {cat.name}".lower()) if len(t) > 2}
        scored = []
        for source, text in self._docs.items():
            if own is not None and source == own[0]:
                continue
            for para in re.split(r"\n\s*\n", text):
                para = para.strip()
                if not para:
                    continue
                words = set(re.findall(r"[a-z0-9]+", para.lower()))
                score = len(terms & words) + (5 if cat.id.lower() in para.lower() else 0)
                if score:
                    scored.append((score, source, para))
        scored.sort(key=lambda t: -t[0])
        chunks += [{"source": s, "text": p} for _, s, p in scored[: max(limit - len(chunks), 0)]]
        for ch in chunks:  # schema check before anything reaches a prompt
            if not isinstance(ch["text"], str) or not ch["text"] or len(ch["text"]) > max_chunk_chars:
                raise CorpusError(f"retrieved chunk from {ch['source']} fails validation (empty or > {max_chunk_chars} chars)")
        return chunks
