"""OWASP AI Testing Guide corpus: integrity-checked loading and retrieval (plan section 6).

The corpus is a directory you supply (the guide text is not shipped here):

    categories.json   [{"id": "AT-01", "name": "...", "summary": "..."}, ...]   (from the guide)
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tracked_files(directory: Path) -> list[Path]:
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and (p.suffix.lower() in _DOC_SUFFIXES or p.name == CATEGORIES)
    )


def ingest(directory: Path | str, version: str, source_url: str, git_commit: str) -> dict:
    """Record corpus version, provenance and per-file SHA-256 in manifest.json."""
    directory = Path(directory)
    if not (directory / CATEGORIES).exists():
        raise CorpusError(f"{directory / CATEGORIES} is missing; list the guide's categories there first")
    manifest = {
        "corpus_version": version,
        "source_url": source_url,
        "git_commit": git_commit,
        "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {p.name: _sha256(p) for p in _tracked_files(directory)},
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

    def retrieve(self, category_id: str, limit: int, max_chunk_chars: int) -> list[dict]:
        """Top `limit` paragraphs mentioning the category, as validated {source, text} chunks."""
        cat = self.category(category_id)
        if cat is None:
            raise CorpusError(f"unknown category {category_id}")
        terms = {t for t in re.findall(r"[a-z0-9]+", f"{cat.id} {cat.name}".lower()) if len(t) > 2}
        scored = []
        for source, text in self._docs.items():
            for para in re.split(r"\n\s*\n", text):
                para = para.strip()
                if not para:
                    continue
                words = set(re.findall(r"[a-z0-9]+", para.lower()))
                score = len(terms & words) + (5 if cat.id.lower() in para.lower() else 0)
                if score:
                    scored.append((score, source, para))
        scored.sort(key=lambda t: -t[0])
        chunks = [{"source": s, "text": p} for _, s, p in scored[:limit]]
        for ch in chunks:  # schema check before anything reaches a prompt
            if not isinstance(ch["text"], str) or not ch["text"] or len(ch["text"]) > max_chunk_chars:
                raise CorpusError(f"retrieved chunk from {ch['source']} fails validation (empty or > {max_chunk_chars} chars)")
        return chunks
