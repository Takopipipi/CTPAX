"""Persistent, per-binary findings store.

Reverse engineering is cumulative and a chat session is not. Renames and comments go
into the Ghidra project, but the reasoning around them - what an algorithm turned out
to be, which key decrypts which blob, what is still unexplained - has nowhere to live.
This keeps that beside the analysis, keyed by the file's SHA-256 so it follows the
binary rather than its path.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any


class Notebook:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._cache: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        try:
            self._cache = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self._cache = {"version": 1, "binaries": {}}
        if "binaries" not in self._cache:
            self._cache["binaries"] = {}
        return self._cache

    def _save(self) -> None:
        data = self._load()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)

    def add(
        self,
        key: str,
        text: str,
        *,
        tags: list[str] | None = None,
        label: str | None = None,
        confidence: str = "medium",
    ) -> dict[str, Any]:
        data = self._load()
        record = {
            "id": uuid.uuid4().hex[:8],
            "text": text,
            "tags": tags or [],
            "label": label,
            "confidence": confidence,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        bucket = data["binaries"].setdefault(key, {"notes": [], "label": label})
        if label and not bucket.get("label"):
            bucket["label"] = label
        bucket["notes"].append(record)
        self._save()
        return record

    def get(self, key: str) -> dict[str, Any]:
        bucket = self._load()["binaries"].get(key)
        if not bucket:
            return {"key": key, "note_count": 0, "notes": []}
        return {"key": key, "label": bucket.get("label"), "note_count": len(bucket["notes"]), "notes": bucket["notes"]}

    def search(self, query: str | None = None, *, regex: bool = False, limit: int = 50) -> dict[str, Any]:
        data = self._load()
        out = []
        matcher = None
        if query and regex:
            try:
                matcher = re.compile(query, re.IGNORECASE)
            except re.error as exc:
                return {"error": f"bad regex: {exc}"}
        needle = (query or "").lower()
        for key, bucket in data["binaries"].items():
            for note in bucket.get("notes", []):
                haystack = note["text"] + " " + " ".join(note.get("tags", []))
                if matcher is not None:
                    if not matcher.search(haystack):
                        continue
                elif needle and needle not in haystack.lower():
                    continue
                out.append({"key": key, "label": bucket.get("label"), **note})
        out.sort(key=lambda n: n["at"], reverse=True)
        return {"query": query, "regex": regex, "count": len(out), "notes": out[:limit]}

    def export(self, path: Path | None = None) -> Path:
        """Dump every note to a readable markdown file; returns the path written."""
        if path is None:
            path = self.path.parent / "notes_export.md"
        data = self._load()
        lines = ["# GhidraMCP notes export", ""]
        for key, bucket in sorted(data["binaries"].items()):
            lines.append(f"## {bucket.get('label') or key} (`{key}`)")
            lines.append("")
            for note in bucket.get("notes", []):
                tags = " ".join(f"#{t}" for t in note.get("tags", []))
                lines.append(f"- **{note['label']}** ({note['at']}) {tags}")
                for line_of_text in str(note.get("text", "")).splitlines():
                    lines.append(f"  {line_of_text}")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def remove(self, key: str, note_id: str) -> bool:
        data = self._load()
        bucket = data["binaries"].get(key)
        if not bucket:
            return False
        before = len(bucket["notes"])
        bucket["notes"] = [n for n in bucket["notes"] if n["id"] != note_id]
        if len(bucket["notes"]) == before:
            return False
        self._save()
        return True

    def binaries(self) -> list[dict[str, Any]]:
        data = self._load()
        return [
            {
                "key": key,
                "label": bucket.get("label"),
                "note_count": len(bucket.get("notes", [])),
                "last_note": bucket["notes"][-1]["at"] if bucket.get("notes") else None,
            }
            for key, bucket in data["binaries"].items()
        ]
