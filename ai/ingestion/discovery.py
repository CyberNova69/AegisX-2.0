"""Source discovery: scan a path for candidate ingestion sources.

Recursively walks a directory (or accepts a single file) and returns candidate
source files with their detected format. Respects the same ignore rules as a
normal VCS checkout so we never try to ingest .git, venvs, caches, etc.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .detection import detect_format
from .types import Format

# Directories we never descend into.
_DEFAULT_SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    "node_modules", ".idea", ".vscode", "checkpoints", "models",
}

# Extensions we consider worth inspecting by default.
_DEFAULT_EXTS = {
    ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml",
    ".log", ".txt", ".xlsx", ".xls", ".parquet",
}


@dataclass
class SourceFile:
    path: str
    size: int
    extension: str
    format: Format
    confidence: float


def discover(
    input_path: str,
    recursive: bool = True,
    extensions: Optional[Iterable[str]] = None,
    skip_dirs: Optional[Iterable[str]] = None,
    max_depth: Optional[int] = None,
) -> List[SourceFile]:
    """Discover candidate source files under `input_path`.

    Args:
        input_path: file or directory to scan.
        recursive: descend into subdirectories.
        extensions: allowed extensions (e.g. {".csv", ".json"}). Defaults to common
            data extensions. Use None to accept everything.
        skip_dirs: directory names to skip. Defaults to a sensible VCS/venv set.
        max_depth: optional maximum directory depth relative to input_path.

    Returns:
        List of SourceFile, sorted by path.
    """
    exts = {e.lower() for e in (extensions or _DEFAULT_EXTS)}
    skips = set(skip_dirs or _DEFAULT_SKIP_DIRS)
    p = Path(input_path)

    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = _walk(p, recursive, skips, max_depth, base_depth=len(p.parts))
    else:
        return []

    results: List[SourceFile] = []
    for f in files:
        if exts and f.suffix.lower() not in exts:
            continue
        fmt, conf = detect_format(str(f))
        results.append(SourceFile(
            path=str(f),
            size=f.stat().st_size,
            extension=f.suffix.lower(),
            format=fmt,
            confidence=conf,
        ))
    results.sort(key=lambda s: s.path)
    return results


def _walk(root: Path, recursive: bool, skips: set, max_depth: Optional[int], base_depth: int):
    out = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except (PermissionError, OSError):
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                if e.name in skips:
                    continue
                depth = len(Path(e.path).parts) - base_depth
                if recursive and (max_depth is None or depth < max_depth):
                    stack.append(Path(e.path))
            elif e.is_file(follow_symlinks=False):
                out.append(Path(e.path))
    return out
