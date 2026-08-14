from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path


def _write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def write_text_atomic(path: Path, contents: str) -> None:
    """Replace a text result only after all bytes have been flushed to disk."""
    _write_atomic(path, contents)


def write_json_atomic(path: Path, payload: Mapping[str, object]) -> None:
    """Write deterministic, human-readable JSON through the same atomic path."""
    contents = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_atomic(path, contents)
