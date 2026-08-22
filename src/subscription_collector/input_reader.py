from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit


class InputError(ValueError):
    """Raised when the user-maintained subscription list is invalid."""


def read_input_urls(path: Path) -> list[str]:
    """Read unique HTTPS subscription URLs while ignoring blank lines and comments."""
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InputError(f"cannot read input file: {path}") from error

    values: list[str] = []
    seen: set[str] = set()
    for raw_line in raw_lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            parsed = urlsplit(line)
        except ValueError as error:
            raise InputError(f"input URL is malformed: {line}") from error
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise InputError(f"input URL must be an HTTPS URL without credentials: {line}")
        if line not in seen:
            seen.add(line)
            values.append(line)

    if not values:
        raise InputError("input.txt contains no HTTPS subscription URLs")
    return values
