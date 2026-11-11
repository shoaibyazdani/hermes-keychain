"""`.env` editing for the migration path — pure functions, no keychain access.

Migration is the one operation that rewrites a file the user cares about, so the editing
rules are explicit and unit-tested:

* only the **value** is removed; the line is replaced by a comment that names the variable
  and says where it went, so a reader still sees why it is gone;
* the write is atomic (temp file in the same directory, mode 0600, then ``os.replace``);
* a timestamped backup is copied first (mode 0600), and the original file mode is preserved;
* nothing is stripped until the keychain readback for that name already matched.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

LINE_RE = re.compile(r"^(?P<pre>[ \t]*(?:export[ \t]+)?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?P<value>.*)$")


@dataclass(frozen=True)
class DotenvHit:
    """One variable found in a dotenv file."""

    name: str
    line_no: int
    raw_value: str

    @property
    def value(self) -> str:
        """The value with one layer of matching surrounding quotes removed."""
        return unquote_dotenv_value(self.raw_value)


def unquote_dotenv_value(raw: str) -> str:
    text = (raw or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def scan(text: str) -> dict[str, DotenvHit]:
    """Map variable name → first definition in ``text`` (later duplicates ignored)."""
    hits: dict[str, DotenvHit] = {}
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LINE_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name in hits:
            continue
        hits[name] = DotenvHit(name=name, line_no=idx, raw_value=match.group("value"))
    return hits


def strip_names(text: str, names: set[str], *, stamp: Optional[str] = None) -> tuple[str, list[str]]:
    """Return ``(new_text, removed_names)`` with each migrated variable's value erased.

    Unrelated lines, ordering, blank lines and trailing newline behaviour are preserved.
    """
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    removed: list[str] = []
    for line in text.split("\n"):
        stripped = line.strip()
        match = None if not stripped or stripped.startswith("#") else LINE_RE.match(line)
        name = match.group("name") if match else None
        if name in names and name not in removed:
            removed.append(name)
            out.append(f"# {name} moved to the macOS Keychain by hermes-keychain on {stamp} "
                       f"(secrets.keychain)")
            continue
        out.append(line)
    return "\n".join(out), removed


def write_atomic(path: Path, text: str, mode: Optional[int] = None) -> None:
    """Replace ``path`` atomically, preserving (or forcing) a 0600-style mode."""
    path = Path(path)
    if mode is None:
        mode = (path.stat().st_mode & 0o777) if path.exists() else 0o600
    tmp = path.with_name(f".{path.name}.hermes-keychain.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def backup(path: Path) -> Optional[Path]:
    """Copy ``path`` to ``<name>.bak-<utc stamp>`` with mode 0600."""
    path = Path(path)
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    return dest
