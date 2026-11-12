"""Read-only `.env` helpers for the migration planner, plus the backup step.

**This module never writes `.env`.** Removing a variable is core's job:
``hermes_cli.config.remove_env_value()`` (what `hermes config unset` calls) takes core's
`.env` lock and refuses when the install is package-managed or the key is admin-managed —
guarantees a plugin-local file writer cannot reproduce. Migration therefore only *reads*
here, and hands the actual removal to core.

`backup()` is the one writing helper: a timestamped copy at mode 0600, so an operator can
recover a value if the keychain item is later deleted.
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
