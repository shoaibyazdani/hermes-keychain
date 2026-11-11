"""Test harness: put the plugin directory (and the host Hermes tree) on ``sys.path``.

The plugin modules fall back to flat imports when no package context exists, so the suite can
import them directly — no package alias, no dependency on the directory being a valid Python
identifier. ``secret_source`` needs the host's ``agent.secret_sources.base``; when pytest runs
outside the ``hermes`` launcher, that tree is added here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ensure_host_tree() -> None:
    try:
        import agent.secret_sources.base  # noqa: F401
        return
    except ImportError:
        pass
    home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
    for candidate in (home / "hermes-agent", home / "hermes-agent" / "src"):
        if (candidate / "agent").is_dir():
            sys.path.insert(0, str(candidate))
            return


_ensure_host_tree()
