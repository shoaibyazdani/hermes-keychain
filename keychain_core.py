"""macOS Keychain primitives for the ``keychain`` plugin.

A thin, testable wrapper over ``/usr/bin/security`` — no Python keychain bindings, no
shell. The binary is addressed by **absolute path**: ``security`` receives secret values on
argv, so resolving it through ``PATH`` would hand every stored value to whatever earlier
``security`` a modified ``PATH`` put in front of it. Every call is an argv list, the child
gets a minimal allowlisted environment, stdin is ``/dev/null`` (so a locked-keychain prompt
fails fast instead of hanging Hermes startup), every call has a hard timeout, and **no
value is ever logged**.

This module deliberately has no relative imports so it can be unit-tested on its own.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

DEFAULT_SERVICE = "hermes"
INDEX_SERVICE_SUFFIX = "!index"
INDEX_ACCOUNT = "index"
INDEX_VERSION = 1
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_TIMEOUT = 8.0
# Cap on items one migration call will move, so a `*` sweep stays reviewable.
MAX_MIGRATE = 50
AUDIT_MAX_BYTES = 512 * 1024
AUDIT_KEEP_LINES = 500

# `security` reports failures on stderr; the CLI collapses several OSStatus codes onto text,
# so classify on text first and fall back to the exit code.
_NOT_FOUND_HINTS = ("could not be found", "item not found", "secitemnotfound", "errsecitemnotfound")
_AUTH_HINTS = (
    "user interaction is not allowed",
    "passphrase you entered is not correct",
    "authorization denied",
    "not authorized",
    "errsecauthfailed",
    "user canceled",
    "the user name or passphrase",
)

# Failure taxonomy shared with SecretSource.ErrorKind (kept as plain strings here so this
# module stays importable outside a Hermes process).
NOT_FOUND = "not_found"
AUTH_FAILED = "auth_failed"
TIMEOUT = "timeout"
INTERNAL = "internal"


class KeychainError(Exception):
    """A ``security`` invocation failed. ``kind`` is a taxonomy slug, never a value."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Item:
    """One generic-password item, by name only."""

    service: str
    account: str


# Absolute path only. `security` receives values on argv, so it is never resolved through PATH.
SECURITY_BIN = "/usr/bin/security"


def is_supported() -> bool:
    """True on macOS with the system ``security`` CLI present."""
    return sys.platform == "darwin" and Path(SECURITY_BIN).exists()


def _security_bin() -> Optional[str]:
    return SECURITY_BIN if Path(SECURITY_BIN).exists() else None


def _child_env() -> dict[str, str]:
    """Minimal environment for ``security``: never the full post-dotenv ``os.environ``."""
    keep = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    env.setdefault("NO_COLOR", "1")
    return env


def _run(argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """Run ``security`` with stdin closed. Raises :class:`KeychainError` on spawn/timeout."""
    binary = _security_bin()
    if binary is None:
        raise KeychainError(INTERNAL, f"{SECURITY_BIN} is missing; this source is macOS-only")
    try:
        return subprocess.run(
            [binary, *argv],
            env=_child_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise KeychainError(TIMEOUT, f"`security {argv[0]}` timed out after {timeout:g}s") from None
    except OSError as exc:
        raise KeychainError(INTERNAL, f"could not run `security`: errno={exc.errno}") from None


def _classify(proc: subprocess.CompletedProcess) -> KeychainError:
    text = f"{proc.stderr or ''} {proc.stdout or ''}".lower()
    if any(hint in text for hint in _NOT_FOUND_HINTS):
        return KeychainError(NOT_FOUND, "item not found in the keychain")
    if any(hint in text for hint in _AUTH_HINTS):
        return KeychainError(AUTH_FAILED, "the keychain refused access (locked, or interaction not allowed)")
    return KeychainError(INTERNAL, f"`security` exited {proc.returncode}")


# --- item access -------------------------------------------------------------------------

def read_secret(service: str, account: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Return the stored password for ``service``/``account``.

    Raises :class:`KeychainError` with ``kind == NOT_FOUND`` when the item is absent. The
    value is returned to the caller only; it is never logged, echoed or put in an error.
    """
    proc = _run(["find-generic-password", "-s", service, "-a", account, "-w"], timeout)
    if proc.returncode != 0:
        raise _classify(proc)
    value = proc.stdout or ""
    # `security` appends exactly one newline; the password itself may contain anything else.
    return value[:-1] if value.endswith("\n") else value


def has_item(service: str, account: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """True when the item exists (never returns the value)."""
    try:
        read_secret(service, account, timeout)
        return True
    except KeychainError as exc:
        if exc.kind == NOT_FOUND:
            return False
        raise


def write_secret(service: str, account: str, value: str, timeout: float = DEFAULT_TIMEOUT) -> None:
    """Create or replace an item (``-U``), then verify the readback.

    The value travels on argv, which macOS exposes to same-user processes only; that window
    is the one documented caveat of shelling out to ``security``. Verification means a silent
    truncation or an ACL failure is reported here rather than surfacing as a dead API key at
    the next model call.
    """
    if not value:
        raise KeychainError(INTERNAL, "refusing to store an empty secret")
    proc = _run(["add-generic-password", "-U", "-s", service, "-a", account, "-w", value], timeout)
    if proc.returncode != 0:
        raise _classify(proc)
    try:
        stored = read_secret(service, account, timeout)
    except KeychainError as exc:
        raise KeychainError(exc.kind, f"stored, but the readback failed: {exc}") from None
    if stored != value:
        raise KeychainError(INTERNAL, "readback did not match the value written")


def delete_secret(service: str, account: str, timeout: float = DEFAULT_TIMEOUT) -> None:
    """Remove an item. A missing item is not an error."""
    proc = _run(["delete-generic-password", "-s", service, "-a", account], timeout)
    if proc.returncode != 0:
        err = _classify(proc)
        if err.kind != NOT_FOUND:
            raise err


# --- index ------------------------------------------------------------------------------
#
# Discovery needs the list of items this plugin owns. `security dump-keychain` would mean
# parsing a fragile, undocumented dump, so the plugin keeps its own index **inside the
# keychain** (service `<service>!index`): it travels with the login keychain, needs no file
# on disk, and reading it is one `security` call.

def _index_item(service: str) -> Item:
    return Item(service=f"{service}{INDEX_SERVICE_SUFFIX}", account=INDEX_ACCOUNT)


def list_index(service: str = DEFAULT_SERVICE, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Account names this plugin has stored under ``service``, in insertion order."""
    item = _index_item(service)
    try:
        raw = read_secret(item.service, item.account, timeout)
    except KeychainError as exc:
        if exc.kind == NOT_FOUND:
            return []
        raise
    return parse_index(raw)


def parse_index(raw: str) -> list[str]:
    """Parse the index blob. A corrupt index degrades to "no names" — never an exception."""
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return []
    names = data.get("names") if isinstance(data, dict) else None
    if not isinstance(names, list):
        return []
    seen: list[str] = []
    for name in names:
        if isinstance(name, str) and name and name not in seen:
            seen.append(name)
    return seen


def save_index(service: str, names: Iterable[str], timeout: float = DEFAULT_TIMEOUT) -> None:
    """Persist the index. Rewrites the whole blob (the index is dozens of names at most)."""
    blob = json.dumps({"version": INDEX_VERSION, "names": list(names)}, separators=(",", ":"))
    write_secret(_index_item(service).service, INDEX_ACCOUNT, blob, timeout)


def index_add(service: str, name: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    names = list_index(service, timeout)
    if name not in names:
        names.append(name)
        save_index(service, names, timeout)
    return names


def index_remove(service: str, name: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    names = [n for n in list_index(service, timeout) if n != name]
    if names:
        save_index(service, names, timeout)
    else:
        try:
            delete_secret(_index_item(service).service, INDEX_ACCOUNT, timeout)
        except KeychainError:
            pass
    return names


# --- audit log --------------------------------------------------------------------------

def audit_path(plugin: str = "keychain") -> Optional[Path]:
    """``<hermes home>/plugin-data/<plugin>/audit.jsonl``; None if the home is unresolvable."""
    try:
        from hermes_constants import get_hermes_home

        root = Path(get_hermes_home()) / "plugin-data" / plugin
        root.mkdir(parents=True, exist_ok=True)
        return root / "audit.jsonl"
    except Exception:
        return None


def record(event: str, *, env: str = "", account: str = "", service: str = DEFAULT_SERVICE,
           ok: bool = True, kind: str = "", ms: float = 0.0, extra: Optional[dict] = None) -> None:
    """Append one audit line. Structured fields only — a value can never reach this function."""
    path = audit_path()
    if path is None:
        return
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "ok": bool(ok),
        "env": env,
        "service": service,
        "ms": round(ms, 1),
    }
    if account:
        entry["account"] = account
    if kind:
        entry["kind"] = kind
    if extra:
        entry.update({k: v for k, v in extra.items() if isinstance(v, (str, int, float, bool))})
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        _rotate(path)
    except OSError:
        return


def read_audit(limit: int = 20) -> list[dict]:
    """Most recent audit entries, newest last."""
    path = audit_path()
    if path is None or not path.exists():
        return []
    out: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict):
                    out.append(entry)
    except OSError:
        return []
    return out[-max(1, limit):]


def _rotate(path: Path) -> None:
    """Keep the audit log bounded without ever blocking a fetch."""
    try:
        if path.stat().st_size <= AUDIT_MAX_BYTES:
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-AUDIT_KEEP_LINES:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        return


def timed(fn, *args, **kwargs) -> tuple[Any, float]:
    """Run ``fn`` and return ``(result, milliseconds)``. Exceptions propagate unchanged."""
    started = time.monotonic()
    result = fn(*args, **kwargs)
    return result, (time.monotonic() - started) * 1000.0
