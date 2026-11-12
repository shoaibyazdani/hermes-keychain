"""Agent tools: inspect binding state, plan a migration, read the audit trail.

**No tool here writes anything.** In particular ``keychain_migration_plan`` is report-only:
it never stores a secret and never touches `.env`. Migration happens only in the
``hermes keychain migrate`` CLI, which the operator runs — a model choosing secret names and
rewriting `<hermes home>/.env` unattended is the failure mode Hermes keeps the model away
from (and if the source is off or the login keychain is locked at the next startup, every
migrated key would be gone).

Every handler returns a JSON string, never raises, and never emits a secret value — only
names, lengths and outcomes.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

try:  # package load (Hermes plugin loader)
    from . import dotenv_edit
except ImportError:  # direct module load (unit tests)
    import dotenv_edit
try:  # package load (Hermes plugin loader)
    from . import keychain_core as kc
except ImportError:  # direct module load (unit tests)
    import keychain_core as kc

# A `*` sweep only touches names that look like credentials, or values that look like tokens.
_SECRETISH_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASS|PWD|CREDENTIAL|AUTH|API|DSN|PRIVATE)", re.I)
_TOKENISH_VALUE = re.compile(r"^[A-Za-z0-9_\-+=/.:@~]{24,}$")


# --- shared helpers ---------------------------------------------------------------------

def _err(message: str, **extra: Any) -> str:
    return json.dumps({"ok": False, "error": message, **extra})


def _looks_like_credential(name: str, value: str) -> bool:
    """Name says key/token/secret, or the value is a long opaque token (never a URL)."""
    if _SECRETISH_NAME.search(name):
        return True
    if "://" in value:
        return False
    return bool(_TOKENISH_VALUE.match(value))


def _hermes_home() -> Optional[Path]:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return None


def _source_config() -> dict:
    """The live ``secrets.keychain`` section from config.yaml ({} when unset)."""
    try:
        from hermes_cli.config import load_config

        cfg = load_config() or {}
        section = cfg.get("secrets")
        if isinstance(section, dict):
            value = section.get("keychain")
            if isinstance(value, dict):
                return value
    except Exception:
        pass
    return {}


def _service(cfg: dict) -> str:
    return str(cfg.get("service") or kc.DEFAULT_SERVICE).strip() or kc.DEFAULT_SERVICE


def _dotenv_path() -> Optional[Path]:
    home = _hermes_home()
    return (home / ".env") if home else None


def _dotenv_hits() -> tuple[Optional[Path], dict[str, dotenv_edit.DotenvHit]]:
    path = _dotenv_path()
    if path is None or not path.exists():
        return path, {}
    try:
        return path, dotenv_edit.scan(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return path, {}


def _normalize_names(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, list):
        return [part.strip() for part in raw if isinstance(part, str) and part.strip()]
    return []


# --- keychain_status --------------------------------------------------------------------

def keychain_status(args: dict, **kwargs) -> str:
    """Report which credentials are vault-backed, which are still plaintext, and recent fetches."""
    try:
        cfg = _source_config()
        service = _service(cfg)
        supported = kc.is_supported()
        bindings = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        indexed: list[str] = []
        index_error = ""
        if supported:
            try:
                indexed = kc.list_index(service)
            except kc.KeychainError as exc:
                index_error = str(exc)

        names = list(dict.fromkeys([*[str(n) for n in bindings if isinstance(n, str)], *indexed]))
        items = []
        for name in names:
            account = str(bindings.get(name) or name)
            in_keychain = False
            length: Optional[int] = None
            if supported:
                try:
                    in_keychain = kc.has_item(service, account)
                    if in_keychain:
                        length = len(kc.read_secret(service, account))
                except kc.KeychainError:
                    in_keychain = False
            items.append({
                "env": name,
                "account": account,
                "bound": "explicit" if name in bindings else "discovered",
                "in_keychain": in_keychain,
                "in_process_env": bool(os.environ.get(name)),
                "length": length,
            })

        env_path, hits = _dotenv_hits()
        vaulted = {item["env"] for item in items if item["in_keychain"]}
        plaintext = sorted(hits)
        credentials = [n for n in plaintext if _looks_like_credential(n, hits[n].value)]
        pending = [n for n in credentials if n not in vaulted]

        audit = kc.read_audit(10)
        return json.dumps({
            "ok": True,
            "supported": supported,
            "service": service,
            "enabled": bool(cfg.get("enabled")),
            "discover": cfg.get("discover", True) is not False,
            "override_existing": bool(cfg.get("override_existing")),
            "items": items,
            "plaintext_dotenv": {
                "path": str(env_path) if env_path else "",
                "count": len(plaintext),
                "credentials": credentials,
                "config": [n for n in plaintext if n not in credentials],
                "not_in_keychain": pending,
            },
            "audit": {"recent": audit},
            "index_error": index_error,
            "platform": "darwin" if kc.sys.platform == "darwin" else kc.sys.platform,
        }, indent=2)
    except Exception as exc:  # never raise out of a tool
        return _err(f"status failed: {exc.__class__.__name__}: {exc}")


# --- keychain_migration_plan ------------------------------------------------------------

# --- keychain_migration_plan ------------------------------------------------------------

def keychain_migration_plan(args: dict, **kwargs) -> str:
    """Report-only: list the keys that *could* move, and the exact command a human runs.

    Deliberately side-effect free. Storing into the keychain and removing the `.env` line
    are operator actions (`hermes keychain migrate`), because a model rewriting
    `<hermes home>/.env` unattended can strand every provider key if the source is disabled
    or the login keychain is locked at the next startup.
    """
    try:
        if not kc.is_supported():
            return _err("the keychain is macOS-only (needs /usr/bin/security)")
        cfg = _source_config()
        service = _service(cfg)
        requested = _normalize_names(args.get("names"))
        env_path, hits = _dotenv_hits()
        sweep = not requested or requested in (["*"], ["all"])

        if sweep:
            candidates = [n for n in hits if _looks_like_credential(n, hits[n].value)]
        else:
            candidates = [n for n in requested if kc.ENV_NAME_RE.match(n)]
        candidates = candidates[:kc.MAX_MIGRATE]

        try:
            already = set(kc.list_index(service))
        except kc.KeychainError:
            already = set()

        plan = []
        for name in candidates:
            live = os.environ.get(name) or (hits[name].value if name in hits else "")
            if not live:
                continue
            plan.append({
                "name": name,
                "length": len(live),
                "in_dotenv": name in hits,
                "already_in_keychain": name in already,
            })

        return json.dumps({
            "ok": True,
            "report_only": True,
            "wrote_nothing": True,
            "service": service,
            "dotenv": str(env_path) if env_path else "",
            "candidates": plan,
            "run_in_terminal": ("hermes keychain migrate " + " ".join(p["name"] for p in plan)) if plan else "",
            "what_the_command_does": (
                "stores each value in the login keychain, verifies it by readback, backs up "
                ".env (0600), then removes the variable through Hermes' own "
                "config.remove_env_value — the `hermes config unset` path, which takes core's "
                ".env lock and refuses package-managed or admin-managed keys"
            ),
            "note": "Nothing has been moved. A human runs the command; this tool never writes.",
        }, indent=2)
    except Exception as exc:
        return _err(f"plan failed: {exc.__class__.__name__}: {exc}")


# --- keychain_audit ---------------------------------------------------------------------

def keychain_audit(args: dict, **kwargs) -> str:
    """The append-only fetch/migrate trail: names, outcomes, timings. Never values."""
    try:
        limit = args.get("limit")
        try:
            limit = max(1, min(200, int(limit))) if limit is not None else 20
        except (TypeError, ValueError):
            limit = 20
        path = kc.audit_path()
        return json.dumps({
            "ok": True,
            "path": str(path) if path else "",
            "entries": kc.read_audit(limit),
        }, indent=2)
    except Exception as exc:
        return _err(f"audit failed: {exc.__class__.__name__}: {exc}")


# --- schemas ----------------------------------------------------------------------------

_EMPTY_OBJECT = {"type": "object", "properties": {}, "additionalProperties": False}

STATUS_SCHEMA = {
    "name": "keychain_status",
    "description": (
        "Report the macOS Keychain secret-source state: which credentials are vault-backed, "
        "which are still plaintext in ~/.hermes/.env, which bindings are explicit vs discovered, "
        "and the most recent fetches. Never returns secret values."
    ),
    "parameters": _EMPTY_OBJECT,
}

PLAN_SCHEMA = {
    "name": "keychain_migration_plan",
    "description": (
        "Report-only plan for moving API keys out of plaintext ~/.hermes/.env into the macOS "
        "Keychain: lists the candidates and returns the exact `hermes keychain migrate ...` "
        "command for the user to run. This tool writes nothing — no keychain item and no .env "
        "edit. Use it to advise; the human performs the migration."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "names": {
                "type": ["array", "string"],
                "items": {"type": "string"},
                "description": "Env-var names to plan for, e.g. ['OPENAI_API_KEY'], or '*' for a sweep.",
            },
        },
        "additionalProperties": False,
    },
}

AUDIT_SCHEMA = {
    "name": "keychain_audit",
    "description": (
        "Read the keychain plugin's audit trail: one line per fetch or migration with variable "
        "name, outcome, error kind and duration. Values are never recorded."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Entries to return (1-200, default 20)."},
        },
        "additionalProperties": False,
    },
}
