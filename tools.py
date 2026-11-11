"""Agent tools: inspect the binding state, migrate plaintext keys, read the audit trail.

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


# --- keychain_migrate -------------------------------------------------------------------

def keychain_migrate(args: dict, **kwargs) -> str:
    """Move named variables from .env (or the live environment) into the keychain.

    Order of operations per name is deliberate: store → verify readback (inside
    ``write_secret``) → only then strip the value out of .env. A failed store leaves
    ``.env`` untouched.
    """
    try:
        if not kc.is_supported():
            return _err("the keychain is macOS-only (needs /usr/bin/security)")
        cfg = _source_config()
        service = _service(cfg)
        dry_run = bool(args.get("dry_run"))
        requested = _normalize_names(args.get("names"))

        env_path, hits = _dotenv_hits()
        sweep = not requested or requested in (["*"], ["all"])

        if sweep:
            candidates = [n for n in hits if _looks_like_credential(n, hits[n].value)]
        else:
            candidates = [n for n in requested if kc.ENV_NAME_RE.match(n)]

        if not candidates:
            return json.dumps({
                "ok": True, "service": service, "dry_run": dry_run,
                "migrated": [], "skipped": [],
                "note": "no candidates: pass names explicitly, or use names: ['*'] for "
                        "credential-looking variables in .env",
            }, indent=2)

        migrated: list[dict] = []
        skipped: list[dict] = []
        to_strip: set[str] = set()

        for name in candidates[:kc.MAX_MIGRATE]:
            live = os.environ.get(name) or (hits[name].value if name in hits else "")
            if not live:
                skipped.append({"name": name, "reason": "no value in .env or the environment"})
                continue
            if name in os.environ and name in hits and os.environ[name] != hits[name].value:
                skipped.append({"name": name, "reason": "environment and .env disagree; "
                                                       "resolved it by hand first"})
                continue
            if dry_run:
                migrated.append({"name": name, "length": len(live), "would_store": True})
                continue
            try:
                kc.write_secret(service, name, live)
                kc.index_add(service, name)
            except kc.KeychainError as exc:
                kc.record("migrate", env=name, service=service, ok=False, kind=exc.kind)
                skipped.append({"name": name, "reason": f"store failed: {exc}"})
                continue
            kc.record("migrate", env=name, service=service, ok=True)
            if name in hits:
                to_strip.add(name)
            migrated.append({"name": name, "length": len(live), "env_line_stripped": name in hits})

        backup_path = ""
        if to_strip and not dry_run and env_path is not None:
            try:
                original = env_path.read_text(encoding="utf-8", errors="replace")
                new_text, _ = dotenv_edit.strip_names(original, to_strip)
                if new_text != original:
                    made = dotenv_edit.backup(env_path)
                    backup_path = str(made) if made else ""
                    dotenv_edit.write_atomic(env_path, new_text)
            except OSError as exc:
                return json.dumps({
                    "ok": False, "error": f"keys are in the keychain but .env could not be "
                                          f"rewritten: {exc}", "migrated": migrated,
                    "skipped": skipped, "service": service,
                }, indent=2)

        remaining = [i["name"] for i in migrated if not i.get("env_line_stripped", False)]
        return json.dumps({
            "ok": True,
            "service": service,
            "dry_run": dry_run,
            "migrated": migrated,
            "skipped": skipped,
            "dotenv": {"path": str(env_path) if env_path else "", "backup": backup_path},
            "next": ("Enable the source (secrets.keychain.enabled: true) and restart the gateway "
                     "so startup resolves these from the keychain — values already in this "
                     "process keep working until then."
                     if remaining or migrated else "nothing to do"),
        }, indent=2)
    except Exception as exc:
        return _err(f"migrate failed: {exc.__class__.__name__}: {exc}")


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

MIGRATE_SCHEMA = {
    "name": "keychain_migrate",
    "description": (
        "Move API keys out of plaintext ~/.hermes/.env into the macOS Keychain. Each value is "
        "stored, read back and compared before the .env line is replaced with a comment; .env is "
        "backed up first. Pass explicit variable names, or '*' for credential-looking ones."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "names": {
                "type": ["array", "string"],
                "items": {"type": "string"},
                "description": "Env-var names to migrate, e.g. ['OPENAI_API_KEY'], or '*' for a sweep.",
            },
            "dry_run": {
                "type": "boolean",
                "description": "Report what would move without touching the keychain or .env.",
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
