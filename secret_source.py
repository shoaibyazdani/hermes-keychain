"""``KeychainSource`` — the macOS Keychain as a mapped Hermes secret source.

Resolution order at startup is Hermes's own: ``~/.hermes/.env`` loads first, then enabled
secret sources are pulled and applied under the orchestrator's precedence rules
(``override_existing`` etc.). This source contributes values and nothing else — it never
writes ``os.environ`` itself.

Two ways a variable gets bound:

1. **Explicit** — ``secrets.keychain.env`` maps an env-var name to a keychain account::

       secrets:
         keychain:
           enabled: true
           env:
             ANTHROPIC_API_KEY: anthropic-prod

2. **Discovered** — anything stored through this plugin (``hermes keychain put NAME``,
   or the ``keychain_migrate`` tool) is recorded in a keychain-resident index, and every
   indexed name that looks like an environment variable is bound to its own account. That
   makes the common case zero-config: store it once, restart, done.
"""

from __future__ import annotations

import sys
from pathlib import Path

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource, coerce_float

try:  # package load (Hermes plugin loader)
    from . import keychain_core as kc
except ImportError:  # direct module load (unit tests)
    import keychain_core as kc

# Bound the work one fetch may do; a source has a wall-clock budget and startup must stay fast.
MAX_ITEMS = 128

_KIND_MAP = {
    kc.NOT_FOUND: ErrorKind.EMPTY_VALUE,
    kc.AUTH_FAILED: ErrorKind.AUTH_FAILED,
    kc.TIMEOUT: ErrorKind.TIMEOUT,
    kc.INTERNAL: ErrorKind.INTERNAL,
}


class KeychainSource(SecretSource):
    """Resolve provider credentials from the login keychain on macOS."""

    name = "keychain"
    label = "macOS Keychain"
    shape = "mapped"
    override_existing_default = False
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: (
            "Store a value with `hermes keychain put NAME`, or bind an existing item under "
            "secrets.keychain.env in config.yaml (env-name: keychain-account)."
        ),
        ErrorKind.AUTH_FAILED: (
            "The login keychain is locked or the item's ACL denies access — unlock it "
            "(`security unlock-keychain`) and retry; unattended runs cannot answer a prompt."
        ),
        ErrorKind.EMPTY_VALUE: (
            "The item exists but the name is not bound to a variable — check secrets.keychain.env "
            "or re-store it with `hermes keychain put NAME` so it lands in the index."
        ),
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch for the keychain source", "default": False},
            "service": {"description": "Keychain service name for items this plugin owns",
                        "default": kc.DEFAULT_SERVICE},
            "env": {"description": "Explicit bindings: ENV_VAR -> keychain account", "default": {}},
            "discover": {"description": "Also bind every indexed item whose name looks like an env var",
                         "default": True},
            "override_existing": {"description": "Keychain values overwrite .env / shell values",
                                  "default": False},
            "timeout_seconds": {"description": "Hard timeout for a single keychain read",
                                "default": kc.DEFAULT_TIMEOUT},
        }

    # -- helpers ----------------------------------------------------------------------

    @staticmethod
    def _bindings(cfg: dict) -> dict[str, str]:
        """Validated explicit ``env`` bindings; malformed entries are dropped, not fatal."""
        raw = cfg.get("env")
        out: dict[str, str] = {}
        if not isinstance(raw, dict):
            return out
        for env_name, account in raw.items():
            if not isinstance(env_name, str) or not kc.ENV_NAME_RE.match(env_name):
                continue
            if isinstance(account, str) and account.strip():
                out[env_name] = account.strip()
        return out

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()

        if sys.platform != "darwin" or not kc.is_supported():
            return result.fail(
                "the keychain secret source is macOS-only (needs /usr/bin/security)", ErrorKind.NOT_CONFIGURED)

        service = str(cfg.get("service") or kc.DEFAULT_SERVICE).strip() or kc.DEFAULT_SERVICE
        timeout = coerce_float(cfg.get("timeout_seconds", kc.DEFAULT_TIMEOUT), kc.DEFAULT_TIMEOUT)
        timeout = timeout if timeout > 0 else kc.DEFAULT_TIMEOUT

        wanted: dict[str, str] = dict(self._bindings(cfg))

        if cfg.get("discover", True) is not False:
            try:
                indexed = kc.list_index(service, timeout)
            except kc.KeychainError as exc:
                result.warnings.append(f"could not read the keychain index: {exc}")
                indexed = []
            for name in indexed:
                if kc.ENV_NAME_RE.match(name) and name not in wanted:
                    wanted[name] = name

        if not wanted:
            # Enabled but nothing stored yet: a fresh install must not look broken at startup.
            result.warnings.append(
                "no keychain items are bound yet — `hermes keychain put NAME` stores one, "
                "or bind an existing item under secrets.keychain.env")
            return result
        if len(wanted) > MAX_ITEMS:
            result.warnings.append(f"only the first {MAX_ITEMS} bindings were fetched")
            wanted = dict(list(wanted.items())[:MAX_ITEMS])

        auth_failures = 0
        for env_name, account in wanted.items():
            try:
                value, ms = kc.timed(kc.read_secret, service, account, timeout)
            except kc.KeychainError as exc:
                kind = _KIND_MAP.get(exc.kind, ErrorKind.INTERNAL)
                kc.record("fetch", env=env_name, account=account, service=service, ok=False,
                          kind=exc.kind)
                if kind is ErrorKind.AUTH_FAILED:
                    auth_failures += 1
                if kind is ErrorKind.EMPTY_VALUE:
                    result.skipped.append(env_name)
                    result.warnings.append(f"{env_name}: no keychain item {service}/{account}")
                else:
                    result.warnings.append(f"{env_name}: {exc}")
                continue

            kc.record("fetch", env=env_name, account=account, service=service, ok=True, ms=ms)
            if not value:
                result.skipped.append(env_name)
                result.warnings.append(f"{env_name}: the keychain item is empty")
                continue
            result.secrets[env_name] = value
            result.applied.append(env_name)

        if auth_failures and not result.secrets:
            return result.fail(
                f"the keychain refused access to {auth_failures} item(s); nothing was applied",
                ErrorKind.AUTH_FAILED)
        if auth_failures:
            result.warnings.append(f"{auth_failures} item(s) were refused by the keychain")
        return result
