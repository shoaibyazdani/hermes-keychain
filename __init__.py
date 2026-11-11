"""keychain — the macOS Keychain as a Hermes secret source.

Registers three public surfaces, each independently guarded so one failure cannot take the
others (or plugin load) down with it:

* a :class:`SecretSource` (``secrets.keychain``) — credential resolution at startup;
* three tools — ``keychain_status``, ``keychain_migrate``, ``keychain_audit``;
* a CLI command — ``hermes keychain put|ls|rm|test|migrate|status|audit``.
"""

from __future__ import annotations

import logging

try:  # package load (Hermes plugin loader)
    from . import cli, tools
    from .secret_source import KeychainSource
except ImportError:  # direct module load (unit tests, ad-hoc scripts)
    import cli
    import tools
    from secret_source import KeychainSource

logger = logging.getLogger(__name__)

_TOOLS = (
    (tools.STATUS_SCHEMA, tools.keychain_status, "Inspect keychain bindings and plaintext .env keys", "🔑"),
    (tools.MIGRATE_SCHEMA, tools.keychain_migrate, "Move .env keys into the macOS Keychain", "🔐"),
    (tools.AUDIT_SCHEMA, tools.keychain_audit, "Read the keychain fetch/migrate audit trail", "📜"),
)


def register(ctx) -> None:
    """Wire the secret source, tools and CLI into the host."""
    try:
        ctx.register_secret_source(KeychainSource())
    except Exception:
        logger.warning("keychain: failed to register the secret source", exc_info=True)

    for schema, handler, description, emoji in _TOOLS:
        try:
            ctx.register_tool(
                name=schema["name"],
                toolset="keychain",
                schema=schema,
                handler=handler,
                description=description,
                emoji=emoji,
            )
        except Exception:
            logger.warning("keychain: failed to register tool %s", schema.get("name"), exc_info=True)

    try:
        ctx.register_cli_command(
            name="keychain",
            help="macOS Keychain secret source (put, ls, rm, test, migrate, status)",
            setup_fn=cli.register_cli,
            handler_fn=cli.dispatch,
            description=(
                "Store, verify and migrate API keys in the macOS login keychain so Hermes "
                "resolves them at startup instead of reading plaintext .env values."
            ),
        )
    except Exception:
        logger.warning("keychain: failed to register the `hermes keychain` CLI command", exc_info=True)
