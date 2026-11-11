"""``hermes keychain ...`` — human-facing CLI for the keychain secret source.

Values are only ever read by a human at a terminal: ``put`` prompts with ``getpass`` (no
echo, no shell history, no argv), ``test`` prints a length and never the value.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

try:  # package load (Hermes plugin loader)
    from . import keychain_core as kc
except ImportError:  # direct module load (unit tests)
    import keychain_core as kc
try:  # package load (Hermes plugin loader)
    from . import tools
except ImportError:  # direct module load (unit tests)
    import tools


def register_cli(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes keychain`` subcommand tree."""
    subs = parser.add_subparsers(dest="keychain_command")

    subs.add_parser("status", help="Binding, plaintext and audit summary")
    subs.add_parser("ls", help="List stored item names")

    put = subs.add_parser("put", help="Store or replace a secret (prompts, no echo)")
    put.add_argument("name", help="Env-var-shaped name, e.g. OPENAI_API_KEY")
    put.add_argument("--service", default=None, help=f"Keychain service (default: {kc.DEFAULT_SERVICE})")
    put.add_argument("--stdin", action="store_true", help="Read the value from stdin (pipes/CI)")
    put.add_argument("--allow-non-env", action="store_true",
                     help="Allow a name that cannot be discovered as an env var")

    rm = subs.add_parser("rm", help="Delete an item and drop it from the index")
    rm.add_argument("name")
    rm.add_argument("--service", default=None)

    test = subs.add_parser("test", help="Check that an item exists and reads back")
    test.add_argument("name")
    test.add_argument("--service", default=None)

    migrate = subs.add_parser("migrate", help="Move .env keys into the keychain")
    migrate.add_argument("names", nargs="*", help="Variable names; omit for a credential-looking sweep")
    migrate.add_argument("--dry-run", action="store_true")

    audit = subs.add_parser("audit", help="Show the audit trail")
    audit.add_argument("--limit", type=int, default=20)

    parser.set_defaults(func=dispatch)


def dispatch(args: argparse.Namespace) -> int:
    sub = getattr(args, "keychain_command", None)
    if sub is None:
        return _status(args)
    handler = _COMMANDS.get(sub)
    if handler is None:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    return handler(args)


# --- handlers ---------------------------------------------------------------------------

def _service(args: argparse.Namespace) -> str:
    return getattr(args, "service", None) or kc.DEFAULT_SERVICE


def _guard_platform() -> bool:
    if kc.is_supported():
        return True
    print("the keychain secret source is macOS-only (needs /usr/bin/security)", file=sys.stderr)
    return False


def _status(args: argparse.Namespace) -> int:
    report = json.loads(tools.keychain_status({}))
    if not report.get("ok"):
        print(f"error: {report.get('error')}", file=sys.stderr)
        return 1

    dot = report["plaintext_dotenv"]
    items = report["items"]
    vaulted = [i for i in items if i["in_keychain"]]
    print(f"service      {report['service']}")
    print(f"enabled      {'yes' if report['enabled'] else 'no'}")
    print(f"discovery    {'on' if report['discover'] else 'off'}")
    print(f"keychain     {len(vaulted)} of {len(items)} bound item(s) present")
    for item in items:
        mark = "ok " if item["in_keychain"] else "MISSING"
        print(f"  [{mark}] {item['env']:<28} {item['bound']:<10} "
              f"{'set in env' if item['in_process_env'] else ''}")
    print(f"plaintext    {dot['count']} variable(s) in {dot['path'] or '.env'}")
    leaked = dot["not_in_keychain"]
    if leaked:
        print("  not vault-backed: " + ", ".join(leaked))
        print("  → migrate them: hermes keychain migrate " + " ".join(leaked[:5])
              + (" …" if len(leaked) > 5 else ""))
    recent = report["audit"]["recent"]
    if recent:
        print("recent       " + ", ".join(
            f"{e.get('event')}:{e.get('env') or '-'}:{'ok' if e.get('ok') else e.get('kind') or 'fail'}"
            for e in recent[-5:]))
    return 0


def _ls(args: argparse.Namespace) -> int:
    if not _guard_platform():
        return 1
    names = kc.list_index(_service(args))
    if not names:
        print("no items stored yet — `hermes keychain put NAME`")
        return 0
    for name in names:
        print(name)
    return 0


def _put(args: argparse.Namespace) -> int:
    if not _guard_platform():
        return 1
    name = args.name.strip()
    if not name:
        print("name is required", file=sys.stderr)
        return 2
    if not kc.ENV_NAME_RE.match(name) and not args.allow_non_env:
        print(f"{name!r} is not an env-var name, so no Hermes credential could ever use it; "
              f"pass --allow-non-env to store it anyway", file=sys.stderr)
        return 2

    if args.stdin:
        value = sys.stdin.readline().rstrip("\n")
        if not value:
            print("no value on stdin", file=sys.stderr)
            return 2
    else:
        value = getpass.getpass(f"Value for {name}: ")
        if not value:
            print("empty value, nothing stored", file=sys.stderr)
            return 2
        if getpass.getpass("Retype to confirm: ") != value:
            print("values did not match, nothing stored", file=sys.stderr)
            return 1

    service = _service(args)
    try:
        kc.write_secret(service, name, value)
        kc.index_add(service, name)
        kc.record("put", env=name, account=name, service=service, ok=True)
    except kc.KeychainError as exc:
        kc.record("put", env=name, account=name, service=service, ok=False, kind=exc.kind)
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    print(f"stored {name} in the keychain (service {service}, {len(value)} chars, verified)")
    print("enable it for startup resolution: hermes config set secrets.keychain.enabled true")
    return 0


def _rm(args: argparse.Namespace) -> int:
    if not _guard_platform():
        return 1
    service = _service(args)
    try:
        kc.delete_secret(service, args.name)
        remaining = kc.index_remove(service, args.name)
    except kc.KeychainError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    kc.record("rm", env=args.name, account=args.name, service=service, ok=True,
              extra={"remaining": len(remaining)})
    print(f"removed {args.name} ({len(remaining)} item(s) left)")
    return 0


def _test(args: argparse.Namespace) -> int:
    if not _guard_platform():
        return 1
    service = _service(args)
    try:
        value = kc.read_secret(service, args.name)
    except kc.KeychainError as exc:
        print(f"{args.name}: {exc}", file=sys.stderr)
        return 1
    print(f"{args.name}: ok ({len(value)} chars, service {service})")
    return 0


def _migrate(args: argparse.Namespace) -> int:
    names = list(args.names) or ["*"]
    report = json.loads(tools.keychain_migrate({"names": names, "dry_run": args.dry_run}))
    if not report.get("ok"):
        print(f"error: {report.get('error')}", file=sys.stderr)
        return 1
    moved = report.get("migrated") or []
    skipped = report.get("skipped") or []
    verb = "would move" if args.dry_run else "moved"
    for entry in moved:
        suffix = "" if args.dry_run else (
            ", .env stripped" if entry.get("env_line_stripped") else ", live env only")
        print(f"  {verb} {entry['name']} ({entry['length']} chars{suffix})")
    for entry in skipped:
        print(f"  skipped {entry['name']}: {entry['reason']}")
    if not moved and not skipped:
        print(report.get("note") or "nothing to do")
    backup = (report.get("dotenv") or {}).get("backup")
    if backup:
        print(f"backup: {backup}")
    if moved and not args.dry_run:
        print(report.get("next", ""))
    return 0


def _audit(args: argparse.Namespace) -> int:
    report = json.loads(tools.keychain_audit({"limit": args.limit}))
    entries = report.get("entries") or []
    if not entries:
        print("no audit entries yet")
        return 0
    for entry in entries:
        status = "ok" if entry.get("ok") else (entry.get("kind") or "fail")
        print(f"{entry.get('ts', '?')}  {entry.get('event', '?'):<8} "
              f"{(entry.get('env') or '-'):<28} {status:<12} {entry.get('ms', '')}ms")
    return 0


_COMMANDS = {
    "status": _status,
    "ls": _ls,
    "put": _put,
    "rm": _rm,
    "test": _test,
    "migrate": _migrate,
    "audit": _audit,
}
