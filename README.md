# hermes-keychain

**Your Hermes API keys belong in the OS keystore, not in a text file.**

`hermes-keychain` makes the macOS Keychain a first-class [Hermes Agent](https://github.com/NousResearch/hermes-agent)
*secret source*. Credentials are resolved from the login keychain at process startup — after
`.env` loads, before the first model call — so a stolen `.env`, a committed dotfile, a screen
share or a backup never contains a live key.

Built for the **Nous Research Hermes Agent Plugin Hackathon** (Nov 2026).

```
hermes keychain put OPENAI_API_KEY     # prompts, no echo, verified readback
hermes keychain migrate                # move every .env key into the keychain
hermes keychain status                 # what is vault-backed, what is still plaintext
```

---

## Why this is a plugin and not a skill

Hermes's credential pipeline has a documented extension point — `SecretSource` — and a skill
cannot reach it. `load_hermes_dotenv()` loads `~/.hermes/.env`, then the orchestrator
(`agent.secret_sources.registry.apply_all`) pulls every enabled source, resolves precedence
(mapped beats bulk, first-claim-wins, `override_existing`), and only then writes
`os.environ`. A plugin sits *inside* that sequence; a shell command or a skill can only run
before or after it.

The result is that Hermes resolves `ANTHROPIC_API_KEY` from the keystore with no wrapper
script, no `op run`, no exported shell profile — the same call path it uses for `.env`.

## What you get

| Surface | Name | What it does |
|---|---|---|
| Secret source | `secrets.keychain` | Resolves bound credentials into the environment at startup |
| Tool | `keychain_status` | Vault-backed vs plaintext inventory, bindings, recent fetches |
| Tool | `keychain_migrate` | Moves `.env` keys into the keychain, verifies, strips the value |
| Tool | `keychain_audit` | The append-only fetch/migrate trail (names and outcomes, never values) |
| CLI | `hermes keychain` | `put`, `ls`, `rm`, `test`, `migrate`, `status`, `audit` |

## Install

```bash
hermes plugins install shoaibyazdani/hermes-keychain
hermes keychain status                 # shows what is bound, what is still plaintext
hermes config set secrets.keychain.enabled true
```

Restart the gateway (or start a new `hermes` session) so startup resolution runs.

## Store and migrate

Prompted, no echo, value verified by readback before the command reports success:

```bash
hermes keychain put OPENAI_API_KEY
```

Already have keys in `~/.hermes/.env`? Move them — per key: **store → read back → compare →
only then** replace the `.env` line with a comment that names the variable. `.env` is backed
up to `.env.bak-<utc>` (mode 0600) first, unrelated lines and ordering are untouched, and a
failed store leaves `.env` alone.

```bash
hermes keychain migrate --dry-run       # report only
hermes keychain migrate                 # credential-looking names
hermes keychain migrate OPENAI_API_KEY ANTHROPIC_API_KEY
```

From a session you can simply ask: *"move my plaintext API keys into the keychain"* — the
agent calls `keychain_migrate`.

Then confirm resolution really happens without `.env`:

```bash
hermes keychain test OPENAI_API_KEY     # ok (51 chars, service hermes)
hermes keychain audit --limit 10        # fetch  OPENAI_API_KEY  ok  71ms
```

## Configuration

```yaml
secrets:
  keychain:
    enabled: true
    service: hermes            # keychain service for items this plugin owns
    discover: true             # bind every indexed item whose name is env-shaped
    override_existing: false   # let the keychain win over .env / shell values
    timeout_seconds: 8
    env:                       # optional explicit bindings: ENV_VAR -> keychain account
      ANTHROPIC_API_KEY: anthropic-prod
```

Two binding modes, both supported at once:

* **Discovered (zero-config)** — anything stored through this plugin is recorded in an index
  kept *inside the keychain* (`hermes!index`). Every indexed name that looks like an
  environment variable is bound to its own account. Store it once, restart, done.
* **Explicit** — map a variable to an existing keychain account you already have (a
  different service, a shared item, a name that is not env-shaped).

## Security model

* **Read-only source.** It contributes values to Hermes's orchestrator and never writes
  `os.environ`, never edits `config.yaml`, never prompts.
* **Fail-open startup.** A locked keychain, a missing item, a denied ACL — every failure is
  classified (`not_found`, `auth_failed`, `timeout`) and reported as a warning, so a broken
  keychain cannot stop Hermes from starting. `security` runs with stdin closed and a hard
  timeout: an unattended run never hangs on a prompt.
* **Values never leave the keystore except into the process env.** They are not logged, not
  in the audit trail, not in tool output, not in error messages. `keychain_status` reports
  names, lengths and outcomes only.
* **Atomic, minimal `.env` edits.** Mode preserved, temp file + `os.replace`, timestamped
  0600 backup, value-only removal.
* **One honest caveat.** `security add-generic-password` takes the secret on argv, so for the
  microseconds it runs the value is visible to same-user processes (`ps`). Storing via
  `put`/`migrate` is a local, one-shot operation; *reads* — the hot path, once per process —
  never put a value on argv. A Keychain Framework binding could remove even that window; it
  is not worth a hard dependency on PyObjC here.

## Platform

macOS only (`/usr/bin/security`). On any other platform the source reports
`not_configured` and the tools explain why — nothing else breaks. Linux/Windows users get
the same contract through the bundled `command` source (`secret-tool`, `keepassxc-cli`,
`pass`) without a plugin.

## Tests

Pure logic (dotenv editing, index parsing, failure classification, binding discovery) is
covered by unit tests that never touch the real keychain:

```bash
python -m pytest        # 14 tests
hermes plugins doctor . # runtime contracts: discovery, manifest, register()
hermes plugins validate . --install-deps   # the catalog CI gate
```

## License

MIT
