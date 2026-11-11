"""Unit tests for the pure parts: dotenv editing, index parsing, source fetch logic.

Keychain access itself is monkeypatched — the suite never touches the real login keychain,
so it is safe to run anywhere, including CI on Linux.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dotenv_edit  # noqa: E402
import keychain_core as kc  # noqa: E402


# --- dotenv editing ---------------------------------------------------------------------

DOTENV = """# Hermes secrets
OPENAI_API_KEY=dummy-key-value
export ANTHROPIC_API_KEY="dummy-quoted-value"

# a comment about GITHUB_TOKEN
GITHUB_TOKEN=dummy-github-token
NOT_A_SECRET=hello
"""


def test_scan_finds_variables_and_skips_comments():
    hits = dotenv_edit.scan(DOTENV)
    assert set(hits) == {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "NOT_A_SECRET"}
    assert hits["OPENAI_API_KEY"].value == "dummy-key-value"
    assert hits["ANTHROPIC_API_KEY"].value == "dummy-quoted-value"  # quotes stripped
    assert hits["OPENAI_API_KEY"].line_no == 2


def test_strip_names_removes_values_and_keeps_structure():
    stripped, removed = dotenv_edit.strip_names(DOTENV, {"OPENAI_API_KEY", "GITHUB_TOKEN"},
                                                stamp="2026-11-11")
    assert sorted(removed) == ["GITHUB_TOKEN", "OPENAI_API_KEY"]
    assert "dummy-key-value" not in stripped
    assert "dummy-github-token" not in stripped
    assert "dummy-quoted-value" in stripped          # untouched variable survives
    assert "NOT_A_SECRET=hello" in stripped
    assert "# a comment about GITHUB_TOKEN" in stripped  # unrelated comment survives
    assert "moved to the macOS Keychain by hermes-keychain on 2026-11-11" in stripped
    assert stripped.count("\n") == DOTENV.count("\n")


def test_strip_names_noop_when_name_absent():
    stripped, removed = dotenv_edit.strip_names(DOTENV, {"NOPE"})
    assert removed == []
    assert stripped == DOTENV


def test_write_atomic_preserves_mode_and_leaves_no_temp(tmp_path: Path):
    target = tmp_path / ".env"
    target.write_text("A=1\n")
    os.chmod(target, 0o600)
    dotenv_edit.write_atomic(target, "A=2\n")
    assert target.read_text() == "A=2\n"
    assert (target.stat().st_mode & 0o777) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == [".env"]


def test_backup_is_0600(tmp_path: Path):
    target = tmp_path / ".env"
    target.write_text("A=1\n")
    made = dotenv_edit.backup(target)
    assert made is not None and made.exists()
    assert made.read_text() == "A=1\n"
    assert (made.stat().st_mode & 0o777) == 0o600


# --- index ------------------------------------------------------------------------------

def test_parse_index_handles_garbage():
    assert kc.parse_index("") == []
    assert kc.parse_index("not json") == []
    assert kc.parse_index('{"names": "nope"}') == []
    assert kc.parse_index('{"version":1,"names":["A","A",3,"B"]}') == ["A", "B"]


def test_env_name_validation():
    assert kc.ENV_NAME_RE.match("OPENAI_API_KEY")
    assert kc.ENV_NAME_RE.match("_X1")
    assert not kc.ENV_NAME_RE.match("1BAD")
    assert not kc.ENV_NAME_RE.match("BAD NAME")
    assert not kc.ENV_NAME_RE.match("bad-name")


# --- source fetch -----------------------------------------------------------------------

@pytest.fixture
def source():
    from secret_source import KeychainSource

    return KeychainSource()


@pytest.fixture
def fake_keychain(monkeypatch):
    """In-memory keychain: name → value, plus record of reads."""
    store: dict[tuple[str, str], str] = {}
    reads: list[tuple[str, str]] = []

    def read_secret(service, account, timeout=kc.DEFAULT_TIMEOUT):
        reads.append((service, account))
        if (service, account) not in store:
            raise kc.KeychainError(kc.NOT_FOUND, "item not found in the keychain")
        return store[(service, account)]

    monkeypatch.setattr(kc, "read_secret", read_secret)
    monkeypatch.setattr(kc, "is_supported", lambda: True)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(kc, "record", lambda *a, **k: None)
    return store, reads


def test_fetch_binds_discovered_items(source, fake_keychain):
    store, _ = fake_keychain
    store[("hermes", "OPENAI_API_KEY")] = "sk-1"
    store[("hermes", "not an env name")] = "whatever"
    store[("hermes!index", "index")] = json.dumps(
        {"version": 1, "names": ["OPENAI_API_KEY", "not an env name"]})
    result = source.fetch({"enabled": True, "env": {}}, Path("/tmp"))
    assert result.ok
    assert result.secrets == {"OPENAI_API_KEY": "sk-1"}
    assert "not an env name" not in result.secrets


def test_fetch_explicit_binding_uses_account(source, fake_keychain, monkeypatch):
    store, _ = fake_keychain
    store[("hermes", "anthropic-prod")] = "sk-ant"
    monkeypatch.setattr(kc, "list_index", lambda *a, **k: [])
    result = source.fetch({"enabled": True, "env": {"ANTHROPIC_API_KEY": "anthropic-prod"}},
                          Path("/tmp"))
    assert result.secrets == {"ANTHROPIC_API_KEY": "sk-ant"}


def test_fetch_reports_missing_item_as_warning(source, fake_keychain, monkeypatch):
    fake_keychain[1].clear()
    monkeypatch.setattr(kc, "list_index", lambda *a, **k: [])
    result = source.fetch({"enabled": True, "env": {"NOPE_KEY": "nope"}}, Path("/tmp"))
    assert result.secrets == {}
    assert "NOPE_KEY" in result.skipped
    assert any("NOPE_KEY" in w for w in result.warnings)


def test_fetch_without_bindings_is_a_warning_not_an_error(source, fake_keychain, monkeypatch):
    """A fresh install must start clean: enabled-but-empty is a warning, never a failure."""
    monkeypatch.setattr(kc, "list_index", lambda *a, **k: [])
    result = source.fetch({"enabled": True}, Path("/tmp"))
    assert result.ok
    assert result.secrets == {}
    assert any("no keychain items are bound" in w for w in result.warnings)


def test_fetch_auth_failure_is_classified(source, fake_keychain, monkeypatch):
    def locked(service, account, timeout=kc.DEFAULT_TIMEOUT):
        raise kc.KeychainError(kc.AUTH_FAILED, "user interaction is not allowed")

    monkeypatch.setattr(kc, "read_secret", locked)
    monkeypatch.setattr(kc, "list_index", lambda *a, **k: ["A_KEY"])
    result = source.fetch({"enabled": True}, Path("/tmp"))
    assert not result.ok
    assert result.error_kind is kc_kind("AUTH_FAILED")


def test_fetch_rejects_non_macos(source, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    result = source.fetch({"enabled": True}, Path("/tmp"))
    assert not result.ok
    assert "macOS-only" in (result.error or "")


def test_source_declares_contract():
    from secret_source import KeychainSource

    assert KeychainSource.name == "keychain"
    assert KeychainSource.shape == "mapped"
    assert keychain_core_api() == 1


# --- helpers ----------------------------------------------------------------------------

def kc_kind(name: str):
    from agent.secret_sources.base import ErrorKind

    return getattr(ErrorKind, name)


def keychain_core_api() -> int:
    from agent.secret_sources.base import SECRET_SOURCE_API_VERSION

    return SECRET_SOURCE_API_VERSION
