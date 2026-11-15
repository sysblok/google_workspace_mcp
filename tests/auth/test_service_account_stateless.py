"""Stateless mode with a service account.

Service account mode mints credentials from the key on every request and never
writes to the credential store, so WORKSPACE_MCP_STATELESS_MODE (and with it
stateless streamable HTTP) does not need OAuth 2.1 there.
"""

import json

import pytest

from auth.oauth_config import OAuthConfig

KEY_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "project",
        "private_key": "unused-in-these-tests",
        "client_email": "robot@project.iam.gserviceaccount.com",
    }
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in (
        "GOOGLE_SERVICE_ACCOUNT_KEY_FILE",
        "GOOGLE_SERVICE_ACCOUNT_KEY_JSON",
        "USER_GOOGLE_EMAIL",
        "MCP_ENABLE_OAUTH21",
        "EXTERNAL_OAUTH21_PROVIDER",
        "WORKSPACE_MCP_STATELESS_MODE",
    ):
        monkeypatch.delenv(var, raising=False)


def test_stateless_mode_is_allowed_with_service_account(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON", KEY_JSON)
    monkeypatch.setenv("USER_GOOGLE_EMAIL", "user@corp.com")
    monkeypatch.setenv("WORKSPACE_MCP_STATELESS_MODE", "true")

    config = OAuthConfig()

    assert config.stateless_mode
    assert config.service_account_enabled


def test_stateless_mode_still_needs_oauth21_or_service_account(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_STATELESS_MODE", "true")

    with pytest.raises(ValueError, match="WORKSPACE_MCP_STATELESS_MODE requires"):
        OAuthConfig()


def test_stateless_mode_with_oauth21_is_unchanged(monkeypatch):
    monkeypatch.setenv("MCP_ENABLE_OAUTH21", "true")
    monkeypatch.setenv("WORKSPACE_MCP_STATELESS_MODE", "true")

    assert OAuthConfig().stateless_mode
