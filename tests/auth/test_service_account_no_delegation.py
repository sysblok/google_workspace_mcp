"""Service account acting as itself (GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION).

Without Google Workspace there is no domain-wide delegation, so the service
account must authenticate with subject=None and operate as its own client_email.
The DWD path must stay unchanged when the flag is off.
"""

import json
import os
import subprocess
import sys

import pytest

import auth.service_decorator as service_decorator
from auth import oauth_config as oauth_config_module
from auth.oauth_config import OAuthConfig
from auth.scopes import (
    DOCS_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
    DRIVE_READONLY_SCOPE,
    DRIVE_SCOPE,
)

SA_EMAIL = "robot@project.iam.gserviceaccount.com"
KEY_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "project",
        "private_key": "unused-in-these-tests",
        "client_email": SA_EMAIL,
    }
)

_ENV_VARS = (
    "GOOGLE_SERVICE_ACCOUNT_KEY_FILE",
    "GOOGLE_SERVICE_ACCOUNT_KEY_JSON",
    "GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION",
    "USER_GOOGLE_EMAIL",
    "MCP_ENABLE_OAUTH21",
    "EXTERNAL_OAUTH21_PROVIDER",
    "WORKSPACE_MCP_STATELESS_MODE",
    "TRUST_GATEWAY_IDENTITY",
    "GATEWAY_IDENTITY_JWKS_URL",
    "GATEWAY_IDENTITY_AUDIENCE",
    "DWD_ALLOWED_DOMAINS",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield
    # Drop any singleton a test built from its patched environment.
    oauth_config_module._oauth_config = None


@pytest.fixture
def no_delegation_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON", KEY_JSON)
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION", "true")


@pytest.fixture
def no_delegation_config(no_delegation_env):
    return oauth_config_module.reload_oauth_config()


# --- Configuration ---


def test_flag_on_reads_client_email_without_user_google_email(no_delegation_env):
    config = OAuthConfig()

    assert config.service_account_enabled
    assert config.service_account_no_delegation
    assert config.service_account_email == SA_EMAIL


def test_flag_on_reads_client_email_from_key_file(monkeypatch, tmp_path):
    key_file = tmp_path / "key.json"
    key_file.write_text(KEY_JSON)
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_KEY_FILE", str(key_file))
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION", "true")

    assert OAuthConfig().service_account_email == SA_EMAIL


def test_flag_off_keeps_dwd_mode(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON", KEY_JSON)
    monkeypatch.setenv("USER_GOOGLE_EMAIL", "user@corp.com")
    oauth_config_module.reload_oauth_config()

    assert oauth_config_module.is_service_account_enabled()
    assert not oauth_config_module.is_service_account_no_delegation()
    assert oauth_config_module.get_service_account_email() is None


def test_flag_requires_a_service_account_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION", "true")

    with pytest.raises(ValueError, match="requires GOOGLE_SERVICE_ACCOUNT_KEY"):
        OAuthConfig()


def test_flag_stays_incompatible_with_oauth21(monkeypatch, no_delegation_env):
    monkeypatch.setenv("MCP_ENABLE_OAUTH21", "true")

    with pytest.raises(ValueError, match="incompatible with OAuth 2.1"):
        OAuthConfig()


def test_flag_is_incompatible_with_trusted_gateway(monkeypatch, no_delegation_env):
    monkeypatch.setenv("TRUST_GATEWAY_IDENTITY", "true")
    monkeypatch.setenv("GATEWAY_IDENTITY_JWKS_URL", "https://gateway.example/jwks")
    monkeypatch.setenv("GATEWAY_IDENTITY_AUDIENCE", "workspace-mcp")

    with pytest.raises(ValueError, match="incompatible with TRUST_GATEWAY_IDENTITY"):
        OAuthConfig()


def test_user_google_email_must_match_client_email(monkeypatch, no_delegation_env):
    monkeypatch.setenv("USER_GOOGLE_EMAIL", "someone@gmail.com")

    with pytest.raises(ValueError, match="USER_GOOGLE_EMAIL must be unset or equal"):
        OAuthConfig()


def test_user_google_email_equal_to_client_email_is_accepted(
    monkeypatch, no_delegation_env
):
    monkeypatch.setenv("USER_GOOGLE_EMAIL", SA_EMAIL.upper())

    assert OAuthConfig().service_account_email == SA_EMAIL


def test_stateless_mode_is_allowed_without_delegation(monkeypatch, no_delegation_env):
    monkeypatch.setenv("WORKSPACE_MCP_STATELESS_MODE", "true")

    config = OAuthConfig()

    assert config.stateless_mode
    assert config.service_account_no_delegation


def test_core_config_user_email_is_the_service_account():
    """core.config.USER_GOOGLE_EMAIL drives schema defaults and arg injection."""
    env = {k: v for k, v in os.environ.items() if k not in _ENV_VARS}
    env.update(
        GOOGLE_SERVICE_ACCOUNT_KEY_JSON=KEY_JSON,
        GOOGLE_SERVICE_ACCOUNT_NO_DELEGATION="true",
    )
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import core.config; print(core.config.USER_GOOGLE_EMAIL)",
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip().splitlines()[-1] == SA_EMAIL


# --- Authentication ---


def _capture_credentials(monkeypatch):
    captured = {}
    fake_service = object()

    def fake_get_creds(scopes, subject):
        captured["scopes"] = scopes
        captured["subject"] = subject
        return object()

    monkeypatch.setattr(
        service_decorator, "_get_service_account_credentials", fake_get_creds
    )
    monkeypatch.setattr(
        service_decorator,
        "build_google_service",
        lambda service_name, service_version, credentials: fake_service,
    )
    return captured, fake_service


async def _authenticate(user_google_email, scopes=("scope-a",)):
    return await service_decorator._authenticate_service(
        use_oauth21=False,
        service_name="docs",
        service_version="v1",
        tool_name="get_doc_content",
        user_google_email=user_google_email,
        resolved_scopes=list(scopes),
        mcp_session_id=None,
        authenticated_user=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("requested", [None, "", SA_EMAIL, SA_EMAIL.upper()])
async def test_no_delegation_authenticates_without_subject(
    monkeypatch, no_delegation_config, requested
):
    monkeypatch.setattr(service_decorator, "_ENV_USER_EMAIL", None)
    captured, fake_service = _capture_credentials(monkeypatch)

    service, actual_user = await _authenticate(requested)

    assert service is fake_service
    assert actual_user == SA_EMAIL
    assert captured["subject"] is None


@pytest.mark.asyncio
async def test_no_delegation_rejects_a_different_user(
    monkeypatch, no_delegation_config
):
    captured, _ = _capture_credentials(monkeypatch)

    with pytest.raises(
        service_decorator.GoogleAuthenticationError,
        match=f"cannot act as someone@gmail.com.*{SA_EMAIL}",
    ):
        await _authenticate("someone@gmail.com")

    assert captured == {}


@pytest.mark.asyncio
async def test_no_delegation_ignores_dwd_domain_allowlist(
    monkeypatch, no_delegation_env
):
    monkeypatch.setenv("DWD_ALLOWED_DOMAINS", "corp.com")
    oauth_config_module.reload_oauth_config()
    captured, _ = _capture_credentials(monkeypatch)

    _, actual_user = await _authenticate(SA_EMAIL)

    assert actual_user == SA_EMAIL
    assert captured["subject"] is None


@pytest.mark.asyncio
async def test_flag_off_still_impersonates_user_google_email(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_KEY_JSON", KEY_JSON)
    monkeypatch.setenv("USER_GOOGLE_EMAIL", "user@corp.com")
    oauth_config_module.reload_oauth_config()
    monkeypatch.setattr(service_decorator, "_ENV_USER_EMAIL", None)
    captured, _ = _capture_credentials(monkeypatch)

    _, actual_user = await _authenticate(None)

    assert actual_user == "user@corp.com"
    assert captured["subject"] == "user@corp.com"


def test_credentials_are_built_without_subject(monkeypatch, no_delegation_config):
    captured = {}

    def fake_from_info(info, scopes, subject):
        captured.update(email=info["client_email"], scopes=scopes, subject=subject)
        return "creds"

    monkeypatch.setattr(
        service_decorator.google_service_account.Credentials,
        "from_service_account_info",
        fake_from_info,
    )

    assert service_decorator._get_service_account_credentials(["s"], None) == "creds"
    assert captured == {"email": SA_EMAIL, "scopes": ["s"], "subject": None}


# --- Scopes in read-only mode ---


@pytest.fixture
def read_only(monkeypatch):
    monkeypatch.setattr(service_decorator, "is_read_only_mode", lambda: True)


def test_read_only_widens_drive_file_to_drive_readonly(read_only):
    assert service_decorator._widen_drive_scope_for_dwd(
        [DOCS_READONLY_SCOPE, DRIVE_FILE_SCOPE, DRIVE_READONLY_SCOPE], "t"
    ) == [DOCS_READONLY_SCOPE, DRIVE_READONLY_SCOPE]


@pytest.mark.asyncio
async def test_read_only_no_delegation_never_requests_write_scopes(
    monkeypatch, no_delegation_config, read_only
):
    """Every docs/sheets/drive tool left enabled in read-only mode must request
    only read-only scopes from Google, after service-account widening too."""
    import gdocs.docs_tools  # noqa: F401
    import gdrive.drive_tools  # noqa: F401
    import gsheets.sheets_tools  # noqa: F401
    from auth.scopes import get_all_read_only_scopes
    from core.server import server
    from core.tool_registry import get_tool_components

    read_only_scopes = set(get_all_read_only_scopes())
    captured, _ = _capture_credentials(monkeypatch)
    checked = []
    for name, tool in get_tool_components(server).items():
        fn = getattr(tool, "fn", tool)
        required = getattr(fn, "_required_google_scopes", None)
        if not required or not set(required) <= read_only_scopes:
            continue  # disabled in read-only mode by filter_server_tools
        await _authenticate(None, scopes=required)
        assert set(captured["scopes"]) <= read_only_scopes, name
        assert DRIVE_SCOPE not in captured["scopes"], name
        checked.append(name)

    assert {"get_doc_content", "search_drive_files", "read_sheet_values"} <= set(
        checked
    )
