import sys
import pytest
from unittest.mock import MagicMock, patch


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_secret_cache():
    """Clear lru_cache before and after every test so results don't bleed across tests."""
    from malsight.config import get_secret
    get_secret.cache_clear()
    yield
    get_secret.cache_clear()


def _sm_modules(return_value: str | None = None, sm_error: Exception | None = None):
    """
    Return a patch.dict context that mocks google.cloud.secretmanager entirely.
    Works whether or not the real package is installed.
    """
    mock_client = MagicMock()
    if sm_error is not None:
        mock_client.access_secret_version.side_effect = sm_error
    else:
        mock_response = MagicMock()
        mock_response.payload.data.decode.return_value = return_value
        mock_client.access_secret_version.return_value = mock_response

    mock_sm = MagicMock()
    mock_sm.SecretManagerServiceClient.return_value = mock_client

    mock_google_cloud = MagicMock()
    mock_google_cloud.secretmanager = mock_sm

    modules = {
        "google.cloud": mock_google_cloud,
        "google.cloud.secretmanager": mock_sm,
    }
    return patch.dict(sys.modules, modules), mock_client


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_returns_env_var_when_set(monkeypatch):
    """get_secret() returns env var value when the env var is set and non-empty."""
    monkeypatch.setenv("MALSIGHT_T1_KEY", "env_value")
    from malsight.config import get_secret
    assert get_secret("MALSIGHT_T1_KEY") == "env_value"


def test_calls_secret_manager_when_env_not_set(monkeypatch):
    """get_secret() calls Secret Manager when env var is NOT set and GCP_PROJECT is set."""
    monkeypatch.delenv("MALSIGHT_T2_KEY", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "test-project")
    from malsight.config import get_secret

    ctx, mock_client = _sm_modules(return_value="from_sm")
    with ctx:
        result = get_secret("MALSIGHT_T2_KEY")

    assert result == "from_sm"
    mock_client.access_secret_version.assert_called_once_with(
        name="projects/test-project/secrets/MALSIGHT_T2_KEY/versions/latest"
    )


def test_raises_runtime_error_when_secret_manager_fails(monkeypatch):
    """get_secret() raises RuntimeError when Secret Manager raises."""
    monkeypatch.delenv("MALSIGHT_T3_KEY", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "test-project")
    from malsight.config import get_secret

    ctx, _ = _sm_modules(sm_error=Exception("not found in SM"))
    with ctx:
        with pytest.raises(RuntimeError, match="MALSIGHT_T3_KEY"):
            get_secret("MALSIGHT_T3_KEY")


def test_raises_runtime_error_when_no_env_and_no_gcp_project(monkeypatch):
    """get_secret() raises RuntimeError when env var absent and GCP_PROJECT is not set."""
    monkeypatch.delenv("MALSIGHT_T4_KEY", raising=False)
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    from malsight.config import get_secret

    with pytest.raises(RuntimeError, match="MALSIGHT_T4_KEY"):
        get_secret("MALSIGHT_T4_KEY")


def test_lru_cache_calls_secret_manager_only_once(monkeypatch):
    """lru_cache ensures Secret Manager is called exactly once for repeated get_secret() calls."""
    monkeypatch.delenv("MALSIGHT_T5_KEY", raising=False)
    monkeypatch.setenv("GCP_PROJECT", "test-project")
    from malsight.config import get_secret

    ctx, mock_client = _sm_modules(return_value="cached_val")
    with ctx:
        r1 = get_secret("MALSIGHT_T5_KEY")
        r2 = get_secret("MALSIGHT_T5_KEY")
        r3 = get_secret("MALSIGHT_T5_KEY")

    assert r1 == r2 == r3 == "cached_val"
    assert mock_client.access_secret_version.call_count == 1


def test_malsight_api_keys_splits_comma_separated(monkeypatch):
    """MALSIGHT_API_KEYS lambda correctly splits a comma-separated string into a list."""
    monkeypatch.setenv("MALSIGHT_API_KEYS", "keyA,keyB,keyC")
    from malsight.config import get_secret, MALSIGHT_API_KEYS

    result = MALSIGHT_API_KEYS()
    assert result == ["keyA", "keyB", "keyC"]
