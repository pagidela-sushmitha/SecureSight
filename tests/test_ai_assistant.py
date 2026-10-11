"""AI foundation tests: mock every request; never read the user's local .env."""

import importlib
import os
from unittest.mock import MagicMock, patch

import httpx
import pytest
from openai import (
    APIConnectionError, APITimeoutError, AuthenticationError, BadRequestError,
    InternalServerError, NotFoundError, PermissionDeniedError, RateLimitError,
)
from streamlit.testing.v1 import AppTest

from src import ai_assistant as ai
from scripts import check_openai_connection as cli


FAKE_KEY = "synthetic-unit-test-credential"


@pytest.fixture(autouse=True)
def isolated_configuration(monkeypatch):
    for name in ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    with patch.object(ai, "dotenv_values", return_value={}):
        yield


def test_defaults_and_no_request(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    with patch.object(ai, "ChatOpenAI") as constructor:
        client = ai.create_chat_model()
    kwargs = constructor.call_args.kwargs
    assert kwargs["model"] == "gpt-4.1-mini"
    assert kwargs["api_key"].get_secret_value() == FAKE_KEY
    assert FAKE_KEY not in repr(kwargs)
    assert kwargs["temperature"] == 0
    assert kwargs["timeout"] == 30
    assert kwargs["max_retries"] == 0 and kwargs["store"] is False
    assert kwargs["base_url"] == "https://api.openai.com/v1"
    client.invoke.assert_not_called()


def test_dotenv_fallback_and_shell_precedence(monkeypatch):
    local = {"OPENAI_API_KEY": FAKE_KEY, "OPENAI_MODEL": "gpt-4o-mini", "OPENAI_TIMEOUT_SECONDS": "12.5"}
    before = dict(os.environ)
    with patch.object(ai, "dotenv_values", return_value=local) as loader, patch.object(ai, "ChatOpenAI") as constructor:
        ai.create_chat_model(dotenv_path="explicit-test.env")
        loader.assert_called_once_with("explicit-test.env", interpolate=False)
        assert constructor.call_args.kwargs["model"] == "gpt-4o-mini"
        assert constructor.call_args.kwargs["timeout"] == 12.5
        assert dict(os.environ) == before
        monkeypatch.setenv("OPENAI_API_KEY", "environment-only-test-credential")
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")
        monkeypatch.setenv("OPENAI_TIMEOUT_SECONDS", "8")
        ai.create_chat_model()
        assert constructor.call_args.kwargs["api_key"].get_secret_value() == "environment-only-test-credential"
        assert constructor.call_args.kwargs["model"] == "gpt-4.1-mini"
        assert constructor.call_args.kwargs["timeout"] == 8


@pytest.mark.parametrize("model, temperature", [("gpt-4.1-mini", 0), ("gpt-4o-mini", 0), ("gpt-5-mini", None), ("o3-mini", None), ("custom-model", None)])
def test_temperature_compatibility(monkeypatch, model, temperature):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("OPENAI_MODEL", model)
    with patch.object(ai, "ChatOpenAI") as constructor:
        ai.create_chat_model(dotenv_path=None)
    assert constructor.call_args.kwargs["temperature"] == temperature
    ai.dotenv_values.assert_not_called()


def test_missing_key_does_not_construct_client():
    with patch.object(ai, "ChatOpenAI") as constructor:
        with pytest.raises(ai.AIConfigurationError, match="OPENAI_API_KEY is missing"):
            ai.create_chat_model()
        result = ai.connectivity_smoke_test()
    assert result.code == "missing_credentials" and not result.success
    constructor.assert_not_called()


@pytest.mark.parametrize("value", ["", "0", "-1", "nan", "inf", "not-a-number"])
def test_invalid_timeout_is_sanitized(monkeypatch, value):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("OPENAI_TIMEOUT_SECONDS", value)
    result = ai.connectivity_smoke_test()
    assert not result.success and result.code == "configuration"
    assert FAKE_KEY not in result.message


def test_empty_model(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("OPENAI_MODEL", "   ")
    assert ai.connectivity_smoke_test().code == "configuration"


def test_dotenv_read_failure_is_sanitized():
    with patch.object(ai, "dotenv_values", side_effect=OSError(FAKE_KEY)):
        result = ai.connectivity_smoke_test()
    assert not result.success and FAKE_KEY not in result.message


def test_initialization_failure_is_sanitized(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    with patch.object(ai, "ChatOpenAI", side_effect=ValueError(FAKE_KEY)):
        result = ai.connectivity_smoke_test()
    assert not result.success and FAKE_KEY not in result.message


def test_smoke_success_sends_only_fixed_prompt():
    model = MagicMock()
    with patch.object(ai, "create_chat_model", return_value=model):
        result = ai.connectivity_smoke_test(dotenv_path=None)
    model.invoke.assert_called_once_with(ai.SMOKE_PROMPT, max_completion_tokens=32)
    assert result.success and result.code == "ok"
    assert "MagicMock" not in result.message


def status_error(cls, status, code=None, error_type=None):
    response = httpx.Response(status, request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
    return cls(FAKE_KEY, response=response, body={"code": code, "type": error_type, "message": FAKE_KEY})


@pytest.mark.parametrize("error, code", [
    (status_error(AuthenticationError, 401), "authentication"),
    (status_error(PermissionDeniedError, 403), "permission"),
    (status_error(RateLimitError, 429, "rate_limit_exceeded"), "rate_limit"),
    (status_error(RateLimitError, 429, "insufficient_quota"), "quota"),
    (status_error(RateLimitError, 429, "billing_hard_limit_reached"), "quota"),
    (status_error(RateLimitError, 429, "credit_balance_exhausted"), "quota"),
    (status_error(RateLimitError, 429, "organization_spend_limit_exceeded"), "quota"),
    (status_error(RateLimitError, 429, "project_spend_limit_exceeded"), "quota"),
    (status_error(RateLimitError, 429, "organization_usage_limit_exceeded"), "quota"),
    (status_error(RateLimitError, 429, "unknown_billing_code", "insufficient_quota"), "quota"),
    (status_error(RateLimitError, 429, "slow_down", "rate_limit_error"), "rate_limit"),
    (APITimeoutError(request=httpx.Request("POST", "https://api.openai.com/v1")), "timeout"),
    (APIConnectionError(message=FAKE_KEY, request=httpx.Request("POST", "https://api.openai.com/v1")), "network"),
    (status_error(BadRequestError, 400), "request"),
    (status_error(NotFoundError, 404), "request"),
    (status_error(InternalServerError, 500), "service"),
    (RuntimeError(FAKE_KEY), "unexpected"),
])
def test_provider_errors_are_sanitized(error, code):
    model = MagicMock()
    model.invoke.side_effect = error
    with patch.object(ai, "create_chat_model", return_value=model):
        result = ai.connectivity_smoke_test()
    assert not result.success and result.code == code
    assert FAKE_KEY not in repr(result)
    model.invoke.assert_called_once()


def test_real_client_initialization_is_offline_and_redacted(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    with patch("httpx.Client.send", side_effect=AssertionError("Unexpected API request")), patch("httpx.AsyncClient.send", side_effect=AssertionError("Unexpected API request")):
        model = ai.create_chat_model(dotenv_path=None)
    assert isinstance(model, ai.ChatOpenAI)
    assert FAKE_KEY not in repr(model)


def test_import_has_no_side_effects():
    with patch("dotenv.dotenv_values") as dotenv, patch("langchain_openai.ChatOpenAI") as constructor:
        importlib.reload(ai)
        dotenv.assert_not_called()
        constructor.assert_not_called()
    importlib.reload(ai)


def test_cli_reports_only_sanitized_result(capsys):
    for success, expected_status in ((True, 0), (False, 1)):
        with patch.object(cli, "connectivity_smoke_test", return_value=ai.ConnectivityResult(success, "test", "Safe result")):
            assert cli.main() == expected_status
        output = capsys.readouterr().out
        assert "Safe result" in output and FAKE_KEY not in output


def test_dashboard_startup_needs_neither_key_nor_model():
    with patch.object(ai, "create_chat_model", side_effect=AssertionError("Dashboard initialized AI")), patch.object(ai, "connectivity_smoke_test", side_effect=AssertionError("Dashboard invoked AI")), patch("httpx.Client.send", side_effect=AssertionError("Unexpected HTTP request")), patch("httpx.AsyncClient.send", side_effect=AssertionError("Unexpected HTTP request")):
        app = AppTest.from_file(str(ai.LOCAL_ENV.parent / "app.py")).run(timeout=30)
    assert not app.exception
    assert app.metric[0].value == "350"
