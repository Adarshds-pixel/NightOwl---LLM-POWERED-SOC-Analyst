"""Startup refuses insecure configuration outside local (core/config.py)."""

import pytest

from app.core.config import (
    InsecureConfigurationError,
    Settings,
    resolve_session_secret,
    validate_production_settings,
)


def _settings(**kw):
    return Settings(_env_file=None, **kw)


def test_app_env_is_honoured():
    assert _settings(APP_ENV="production").env == "production"
    assert not _settings(APP_ENV="production").is_local


def test_empty_secret_is_fatal_outside_local():
    with pytest.raises(InsecureConfigurationError):
        resolve_session_secret(_settings(APP_ENV="production", session_secret_key=""))


def test_short_secret_is_fatal_outside_local():
    with pytest.raises(InsecureConfigurationError):
        resolve_session_secret(_settings(APP_ENV="production", session_secret_key="short"))


def test_empty_secret_in_local_is_replaced_by_a_random_key():
    s = _settings(APP_ENV="local", session_secret_key="")
    first, second = resolve_session_secret(s), resolve_session_secret(s)
    assert len(first) >= 32 and first != second


def test_real_secret_is_used_verbatim():
    secret = "a" * 64
    assert resolve_session_secret(_settings(APP_ENV="production", session_secret_key=secret)) == secret


def test_production_requires_a_bcrypt_admin_hash():
    with pytest.raises(InsecureConfigurationError):
        validate_production_settings(_settings(APP_ENV="production", admin_password_hash=""))
    validate_production_settings(_settings(APP_ENV="production", admin_password_hash="$2b$12$" + "a" * 53))
