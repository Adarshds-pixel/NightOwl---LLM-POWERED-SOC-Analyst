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


_BCRYPT = "$2b$12$" + "a" * 53
_STRONG_DB = "postgresql+psycopg2://nightowl:Xq7vR2mK9pL4wT8z@db:5432/nightowl"


def test_production_requires_a_bcrypt_admin_hash():
    with pytest.raises(InsecureConfigurationError):
        validate_production_settings(_settings(APP_ENV="production", admin_password_hash="", database_url=_STRONG_DB))
    validate_production_settings(_settings(APP_ENV="production", admin_password_hash=_BCRYPT, database_url=_STRONG_DB))


@pytest.mark.parametrize(
    "password",
    ["nightowl", "NightOwl", "postgres", "password", "changeme", "short1"],
)
def test_production_refuses_a_weak_database_password(password):
    url = f"postgresql+psycopg2://nightowl:{password}@db:5432/nightowl"
    with pytest.raises(InsecureConfigurationError):
        validate_production_settings(_settings(APP_ENV="production", admin_password_hash=_BCRYPT, database_url=url))


def test_production_refuses_a_database_url_without_a_password():
    url = "postgresql+psycopg2://nightowl@db:5432/nightowl"
    with pytest.raises(InsecureConfigurationError):
        validate_production_settings(_settings(APP_ENV="production", admin_password_hash=_BCRYPT, database_url=url))


def test_weak_database_password_is_allowed_in_local():
    validate_production_settings(_settings(APP_ENV="local", database_url="postgresql+psycopg2://a:nightowl@x/db"))


def test_demo_mode_defaults_on_in_local_and_off_elsewhere():
    assert _settings(APP_ENV="local").demo_mode_enabled is True
    assert _settings(APP_ENV="production").demo_mode_enabled is False


def test_demo_mode_can_be_enabled_explicitly_in_production(monkeypatch):
    assert _settings(APP_ENV="production", demo_mode_enabled=True).demo_mode_enabled is True
    monkeypatch.setenv("DEMO_MODE_ENABLED", "true")
    assert _settings(APP_ENV="production").demo_mode_enabled is True


def test_demo_mode_can_be_disabled_in_local():
    assert _settings(APP_ENV="local", demo_mode_enabled=False).demo_mode_enabled is False


def test_sqlite_database_needs_no_password():
    validate_production_settings(
        _settings(APP_ENV="production", admin_password_hash=_BCRYPT, database_url="sqlite:///./nightowl.db")
    )
