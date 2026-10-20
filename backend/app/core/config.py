"""App settings, loaded from environment / .env via pydantic-settings.

Centralizing config here means every other module (db session, future
LLM client, etc.) reads settings the same way instead of scattering
os.environ calls around the codebase.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root .env, resolved from this file's location rather than the
# process's cwd -- every documented workflow runs commands from backend/,
# where a relative "env_file" would silently miss the real .env and fall
# back to field defaults instead of raising.
_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")

    app_name: str = "NightOwl"
    # Read from APP_ENV (what .env.example has always documented) or ENV.
    # This used to be a bare `env` field, which pydantic-settings maps to
    # ENV only -- so APP_ENV was silently ignored, `env` was always "local",
    # and the session cookie's Secure flag could never turn on.
    env: str = Field(default="local", validation_alias=AliasChoices("APP_ENV", "ENV"))
    # Port 5433, not Postgres's default 5432 — see docker-compose.yml comment
    # (another, unrelated Postgres process already owns 5432 on dev machines).
    database_url: str = "postgresql+psycopg2://nightowl:nightowl@localhost:5433/nightowl"

    # LLM wiring (Pair 2, Day 7+) — Groq, exclusively (see rag/llm_client.py's
    # module docstring: this project previously also supported Gemini as an
    # alternate provider, removed 2026-09-06 once its free tier proved
    # structurally unreliable for this project's call volume).
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"

    # Day 12 robustness: an explicit per-request timeout so a hung provider
    # call surfaces as a timeout (caught by llm_client.generate's existing
    # retry/LLMProviderError handling) instead of blocking indefinitely.
    llm_timeout_seconds: float = 30.0

    # Day 12: opt-in in-memory cache for llm_client.generate(), keyed on
    # exact prompt content -- off by default (it's a testing aid for
    # repeated manual runs against a tight free-tier quota, not production
    # behavior). Enable via LLM_CACHE_ENABLED=true in .env.
    llm_cache_enabled: bool = False

    # Day 13: always-on response cache for explain()/chat() results, keyed
    # on incident id (+ message, for chat) -- see rag/cache.py. Distinct
    # from llm_cache_enabled above (that one is opt-in, keyed on exact
    # prompt content, and stays off by default).
    response_cache_enabled: bool = True
    response_cache_ttl_seconds: float = 900.0

    # Shared-secret header auth (Day 13, Pair 1). Empty (default) = auth
    # disabled -- same "empty string = not configured" convention as
    # groq_api_key above, so local dev, Postman, and the existing test
    # suite keep working with no header until an operator opts in by
    # setting this in .env.
    api_key: str = ""

    # In-memory token-bucket rate limiting (Day 13, Pair 1). Requests/minute
    # per client; <= 0 disables limiting entirely (same "0/empty = off"
    # pattern).
    #
    # Raised from 60 during the Phase 3 frontend build: 60/min is one token
    # per second, while a single dashboard paint legitimately costs about a
    # dozen requests (KPIs, severity split, heatmap, alerts, live log slice).
    # At the old ceiling a normal page load plus the background pollers kept
    # the bucket at zero, so the console showed "rate limit exceeded" during
    # ordinary use. This is a per-IP burst guard for a single-analyst local
    # deployment, not a multi-tenant quota.
    rate_limit_per_minute: int = 300

    # Trusted proxy configuration (Day 15). Comma-separated list of IP
    # addresses or CIDR networks (e.g., "127.0.0.1, 10.0.0.0/8"). If empty
    # (the default), no proxies are trusted and the direct peer IP is used,
    # preventing X-Forwarded-For spoofing.
    trusted_proxies: str = ""

    # Day 14 (Pair 1): origins the new frontend (Vite dev server) is allowed
    # to call the API from. Comma-separated; without this, every browser
    # fetch from localhost:5173 to this API is blocked by CORS even though
    # curl/Postman work fine (browsers enforce it, other tools don't).
    cors_allow_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Demo reset (/demo/reset, api/routes_demo.py). On by default: this is
    # a single-analyst local deployment whose whole point is demoing the
    # pipeline, and the endpoint is only destructive to data this same demo
    # workflow creates. Set false for any deployment where a reachable,
    # destructive reset endpoint is not acceptable.
    demo_mode_enabled: bool = True

    # Admin login (single admin, no registration -- see api/routes_auth.py).
    # `admin_password_hash` holds a bcrypt hash, never a plaintext password;
    # empty (default) means no password can ever match, so a freshly cloned
    # repo with no .env correctly has login disabled rather than accepting
    # some baked-in default credential. `session_secret_key` signs the
    # session cookie (Starlette's SessionMiddleware, itsdangerous under the
    # hood) -- also empty by default. See `is_local` / `resolve_session_secret`
    # below: outside local, startup refuses an empty or short secret; in
    # local, an empty one is replaced by a random per-process secret, so a
    # cookie can never be signed with a guessable (empty) key.
    admin_username: str = "admin"
    admin_password_hash: str = ""
    session_secret_key: str = ""
    # 12 hours -- long enough that a real analyst's working day, including a
    # browser refresh or a laptop sleep/wake, doesn't force a re-login, short
    # enough that a stolen session cookie doesn't stay valid indefinitely.
    session_max_age_seconds: int = 12 * 60 * 60

    # Login-attempt throttling (api/routes_auth.py), deliberately separate
    # from rate_limit_per_minute above: that bucket is shared across every
    # route and sized for normal dashboard traffic (hundreds/minute), which
    # would make brute-forcing a password trivial if login attempts drew
    # from the same budget. This one is scoped to POST /auth/login only.
    login_rate_limit_per_minute: int = 5


    # ML anomaly layer (app/ml/): "advisory" (default) records anomalies with
    # their evidence and links them to an incident that already exists, but
    # never opens an incident on its own; "alert" may open one; "off"
    # disables scoring. Advisory is the default because, measured on the
    # current 2-host benign baseline, the layer flags 1-4.5 benign windows
    # per host-day (ML.md) -- too many to page anyone on.
    ml_mode: str = "advisory"

    # Upload cap for POST /ingest, enforced on Content-Length before the body
    # is read (see core/upload_guard.py) and again while copying to disk.
    max_upload_bytes: int = 100 * 1024 * 1024

    # Uploads processed at once (api/routes_ingest.py). Each one holds every
    # record in memory and can start up to 16 reader processes; two large
    # files at once ran a 16 GB machine out of memory on 19 Oct 2026.
    max_concurrent_ingests: int = 1

    @property
    def is_local(self) -> bool:
        return (self.env or "local").strip().lower() in {"local", "dev", "development", "test"}


MIN_SESSION_SECRET_LENGTH = 32


class InsecureConfigurationError(RuntimeError):
    """Raised at startup when a non-local deployment is missing a secret."""


def resolve_session_secret(s: "Settings") -> str:
    """The key SessionMiddleware signs cookies with.

    An empty key makes itsdangerous sign with "" -- anyone can then forge an
    authenticated cookie. Outside local that is a hard startup failure; in
    local (tests, a fresh clone) a random per-process key is used instead,
    which is safe (unforgeable) at the cost of sessions not surviving a
    restart.
    """
    secret = (s.session_secret_key or "").strip()
    if len(secret) >= MIN_SESSION_SECRET_LENGTH:
        return secret
    if not s.is_local:
        raise InsecureConfigurationError(
            f"SESSION_SECRET_KEY must be set to at least {MIN_SESSION_SECRET_LENGTH} characters "
            f"when APP_ENV={s.env!r}; generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    import logging
    import secrets

    logging.getLogger(__name__).warning(
        "SESSION_SECRET_KEY is empty or shorter than %d chars; using a random per-process key "
        "(local only -- sessions will not survive a restart)",
        MIN_SESSION_SECRET_LENGTH,
    )
    return secrets.token_hex(32)


# Database passwords that ship in examples and tutorials, rejected outside local.
WEAK_DATABASE_PASSWORDS = frozenset({"nightowl", "postgres", "password", "changeme", "admin", "root"})
MIN_DATABASE_PASSWORD_LENGTH = 12


def validate_production_settings(s: "Settings") -> None:
    """Fail fast on configurations that are only acceptable on a dev box."""
    if s.is_local:
        return
    if not s.admin_password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        raise InsecureConfigurationError("ADMIN_PASSWORD_HASH must be a bcrypt hash when APP_ENV is not local")
    _validate_database_password(s.database_url)


def _validate_database_password(database_url: str) -> None:
    """The example POSTGRES_PASSWORD (`nightowl`) was found running in a real
    deployment by the 19 Oct 2026 audit; outside local it is now refused."""
    from sqlalchemy.engine import make_url

    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        return
    password = url.password or ""
    if password.lower() in WEAK_DATABASE_PASSWORDS or len(password) < MIN_DATABASE_PASSWORD_LENGTH:
        raise InsecureConfigurationError(
            f"the database password must be at least {MIN_DATABASE_PASSWORD_LENGTH} characters and not an "
            "example value when APP_ENV is not local; set POSTGRES_PASSWORD (and DATABASE_URL) in .env -- "
            "generate one with: python -c \"import secrets; print(secrets.token_urlsafe(24))\""
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
