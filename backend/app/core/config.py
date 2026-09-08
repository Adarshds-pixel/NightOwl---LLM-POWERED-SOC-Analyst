"""App settings, loaded from environment / .env via pydantic-settings.

Centralizing config here means every other module (db session, future
LLM client, etc.) reads settings the same way instead of scattering
os.environ calls around the codebase.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root .env, resolved from this file's location rather than the
# process's cwd -- every documented workflow runs commands from backend/,
# where a relative "env_file" would silently miss the real .env and fall
# back to field defaults instead of raising.
_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")

    app_name: str = "NightOwl"
    env: str = "local"
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
    # hood) -- also empty by default; app startup rejects an empty secret
    # once real routes are gated on it, rather than silently signing
    # sessions with a guessable key.
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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
