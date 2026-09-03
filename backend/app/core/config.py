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

    # LLM wiring (Pair 2, Day 7+) — Gemini free tier via langchain-google-genai.
    llm_api_key: str = ""
    # Alias that auto-tracks Google's current recommended free-tier Flash
    # model rather than a pinned dated snapshot that could be deprecated
    # mid-roadmap (e.g. the Gemini 2.5 family, retiring 2026-10-16) — see
    # docs/decisions.md. Override via LLM_MODEL in .env to pin a version.
    llm_model: str = "gemini-flash-latest"

    # Which provider llm_client.py builds: "gemini" (default) or "groq".
    # Added for the Day 10 hallucination spot-check, where Gemini's 20
    # req/day free-tier cap can't reliably cover 10 explain() calls (20
    # requests). Groq is also an explicitly allowed free-tier provider per
    # the roadmap's Day 2 task. Gemini stays the project default.
    llm_provider: str = "gemini"
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
    # llm_api_key/groq_api_key above, so local dev, Postman, and the
    # existing test suite keep working with no header until an operator
    # opts in by setting this in .env.
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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
