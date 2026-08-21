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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
