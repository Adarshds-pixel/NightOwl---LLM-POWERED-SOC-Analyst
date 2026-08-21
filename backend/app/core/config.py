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

    # Shared-secret header auth (Day 13). Empty (default) = auth disabled --
    # same "empty string = not configured" convention as llm_api_key/groq_api_key
    # above, so local dev, Postman, and the existing test suite keep working
    # with no header until an operator opts in by setting this in .env.
    api_key: str = ""

    # In-memory token-bucket rate limiting (Day 13). Requests/minute per
    # client; <= 0 disables limiting entirely (same "0/empty = off" pattern).
    rate_limit_per_minute: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
