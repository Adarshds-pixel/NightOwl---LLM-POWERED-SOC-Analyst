#!/bin/sh
# Container start-up: bring the schema up to date, make sure the RAG knowledge
# base exists, then hand PID 1 to uvicorn.
set -e

cd /app/backend
echo "[nightowl] applying database migrations"
alembic upgrade head

if [ "${NIGHTOWL_BUILD_KB:-1}" = "1" ] && [ ! -f /app/ai/vector_store/chroma.sqlite3 ]; then
  echo "[nightowl] knowledge base not found -- building it (first start only; needs network)"
  python /app/ai/tools/build_kb.py || echo "[nightowl] WARNING: knowledge base build failed; explanations will have no retrieval grounding until it succeeds"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-127.0.0.1}"
