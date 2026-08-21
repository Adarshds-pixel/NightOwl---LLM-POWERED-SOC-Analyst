# Build context is the REPO ROOT (see docker-compose.yml's `build.context: .`),
# not backend/ -- app/core/config.py, app/mitre/loader.py, and
# app/rag/chroma_client.py all resolve paths via
# `Path(__file__).resolve().parents[3]` (repo root, 3 levels above app/), so
# this image mirrors the same backend/app/... nesting rather than flattening
# it, and zero application code needs to change to run in a container.

# ---- builder: install deps into a venv, kept out of the runtime stage's history ----
FROM python:3.13-slim AS builder
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY backend/requirements.txt ./backend/requirements.txt
# --trusted-host: this network intercepts outbound TLS via a corporate root
# CA that Windows/curl trust but this container's bare Debian image doesn't
# (same root cause as the guide's §0 "Windows + corporate/AV network only"
# pip-system-certs note -- that fix works on the host because it points
# Python at Windows' trust store, which isn't available inside a Linux
# container). Scoped to just the two PyPI hosts, build-time only -- doesn't
# weaken the runtime image's own TLS behavior.
RUN pip install --no-cache-dir \
    --trusted-host pypi.org --trusted-host files.pythonhosted.org \
    -r backend/requirements.txt

# ---- runtime ----
FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 1000 appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY --chown=appuser:appuser backend/app ./backend/app
COPY --chown=appuser:appuser backend/alembic ./backend/alembic
COPY --chown=appuser:appuser backend/alembic.ini ./backend/alembic.ini
USER appuser
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
