# Build context is the REPO ROOT (see docker-compose.yml's `build.context: .`
# for this service), matching backend/Dockerfile's own convention.

# ---- builder: install deps and produce the static Vite build ----
FROM node:24-alpine AS builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Vite inlines VITE_* variables into the built JS at build time, not at
# container start -- there is no "runtime env" for a static bundle, so
# these must be build ARGs, not docker-compose `environment:` entries.
# Defaults match frontend/.env.example (a bare backend, no shared-secret
# key configured).
ARG VITE_API_BASE_URL=http://127.0.0.1:8000
ARG VITE_API_KEY=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL} \
    VITE_API_KEY=${VITE_API_KEY}
RUN npm run build

# ---- runtime: serve the static build ----
FROM nginx:1.27-alpine AS runtime
COPY --from=builder /app/dist /usr/share/nginx/html
# React Router uses client-side routes (e.g. /incidents/42) that don't
# exist as real files -- without this, refreshing or deep-linking to one
# 404s at the nginx layer before React ever gets a chance to render it.
RUN printf 'server {\n\
    listen 80;\n\
    root /usr/share/nginx/html;\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
