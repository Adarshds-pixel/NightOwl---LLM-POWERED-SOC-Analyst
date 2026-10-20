# Build context is the REPO ROOT (see docker-compose.yml's `build.context: .`
# for this service), matching backend/Dockerfile's own convention.

# ---- builder: install deps and produce the static Vite build ----
FROM node:24-alpine AS builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Vite inlines VITE_* variables into the built JS at build time, so this is a
# build ARG. Nothing secret belongs here: everything in the bundle is public.
ARG VITE_API_BASE_URL=http://127.0.0.1:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

# ---- runtime: serve the static build ----
FROM nginx:1.31-alpine AS runtime
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
