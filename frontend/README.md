# NightOwl Frontend

Vite + React + TypeScript + Tailwind v4. Scaffolded Day 14 (Pair 1) — see
`docs/02_NightOwl_Handbook_Vol2_Roadmap.md` and
`docs/05_NightOwl_Manual_Testing_Guide.md` for the full project roadmap/testing
guide.

## Quick start

```bash
npm install
npm run dev       # http://localhost:5173
```

The backend (`../backend/`) must be running separately for any real API call
to succeed:

```bash
cd ../backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```

By default the app points at `http://127.0.0.1:8000` (see `.env.development`).
Copy `.env.example` values into a git-ignored `.env.local` to override locally
(e.g. to set `VITE_API_KEY` if the backend has `API_KEY` configured).

## Where things go

- `src/pages/` — one file per route (see `src/App.tsx` for the route table).
- `src/layout/` — the app shell (sidebar/topbar) every page renders inside.
- `src/api/` — the typed API client (`client.ts` has one function per backend
  endpoint, `types.ts` mirrors the backend's Pydantic response models). Import
  from the barrel: `import { getIncidents, ApiError } from '../api'`.
- `src/components/<feature>/` — one folder per feature-specific component
  (e.g. `chat/`, `ingest/`) — drop a new component straight into its feature's
  folder; each has a placeholder `README.md` noting what's expected there and
  which page shell it plugs into.

## Scripts

- `npm run dev` — dev server with HMR.
- `npm run build` — typecheck (`tsc -b`) + production build.
- `npm run lint` — oxlint.
- `npm run preview` — serve the production build locally.
