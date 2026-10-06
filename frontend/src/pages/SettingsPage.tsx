import { Bot, Info, Monitor, Plug, RotateCcw, Settings as SettingsIcon, Database } from 'lucide-react'
import { useState } from 'react'
import {
  Button,
  Card,
  KeyValue,
  PageHeader,
  SegmentedControl,
  Select,
  StatusDot,
  Toggle,
} from '../components/ui'
import { useAuth } from '../context/auth/useAuth'
import { useHealth } from '../context/health/useHealth'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'
import { usePreferences } from '../context/preferences/usePreferences'
import { useToast } from '../context/toast/useToast'
import { useRules } from '../hooks/useRules'
import { formatLatency } from '../lib/format'
import { LOG_INTERVAL_OPTIONS, PAGE_SIZE_OPTIONS, REFRESH_INTERVAL_OPTIONS } from '../lib/preferences'

type Section = 'appearance' | 'data' | 'ai' | 'connection' | 'about'

const SECTIONS: { value: Section; label: string; icon: typeof Monitor }[] = [
  { value: 'appearance', label: 'Appearance', icon: Monitor },
  { value: 'data', label: 'Data and refresh', icon: Database },
  { value: 'ai', label: 'AI assistant', icon: Bot },
  { value: 'connection', label: 'Connection', icon: Plug },
  { value: 'about', label: 'About', icon: Info },
]

/**
 * Settings.
 *
 * NightOwl has exactly one admin account and no settings endpoint, so this
 * is honestly scoped as *this browser's* preferences: every control here
 * changes real behaviour immediately and persists to localStorage, and
 * everything the page cannot change (LLM provider, rule set, API key,
 * session) is presented as read-only fact with a note about where it
 * actually lives. There is no Account or Security section beyond the
 * read-only facts in Connection -- session sign-in/out lives in the top
 * bar's account menu, not here, since there is nothing else to manage.
 */
function SettingsPage() {
  const { prefs, setPref, reset } = usePreferences()
  const { username } = useAuth()
  const { status, latencyMs, samples } = useHealth()
  const { rules } = useRules()
  const { techniques } = useMitreCatalog()
  const { meta } = useIncidentsSnapshot()
  const { push } = useToast()
  const [section, setSection] = useState<Section>('appearance')

  const apiBase = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Settings"
        subtitle="Preferences stored in this browser, plus the facts about this deployment"
        icon={<SettingsIcon className="h-5 w-5 text-accent-primary" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Settings' }]}
        actions={
          <Button
            variant="ghost"
            icon={<RotateCcw className="h-3.5 w-3.5" />}
            onClick={() => {
              reset()
              push({ tone: 'success', title: 'Preferences reset to defaults' })
            }}
          >
            Reset to defaults
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <nav
          className="flex flex-row gap-1 self-start overflow-x-auto pb-1 xl:col-span-3 xl:flex-col xl:overflow-visible xl:pb-0"
          aria-label="Settings sections"
        >
          {SECTIONS.map((entry) => {
            const Icon = entry.icon
            const active = section === entry.value
            return (
              <button
                key={entry.value}
                type="button"
                onClick={() => setSection(entry.value)}
                aria-current={active ? 'true' : undefined}
                className={`flex shrink-0 items-center gap-2.5 rounded-control border px-3 py-2.5 text-left text-meta transition-colors ${
                  active
                    ? 'border-accent-primary/35 bg-accent-primary/12 text-text'
                    : 'border-transparent text-text-muted hover:bg-white/5 hover:text-text-dim'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {entry.label}
              </button>
            )
          })}
        </nav>

        <div className="flex flex-col gap-4 xl:col-span-9">
          {section === 'appearance' && (
            <Card title="Appearance" accent="primary">
              <div className="flex flex-col divide-y divide-line-soft">
                <Row label="Density" hint="Row height across every table and list.">
                  <SegmentedControl
                    value={prefs.density}
                    onChange={(density) => setPref('density', density)}
                    options={[
                      { label: 'Comfortable', value: 'comfortable' as const },
                      { label: 'Compact', value: 'compact' as const },
                    ]}
                  />
                </Row>
                <Row label="Ambient background" hint="The violet and magenta glow behind the interface.">
                  <Toggle
                    checked={prefs.ambientBackground}
                    onChange={(value) => setPref('ambientBackground', value)}
                    label="Ambient background"
                  />
                </Row>
                <Row label="Reduce motion" hint="Turns off transitions and pulses, regardless of the OS setting.">
                  <Toggle
                    checked={prefs.reduceMotion}
                    onChange={(value) => setPref('reduceMotion', value)}
                    label="Reduce motion"
                  />
                </Row>
                <Row label="Animated counters" hint="Count-up animation on the metric cards.">
                  <Toggle
                    checked={prefs.animatedCounters}
                    onChange={(value) => setPref('animatedCounters', value)}
                    label="Animated counters"
                  />
                </Row>
                <Row label="24-hour clock" hint="Applies to the header clock.">
                  <Toggle checked={prefs.clock24h} onChange={(value) => setPref('clock24h', value)} label="24-hour clock" />
                </Row>
              </div>
            </Card>
          )}

          {section === 'data' && (
            <Card title="Data and refresh" accent="violet">
              <div className="flex flex-col divide-y divide-line-soft">
                <Row
                  label="Incident refresh"
                  hint="How often the incident snapshot is re-fetched. It pauses while the tab is hidden."
                >
                  <Select
                    value={String(prefs.refreshIntervalMs)}
                    onChange={(value) => setPref('refreshIntervalMs', Number(value))}
                    options={REFRESH_INTERVAL_OPTIONS.map((option) => ({
                      label: option.label,
                      value: String(option.value),
                    }))}
                    className="w-44"
                  />
                </Row>
                <Row label="Live log stream" hint="Poll interval for the dashboard log tail.">
                  <Select
                    value={String(prefs.logStreamIntervalMs)}
                    onChange={(value) => setPref('logStreamIntervalMs', Number(value))}
                    options={LOG_INTERVAL_OPTIONS.map((option) => ({
                      label: option.label,
                      value: String(option.value),
                    }))}
                    className="w-44"
                  />
                </Row>
                <Row label="Rows per page" hint="Default page size for the incident, alert, log and rule tables.">
                  <Select
                    value={String(prefs.pageSize)}
                    onChange={(value) => setPref('pageSize', Number(value))}
                    options={PAGE_SIZE_OPTIONS.map((size) => ({ label: `${size} rows`, value: String(size) }))}
                    className="w-44"
                  />
                </Row>
              </div>
              <p className="mt-3 text-micro text-text-faint">
                The backend has no websocket or SSE endpoint, so live data is polling. Shorter intervals mean more
                requests against the API rate limit; the pollers back off automatically if they are throttled.
              </p>
            </Card>
          )}

          {section === 'ai' && (
            <Card title="AI assistant" accent="violet">
              <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <KeyValue label="Explanation endpoint" value="POST /incidents/{id}/explain" mono />
                <KeyValue label="Chat endpoint" value="POST /incidents/{id}/chat" mono />
                <KeyValue label="Scope" value="Incident-scoped, grounded in the MITRE knowledge base" />
                <KeyValue label="Streaming" value="Not supported by the backend" />
              </dl>
              <p className="mt-4 text-meta text-text-muted">
                The model provider, model name, timeout and response cache are backend configuration
                (LLM_PROVIDER, GROQ_MODEL, LLM_TIMEOUT_SECONDS in the repo-root .env). They are deliberately not
                editable or even readable from the browser: the API never exposes its own credentials or provider
                settings to the client, and a control here that could not actually change them would be theatre.
              </p>
              <p className="mt-2 text-meta text-text-muted">
                Explanations run retrieval, drafting and a self-critique pass per call, so each one costs two model
                requests against a free-tier quota. Answers are cached backend-side for 15 minutes per incident.
              </p>
            </Card>
          )}

          {section === 'connection' && (
            <Card title="Connection" accent="primary">
              <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <KeyValue label="API base URL" value={apiBase} mono />
                <KeyValue
                  label="API status"
                  value={
                    <span className="flex items-center gap-1.5">
                      <StatusDot tone={status === 'healthy' ? 'good' : status === 'checking' ? 'idle' : 'bad'} pulse={false} />
                      {status === 'healthy' ? 'Reachable' : status === 'checking' ? 'Checking' : 'Unreachable'}
                    </span>
                  }
                />
                <KeyValue label="Latency" value={formatLatency(latencyMs)} mono />
                <KeyValue label="Samples this session" value={samples.length} mono />
                <KeyValue label="Signed in as" value={username ?? '—'} mono />
                <KeyValue label="Auth model" value="Single-admin session login (signed, HttpOnly cookie)" />
              </dl>
              <p className="mt-4 text-meta text-text-muted">
                Sign-in is a real admin login (POST /auth/login sets the session cookie); use the account menu in
                the top bar to sign out; signing out revokes the session on the server. The API base URL is a build-time
                setting (VITE_API_BASE_URL), so changing it means rebuilding the frontend, not typing into this page.
              </p>
            </Card>
          )}

          {section === 'about' && (
            <Card title="About this deployment" accent="neutral">
              <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <KeyValue label="Detection rules loaded" value={rules.length} mono />
                <KeyValue label="ATT&CK catalog entries" value={techniques.length.toLocaleString()} mono />
                <KeyValue label="Incidents stored" value={meta.totalAll.toLocaleString()} mono />
                <KeyValue label="Rule source" value="backend/app/detection/rules/*.yml" mono />
                <KeyValue label="Data store" value="PostgreSQL, plus ChromaDB for the knowledge base" />
                <KeyValue label="Deployment" value="Single-user local install" />
              </dl>
              <p className="mt-4 text-meta text-text-muted">
                NightOwl ingests Windows EVTX exports, evaluates them against Sigma rules, groups matches into
                incidents and explains them with a retrieval-grounded model. Everything on screen anywhere in this
                console is derived from that pipeline.
              </p>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0">
        <p className="text-body text-text-dim">{label}</p>
        {hint && <p className="mt-0.5 text-micro text-text-faint">{hint}</p>}
      </div>
      {children}
    </div>
  )
}

export default SettingsPage
