import { ArrowRight, BrainCircuit, Crosshair, Eye, EyeOff, FileText, Lock, ShieldCheck, User } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { NightOwlMark } from '../components/brand/NightOwlMark'
import { Button, CursorGlow, Reflection, TextInput } from '../components/ui'
import { useAuth } from '../context/auth/useAuth'

/**
 * The NightOwl sign-in screen -- built to the `frontend design images/`
 * reference (login page.png over background image.png), not the generic
 * AmbientBackground splash the rest of the app uses: a real photo
 * (public/login-background.png, copied from that same reference) fills the
 * viewport behind a two-panel layout, brand/value copy on the left, the
 * glass sign-in card on the right.
 *
 * Two deliberate departures from the reference artwork, both because this
 * deployment's real backend contract requires them:
 * - "Email Address" -> "Username": there is no email field anywhere in this
 *   system -- ADMIN_USERNAME is a plain username, not an address.
 * - No "Forgot password?" link and no "Remember me" checkbox: this project
 *   has no password-reset infrastructure (explicitly out of scope) and the
 *   session already persists via its own cookie lifetime regardless of any
 *   checkbox, so both would be UI promising something the backend can't
 *   back -- exactly what this project's honesty policy exists to avoid.
 *
 * Real authentication: submitting calls POST /auth/login (via
 * AuthProvider's `login`), which sets a signed HttpOnly session cookie on
 * success. There is exactly one admin account, configured entirely through
 * environment variables (ADMIN_USERNAME / ADMIN_PASSWORD_HASH) -- no
 * registration, no password reset, no SSO, matching this deployment's
 * single-admin scope.
 */

const FEATURES = [
  {
    icon: ShieldCheck,
    title: 'Rule-Based Detection, AI Explanation',
    body: 'Sigma-style rules and sequence correlation detect; an LLM explains what they found.',
  },
  {
    icon: Crosshair,
    title: 'MITRE ATT&CK Aligned',
    body: 'Map detections to real attacker techniques.',
  },
  {
    icon: BrainCircuit,
    title: 'Contextual Analysis',
    body: 'Group detections per host and time window into investigable incidents.',
  },
  {
    icon: FileText,
    title: 'Automated Reporting',
    body: 'Generate clear, analyst-ready incident summaries.',
  },
]

const STATS = [
  { value: 'EVTX', label: 'Windows Log Analysis' },
  { value: 'MITRE ATT&CK', label: 'Technique Mapping' },
  { value: 'AI + Human', label: 'Stronger Together' },
]

const FIELD_SIZE = 'h-12 pr-3.5 pl-11 text-label'

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, error } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const redirectTo = (location.state as { from?: string } | null)?.from ?? '/'

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    setSubmitting(true)
    try {
      await login(username, password)
      navigate(redirectTo, { replace: true })
    } catch {
      // AuthProvider already recorded a generic, user-facing message in
      // `error` -- nothing else to do here except stop showing "Signing
      // in...". The password is deliberately left in place (not cleared)
      // so a mistyped username doesn't force retyping both fields.
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden">
      {/* The reference photo itself -- server racks, a triple-monitor SOC
          desk, and the floating threat-intel/analysis cards are all baked
          into this one image, not separate elements. A dark wash keeps the
          foreground copy and card readable over its brighter areas at every
          viewport width, including where object-cover crops it on mobile. */}
      <div className="absolute inset-0 -z-10">
        <img src="/login-background.png" alt="" className="h-full w-full object-cover" draggable={false} />
        <div className="absolute inset-0 bg-gradient-to-r from-bg-deep/85 via-bg-deep/55 to-bg-deep/40" />
        <div className="absolute inset-0 bg-gradient-to-t from-bg-deep/70 via-transparent to-bg-deep/30" />
      </div>
      <CursorGlow />

      <div className="relative flex min-h-screen flex-col px-6 py-6 sm:px-10 lg:px-14">
        {/* ---------------- Top bar ---------------- */}
        <header className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <NightOwlMark size={34} />
            <div className="leading-tight">
              <p className="text-label font-bold tracking-[0.08em] text-text">
                NIGHT<span className="text-accent-magenta">OWL</span>
              </p>
              <p className="text-[0.6rem] font-medium tracking-[0.28em] text-text-faint uppercase">
                AI-Powered SOC Analyst
              </p>
            </div>
          </div>
          <div className="hidden items-center gap-2.5 sm:flex">
            <nav className="flex items-center gap-5 text-micro font-semibold tracking-[0.2em] text-text-muted uppercase">
              <span>Detect</span>
              <span>Analyze</span>
              <span>Reason</span>
              <span>Respond</span>
            </nav>
            <span aria-hidden className="h-px w-10 bg-gradient-to-r from-accent-violet to-transparent" />
          </div>
        </header>

        {/* ---------------- Content ---------------- */}
        <div className="flex flex-1 items-center py-10">
          <div className="grid w-full items-center gap-12 lg:grid-cols-2 lg:gap-10">
            {/* ---------------- Brand / value panel ---------------- */}
            <section className="hidden flex-col lg:flex lg:pl-6 xl:pl-12">
              <span className="inline-flex w-fit items-center gap-2 rounded-full border border-accent-violet/35 bg-accent-violet/10 px-3.5 py-1.5 text-micro font-medium text-text-dim backdrop-blur-md">
                <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-accent-magenta shadow-glow-magenta" />
                Explainable Windows threat detection
              </span>

              <h1 className="mt-5 max-w-xl text-[2.75rem] leading-[1.08] font-bold tracking-tight text-text">
                Turn Security Data into{' '}
                <span className="bg-gradient-to-r from-accent-violet to-accent-magenta bg-clip-text text-transparent">
                  Actionable Insights
                </span>
              </h1>

              <p className="mt-4 max-w-md text-label leading-relaxed text-text-muted">
                NightOwl uses AI and MITRE ATT&CK knowledge to detect threats, correlate signals, and assist SOC
                analysts with faster, smarter investigations.
              </p>

              <ul className="mt-8 flex flex-col gap-4">
                {FEATURES.map(({ icon: Icon, title, body }) => (
                  <li key={title} className="flex items-start gap-3.5">
                    <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-control border border-accent-primary/25 bg-accent-primary/10 text-accent-violet shadow-glow-primary backdrop-blur-md">
                      <Icon className="h-5 w-5" />
                    </span>
                    <div className="min-w-0">
                      <p className="text-label font-semibold text-text">{title}</p>
                      <p className="mt-0.5 max-w-sm text-meta leading-relaxed text-text-muted">{body}</p>
                    </div>
                  </li>
                ))}
              </ul>

              <div className="mt-9 flex max-w-lg divide-x divide-line rounded-card border border-line bg-surface-1/60 shadow-card backdrop-blur-xl">
                {STATS.map((stat) => (
                  <div key={stat.label} className="flex-1 px-4 py-3.5 text-center first:pl-5 last:pr-5">
                    <p className="truncate bg-gradient-to-r from-accent-violet to-accent-magenta bg-clip-text text-label font-bold text-transparent">
                      {stat.value}
                    </p>
                    <p className="mt-0.5 text-micro text-text-muted">{stat.label}</p>
                  </div>
                ))}
              </div>

              <div className="mt-6 flex items-center gap-3 text-micro font-semibold tracking-[0.18em] text-text-faint uppercase">
                <span aria-hidden className="h-px w-8 bg-gradient-to-r from-accent-violet to-transparent" />
                Built for SOC teams
                <span aria-hidden>|</span>
                Secure
                <span aria-hidden>|</span>
                Intelligent
                <span aria-hidden>|</span>
                Resilient
              </div>
            </section>

            {/* ---------------- Sign-in card ---------------- */}
            <section className="relative mx-auto w-full max-w-md">
              <Reflection height="34%" />
              <div className="relative rounded-[22px] border border-line-strong bg-surface-1/70 px-7 py-9 shadow-e5 backdrop-blur-2xl sm:px-9">
                <div className="flex justify-center">
                  <NightOwlMark size={72} className="drop-shadow-[0_0_28px_var(--color-accent-violet)]" />
                </div>

                <p className="mt-4 text-center text-[1.35rem] leading-tight font-bold tracking-[0.06em] text-text">
                  NIGHT<span className="text-accent-magenta">OWL</span>
                </p>
                <p className="mt-0.5 text-center text-[0.65rem] font-medium tracking-[0.3em] text-text-faint uppercase">
                  AI-Powered SOC Analyst
                </p>

                <h2 className="mt-6 text-center text-title leading-tight font-bold text-text">Admin Login</h2>
                <p className="mt-1 text-center text-meta text-text-muted">Sign in to continue to NightOwl</p>

                <form onSubmit={handleSubmit} className="mt-7 flex flex-col gap-4">
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="login-username" className="text-meta font-semibold text-text-dim">
                      Username
                    </label>
                    <div className="relative">
                      <User className="pointer-events-none absolute top-1/2 left-3.5 z-10 h-4 w-4 -translate-y-1/2 text-text-muted" />
                      <TextInput
                        id="login-username"
                        type="text"
                        required
                        autoComplete="username"
                        autoFocus
                        disabled={submitting}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Enter your admin username"
                        className={FIELD_SIZE}
                      />
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="login-password" className="text-meta font-semibold text-text-dim">
                      Password
                    </label>
                    <div className="relative">
                      <Lock className="pointer-events-none absolute top-1/2 left-3.5 z-10 h-4 w-4 -translate-y-1/2 text-text-muted" />
                      <TextInput
                        id="login-password"
                        type={showPassword ? 'text' : 'password'}
                        required
                        autoComplete="current-password"
                        disabled={submitting}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter your password"
                        className={`${FIELD_SIZE} pr-11`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((v) => !v)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        className="absolute top-1/2 right-3 -translate-y-1/2 rounded p-1 text-text-muted transition-colors hover:text-accent-violet"
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>

                  {error && (
                    <p
                      role="alert"
                      className="rounded-control border border-accent-red/30 bg-accent-red/10 px-3.5 py-2.5 text-meta text-accent-red"
                    >
                      {error}
                    </p>
                  )}

                  <Button
                    type="submit"
                    variant="primary"
                    size="lg"
                    className="mt-1 w-full"
                    disabled={submitting}
                    icon={<ArrowRight className="h-4 w-4" />}
                  >
                    {submitting ? 'Signing in...' : 'Sign In'}
                  </Button>
                </form>
              </div>
            </section>
          </div>
        </div>
      </div>
    </main>
  )
}

export default LoginPage
