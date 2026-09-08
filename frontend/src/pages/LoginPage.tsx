import { ArrowRight, BrainCircuit, Crosshair, Eye, EyeOff, FileText, Lock, Shield, ShieldCheck, User } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { NightOwlMark } from '../components/brand/NightOwlMark'
import { AmbientBackground, Button, CursorGlow, Reflection, TextInput } from '../components/ui'
import { useAuth } from '../context/auth/useAuth'

/**
 * The NightOwl sign-in screen.
 *
 * Real authentication: submitting calls POST /auth/login (via
 * AuthProvider's `login`), which sets a signed HttpOnly session cookie on
 * success. There is exactly one admin account, configured entirely through
 * environment variables (ADMIN_USERNAME / ADMIN_PASSWORD_HASH) -- no
 * registration, no password reset, no SSO, matching this deployment's
 * single-admin scope.
 *
 * Built from the same tokens as the rest of the app, so it belongs to one
 * product rather than being a detached splash screen.
 */

const FEATURES = [
  {
    icon: ShieldCheck,
    title: 'AI-Powered Detection',
    body: 'Sigma rules and LLM reasoning surface real threats from raw Sysmon telemetry.',
  },
  {
    icon: Crosshair,
    title: 'MITRE ATT&CK Aligned',
    body: 'Every detection maps to a validated technique so attacker behaviour is legible.',
  },
  {
    icon: BrainCircuit,
    title: 'Grounded LLM Reasoning',
    body: 'Retrieved context, a drafted explanation, then a self-critique against its own sources.',
  },
  {
    icon: FileText,
    title: 'Automated Reporting',
    body: 'Shift summaries and incident reports generated from the evidence already collected.',
  },
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
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 py-10">
      {/* Same atmosphere component as the console, turned up: one lighting
          system across the whole product rather than a bespoke splash. */}
      <AmbientBackground seed="login" intensity="cinematic" />
      <CursorGlow />
      {/* The owl watching from the right edge of the reference artwork.
          Routed through NightOwlMark so it carries the same brand hue shift
          as every other instance of the emblem. */}
      <NightOwlMark
        size={672}
        className="pointer-events-none absolute top-1/2 -right-32 hidden -translate-y-1/2 animate-float opacity-[0.13] blur-[1px] xl:block"
      />

      <div className="relative grid w-full max-w-6xl items-center gap-12 lg:grid-cols-2 lg:gap-16">
        {/* ---------------- Brand / value panel ---------------- */}
        <section className="hidden flex-col lg:flex">
          <NightOwlMark size={132} className="animate-glow-pulse drop-shadow-[0_0_28px_var(--color-accent-violet)]" />

          <h1 className="mt-5 text-[2.75rem] leading-none font-bold tracking-[0.08em]">
            <span className="text-text">NIGHT</span>
            <span className="bg-gradient-to-r from-accent-violet to-accent-magenta bg-clip-text text-transparent">
              OWL
            </span>
          </h1>
          <p className="mt-3 text-label font-medium tracking-[0.34em] text-text-dim uppercase">AI-Powered SOC Analyst</p>

          <span aria-hidden className="mt-5 h-px w-16 bg-gradient-to-r from-accent-violet to-transparent" />

          <p className="mt-5 max-w-md text-title leading-relaxed text-text-dim">
            Detect threats. Correlate signals. Outsmart adversaries.
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

          <div className="mt-9 flex max-w-md items-center gap-4 rounded-card border border-line bg-surface-1/60 px-4 py-3.5 shadow-card backdrop-blur-xl">
            <Shield className="h-5 w-5 shrink-0 text-accent-violet" />
            <div className="min-w-0 flex-1">
              <p className="text-meta font-semibold text-text">Built for SOC teams</p>
              <p className="text-micro text-text-muted">Secure. Intelligent. Relentless.</p>
            </div>
            <div className="shrink-0 text-right">
              <p className="bg-gradient-to-r from-accent-violet to-accent-magenta bg-clip-text text-title font-bold text-transparent">
                24/7
              </p>
              <p className="text-micro text-text-muted">Monitoring</p>
            </div>
          </div>
        </section>

        {/* ---------------- Sign-in card ---------------- */}
        <section className="relative mx-auto w-full max-w-md">
          <Reflection height="34%" />
          <div className="relative rounded-[22px] border border-line-strong bg-surface-1/70 px-7 py-9 shadow-e5 backdrop-blur-2xl sm:px-9">
            <div className="flex justify-center">
              <span className="flex h-16 w-16 items-center justify-center rounded-full border border-accent-violet/40 bg-accent-primary/10 text-accent-violet shadow-glow-violet">
                <Lock className="h-6 w-6" />
              </span>
            </div>

            <h2 className="mt-6 text-center text-[1.75rem] leading-tight font-bold text-text">Admin Login</h2>
            <p className="mt-1.5 text-center text-label text-text-muted">Sign in to continue to NightOwl</p>

            <form onSubmit={handleSubmit} className="mt-7 flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="login-username" className="text-meta font-semibold text-text-dim">
                  Username
                </label>
                <div className="relative">
                  <User className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-text-muted" />
                  <TextInput
                    id="login-username"
                    type="text"
                    required
                    autoComplete="username"
                    autoFocus
                    disabled={submitting}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter your username"
                    className={FIELD_SIZE}
                  />
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label htmlFor="login-password" className="text-meta font-semibold text-text-dim">
                  Password
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-text-muted" />
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
                <p role="alert" className="rounded-control border border-accent-red/30 bg-accent-red/10 px-3.5 py-2.5 text-meta text-accent-red">
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
    </main>
  )
}

export default LoginPage
