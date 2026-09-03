import {
  ArrowRight,
  BrainCircuit,
  Crosshair,
  Eye,
  EyeOff,
  FileText,
  Lock,
  Mail,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { NightOwlMark } from '../components/brand/NightOwlMark'
import { AmbientBackground, Button, CursorGlow, Reflection } from '../components/ui'

/**
 * The NightOwl sign-in screen.
 *
 * IMPORTANT: this is the visual shell only. NightOwl has no accounts,
 * sessions or roles yet (see lib/preferences.ts and the Settings page's
 * "Auth model" row) -- authentication is tracked as future work. Nothing
 * here validates a credential and no route is gated by it: submitting the
 * form simply enters the console, exactly as navigating to "/" always has.
 * The page exists so the design system has a front door and so the intended
 * end state can be demonstrated; the footer says as much on screen rather
 * than implying a security control that does not exist.
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

export function LoginPage() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate('/')
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

            <h2 className="mt-6 text-center text-[1.75rem] leading-tight font-bold text-text">Welcome Back</h2>
            <p className="mt-1.5 text-center text-label text-text-muted">Sign in to continue to NightOwl</p>

            <form onSubmit={handleSubmit} className="mt-7 flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="login-email" className="text-meta font-semibold text-text-dim">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-text-muted" />
                  <input
                    id="login-email"
                    type="email"
                    required
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email"
                    className="h-12 w-full rounded-control border border-line bg-bg-deep/80 pr-3.5 pl-11 text-label text-text backdrop-blur-md placeholder:text-text-faint transition-all duration-200 focus:border-accent-violet/65 focus:shadow-glow-primary focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label htmlFor="login-password" className="text-meta font-semibold text-text-dim">
                  Password
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-text-muted" />
                  <input
                    id="login-password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    className="h-12 w-full rounded-control border border-line bg-bg-deep/80 pr-11 pl-11 text-label text-text backdrop-blur-md placeholder:text-text-faint transition-all duration-200 focus:border-accent-violet/65 focus:shadow-glow-primary focus:outline-none"
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

              <div className="flex justify-end">
                <button
                  type="button"
                  className="text-meta font-medium text-accent-violet transition-colors hover:text-accent-magenta"
                >
                  Forgot password?
                </button>
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="mt-1 w-full"
                icon={<ArrowRight className="h-4 w-4" />}
              >
                Sign In
              </Button>
            </form>

            <div className="my-6 flex items-center gap-3">
              <span className="h-px flex-1 bg-line" />
              <span className="text-micro font-semibold tracking-[0.18em] text-text-muted uppercase">or</span>
              <span className="h-px flex-1 bg-line" />
            </div>

            <Button
              variant="secondary"
              size="lg"
              className="w-full"
              icon={<Shield className="h-4 w-4" />}
              onClick={() => navigate('/')}
            >
              Sign in with SSO
            </Button>

            <p className="mt-7 text-center text-meta text-text-muted">
              Don&apos;t have an account?{' '}
              <span className="font-medium text-accent-violet">Contact your administrator</span>
            </p>
            <p className="mt-3 text-center text-micro leading-relaxed text-text-faint">
              Interface preview - NightOwl does not enforce authentication yet, so this form does not verify credentials.
            </p>
          </div>
        </section>
      </div>
    </main>
  )
}

export default LoginPage
