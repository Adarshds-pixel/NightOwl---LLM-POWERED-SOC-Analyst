import { useMemo } from 'react'

/**
 * The environment every page sits inside: two slowly drifting aurora orbs,
 * a faint cyber grid, a sparse particle field and a vignette.
 *
 * Why a component rather than body::before/::after: this needs more than
 * two independently-animated layers. The class names are defined in
 * index.css (`.ambient-*`), which is also where the preference gating lives
 * -- `data-ambient='off'` hides the whole thing and `data-motion='reduced'`
 * (or an OS reduced-motion setting) freezes the drift while keeping the
 * lighting. Nothing here is interactive: the root is `pointer-events: none`
 * and `contain: strict`, so it can never intercept a click or force the
 * application above it to re-layout.
 *
 * Performance: only `transform`/`opacity` are animated. The orbs carry one
 * static `blur()` that never changes, because animating a filter would be
 * the single most expensive thing this effect could do.
 */

/** Deterministic PRNG -- particles must not reshuffle on every re-render. */
function seeded(seed: number): () => number {
  let value = seed
  return () => {
    value = (value * 1664525 + 1013904223) % 4294967296
    return value / 4294967296
  }
}

function hash(text: string): number {
  let acc = 2166136261
  for (let i = 0; i < text.length; i += 1) {
    acc ^= text.charCodeAt(i)
    acc = Math.imul(acc, 16777619)
  }
  return Math.abs(acc)
}

const PARTICLE_COUNT = 26

export function AmbientBackground({
  /** Shifts the lighting slightly per page, so Dashboard and MITRE are lit
   *  a little differently without either looking off-brand. Pass a route. */
  seed = 'nightowl',
  /** Login uses a stronger, more cinematic key light than the console. */
  intensity = 'console',
}: {
  seed?: string
  intensity?: 'console' | 'cinematic'
}) {
  const particles = useMemo(() => {
    const rand = seeded(hash(seed) || 1)
    return Array.from({ length: PARTICLE_COUNT }, () => ({
      left: rand() * 100,
      top: 55 + rand() * 45,
      size: 1 + rand() * 2,
      delay: rand() * 18,
      duration: 14 + rand() * 12,
      opacity: 0.18 + rand() * 0.4,
    }))
  }, [seed])

  // A small deterministic offset per route keeps the two orbs from sitting
  // in exactly the same place on every page.
  const drift = useMemo(() => {
    const rand = seeded(hash(seed) + 7)
    return { ax: rand() * 14 - 7, ay: rand() * 10 - 5, bx: rand() * 14 - 7, by: rand() * 10 - 5 }
  }, [seed])

  const cinematic = intensity === 'cinematic'

  return (
    <div className="ambient-root" aria-hidden>
      {/* Key light: violet, upper-left. */}
      <div
        className="ambient-orb animate-aurora-a"
        style={{
          left: `${-12 + drift.ax}%`,
          top: `${-18 + drift.ay}%`,
          width: cinematic ? '52rem' : '44rem',
          height: cinematic ? '52rem' : '44rem',
          background: `radial-gradient(circle, rgba(124, 58, 237, ${cinematic ? 0.4 : 0.28}), transparent 68%)`,
        }}
      />
      {/* Fill light: magenta, lower-right. */}
      <div
        className="ambient-orb animate-aurora-b"
        style={{
          right: `${-14 + drift.bx}%`,
          bottom: `${-20 + drift.by}%`,
          width: cinematic ? '46rem' : '38rem',
          height: cinematic ? '46rem' : '38rem',
          background: `radial-gradient(circle, rgba(236, 72, 153, ${cinematic ? 0.24 : 0.16}), transparent 68%)`,
        }}
      />
      {/* Rim light: bright purple, upper-right. Static -- three moving orbs
          starts to read as movement rather than atmosphere. */}
      <div
        className="ambient-orb"
        style={{
          right: '6%',
          top: '-10%',
          width: '30rem',
          height: '30rem',
          background: `radial-gradient(circle, rgba(168, 85, 247, ${cinematic ? 0.18 : 0.12}), transparent 70%)`,
        }}
      />

      <div className="ambient-grid" />

      {particles.map((particle, i) => (
        <span
          key={i}
          className="ambient-particle animate-particle"
          style={{
            left: `${particle.left}%`,
            top: `${particle.top}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
            opacity: particle.opacity,
            animationDelay: `${particle.delay}s`,
            animationDuration: `${particle.duration}s`,
          }}
        />
      ))}

      <div className="ambient-vignette" />
    </div>
  )
}
