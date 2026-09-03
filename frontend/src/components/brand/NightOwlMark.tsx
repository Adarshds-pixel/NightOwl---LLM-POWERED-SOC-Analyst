import clsx from 'clsx'

/**
 * The NightOwl emblem and the analyst avatar, both cropped from the brand
 * artwork in `frontend design images/logos.png` and served from public/.
 *
 * They are plain <img> rather than inline SVG because the source is raster
 * artwork; each asset is a 320px square with its edges faded to transparent,
 * so the artwork's own glow melts into the sidebar surface instead of
 * showing a rectangle. Both are decorative next to real text, so they carry
 * empty alt text and the label lives in the markup beside them.
 *
 * BRAND_HUE_SHIFT rotates the source artwork's cyan/blue palette into the
 * violet/magenta brand range. The PNGs are raster and predate the violet
 * redesign, so a filter is the only way to keep one asset on-palette
 * everywhere it appears; the silver highlights are near-desaturated and
 * survive the rotation untouched. Replace the artwork and this goes away.
 */

const BRAND_HUE_SHIFT = 'hue-rotate(40deg) saturate(1.05)'

export function NightOwlMark({ size = 38, className }: { size?: number; className?: string }) {
  return (
    <img
      src="/nightowl-owl.png"
      alt=""
      width={size}
      height={size}
      className={clsx('shrink-0 select-none', className)}
      style={{ width: size, height: size, filter: BRAND_HUE_SHIFT }}
      draggable={false}
    />
  )
}

export function AnalystAvatar({ size = 34, className }: { size?: number; className?: string }) {
  return (
    <img
      src="/nightowl-analyst.png"
      alt=""
      width={size}
      height={size}
      className={clsx('shrink-0 select-none rounded-full', className)}
      style={{ width: size, height: size, filter: BRAND_HUE_SHIFT }}
      draggable={false}
    />
  )
}
