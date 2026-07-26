/**
 * Branding logo (prompts-045, rebranded to OpenTARS in issue-local-024).
 *
 * Renders the operator-configured logo image when one exists, otherwise the
 * bundled default OpenTARS mark (frontend/src/assets/tars-logo-app.png).
 * Both paths render a plain <img> — the only difference is the src — so an
 * operator-uploaded logo behaves identically to the shipped default. Two
 * usage modes:
 *   - hasLogo known (Sidebar, via the /api/app/logo-info query): pass it
 *     explicitly so we render the right element on first paint.
 *   - hasLogo unknown (Login, which is unauthenticated and cannot query
 *     logo-info): omit it; we optimistically try the image and fall back to
 *     the default mark via onError. GET /api/app/logo is public, so this
 *     works for signed-out users.
 *
 * The backend serves the operator logo with Cache-Control: no-cache, so a
 * replaced image refreshes without any client-side cache-busting.
 */
import { useState, useEffect } from 'react'
import { clsx } from 'clsx'
import { logoSrc } from '../api/client'
import defaultLogo from '../assets/tars-logo-app.png'

interface Props {
  hasLogo?: boolean
  /** Square pixel size of the badge. */
  size?: number
  className?: string
}

export default function BrandLogo({ hasLogo, size = 28, className }: Props) {
  const [failed, setFailed] = useState(false)

  // Reset the failure flag if the logo availability changes (e.g. a logo is
  // uploaded after an earlier 404).
  useEffect(() => {
    setFailed(false)
  }, [hasLogo])

  const useCustom = hasLogo !== false && !failed

  return (
    <img
      src={useCustom ? logoSrc() : defaultLogo}
      alt="OpenTARS"
      width={size}
      height={size}
      className={clsx('object-contain rounded-md', className)}
      onError={() => {
        if (useCustom) setFailed(true)
      }}
    />
  )
}
