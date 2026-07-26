/**
 * BrandLogo tests (prompts-048, rebranded to OpenTARS in issue-local-024).
 *
 * Verifies the default OpenTARS mark fallback (bundled tars-logo-app.png)
 * and that an operator-configured logo still overrides it. Both paths
 * render a plain <img> — only the src differs — so no API mocking is
 * needed to render.
 */
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

import BrandLogo from '../components/BrandLogo'

describe('BrandLogo default mark (prompts-048)', () => {
  it('renders the default OpenTARS mark when no logo is configured', () => {
    render(<BrandLogo hasLogo={false} size={48} />)

    const img = screen.getByRole('img', { name: 'OpenTARS' })
    expect(img).toBeInTheDocument()
    expect(img).toHaveAttribute('src', expect.stringContaining('tars-logo-app'))
  })

  it('renders the operator logo image when one is configured', () => {
    render(<BrandLogo hasLogo={true} size={28} />)

    const img = screen.getByRole('img', { name: 'OpenTARS' })
    expect(img).toBeInTheDocument()
    expect(img).toHaveAttribute('src', expect.stringContaining('/app/logo'))
  })
})
