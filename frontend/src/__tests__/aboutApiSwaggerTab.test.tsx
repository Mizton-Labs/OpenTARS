/**
 * Tests for the About page's API Swagger tab (issue-local-030).
 *
 * `swaggerUiSrc` is exercised for real (it only builds a relative URL string,
 * no network) to confirm the iframe and the "open in a new tab" link both
 * point at the docs route. The relative form matters: it is what keeps the
 * embedded page resolving inside a reverse-proxy alias rather than at the
 * proxy root — see backend/main.py's /docs route for the full rationale.
 */
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

import ApiSwaggerTab from '../pages/about/ApiSwaggerTab'

describe('ApiSwaggerTab', () => {
  it('embeds the Swagger UI iframe pointing at the docs route', () => {
    render(<ApiSwaggerTab />)

    const iframe = screen.getByTitle('OpenTARS API Swagger UI')
    expect(iframe.tagName).toBe('IFRAME')
    expect(iframe).toHaveAttribute('src', 'docs')
  })

  it('offers an "open in a new tab" link to the same docs route', () => {
    render(<ApiSwaggerTab />)

    const openLink = screen.getByRole('link', { name: /open in a new tab/i })
    expect(openLink).toHaveAttribute('href', 'docs')
    expect(openLink).toHaveAttribute('target', '_blank')
    expect(openLink).toHaveAttribute('rel', expect.stringContaining('noopener'))
  })

  it('uses a document-relative src so it resolves inside a proxy alias', () => {
    render(<ApiSwaggerTab />)
    const src = screen.getByTitle('OpenTARS API Swagger UI').getAttribute('src')
    // A leading slash would resolve against the proxy ROOT (the parent app),
    // which is exactly the bug this relative form prevents.
    expect(src?.startsWith('/')).toBe(false)
  })

  it('renders its own heading', () => {
    render(<ApiSwaggerTab />)
    expect(screen.getByRole('heading', { name: 'API Swagger' })).toBeInTheDocument()
  })
})
