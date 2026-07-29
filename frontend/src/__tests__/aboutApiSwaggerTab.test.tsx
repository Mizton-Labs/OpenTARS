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
import userEvent from '@testing-library/user-event'
import { describe, it, expect } from 'vitest'

import ApiSwaggerTab from '../pages/about/ApiSwaggerTab'

const iframe = () => screen.getByTitle('OpenTARS API Swagger UI')
const openLink = () => screen.getByRole('link', { name: /open in a new tab/i })
const showAll = () => screen.getByRole('checkbox', { name: /show all endpoints/i })

describe('ApiSwaggerTab', () => {
  it('defaults to the API-key-reachable subset of the API', () => {
    render(<ApiSwaggerTab />)
    expect(showAll()).not.toBeChecked()
    expect(iframe()).toHaveAttribute('src', 'docs?api_keys_only=1')
  })

  it('switches to the full application API when "Show all endpoints" is ticked', async () => {
    const user = userEvent.setup()
    render(<ApiSwaggerTab />)

    await user.click(showAll())

    expect(showAll()).toBeChecked()
    expect(iframe()).toHaveAttribute('src', 'docs')
  })

  it('switches back to the subset when unticked', async () => {
    const user = userEvent.setup()
    render(<ApiSwaggerTab />)

    await user.click(showAll())
    await user.click(showAll())

    expect(iframe()).toHaveAttribute('src', 'docs?api_keys_only=1')
  })

  it('keeps the "open in a new tab" link in step with the checkbox', async () => {
    const user = userEvent.setup()
    render(<ApiSwaggerTab />)

    expect(openLink()).toHaveAttribute('href', 'docs?api_keys_only=1')
    expect(openLink()).toHaveAttribute('target', '_blank')
    expect(openLink()).toHaveAttribute('rel', expect.stringContaining('noopener'))

    await user.click(showAll())
    expect(openLink()).toHaveAttribute('href', 'docs')
  })

  it('explains which endpoint set is on screen', async () => {
    const user = userEvent.setup()
    render(<ApiSwaggerTab />)

    expect(screen.getByText(/reachable with a scoped API access key/i)).toBeInTheDocument()

    await user.click(showAll())
    expect(screen.getByText(/every endpoint in the application/i)).toBeInTheDocument()
  })

  it('uses a document-relative src so it resolves inside a proxy alias', () => {
    render(<ApiSwaggerTab />)
    // A leading slash would resolve against the proxy ROOT (the parent app),
    // which is exactly the bug this relative form prevents.
    expect(iframe().getAttribute('src')?.startsWith('/')).toBe(false)
  })

  it('renders its own heading', () => {
    render(<ApiSwaggerTab />)
    expect(screen.getByRole('heading', { name: 'API Swagger' })).toBeInTheDocument()
  })
})
