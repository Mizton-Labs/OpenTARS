/**
 * Tests for issue-local-017's asDisplayText helper and its use in
 * AnalysisTab.tsx / ReportPanel.tsx — defensive rendering of already-
 * persisted historical runs whose key_observations/suggested_actions/
 * detection_opportunities entries are objects instead of plain strings
 * (observed live: Mistral returning {observation, confidence, evidence}
 * for a key_observations entry, which previously crashed the whole page
 * with React's "objects are not valid as a child" error).
 */
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { asDisplayText } from '../pages/threat-hunting/llmTextUtils'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getRunStatus: vi.fn(),
        getGenerationStatus: vi.fn(),
        listIocs: vi.fn(),
        listEvidence: vi.fn(),
      },
    },
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isResearcher: true,
    isAdmin: true,
    authEnabled: false,
    isAuthenticated: true,
    loading: false,
    user: null,
  }),
}))

import { api } from '../api/client'
import AnalysisTab from '../pages/threat-hunting/AnalysisTab'

describe('asDisplayText', () => {
  it('returns a plain string unchanged', () => {
    expect(asDisplayText('hello')).toBe('hello')
  })

  it('extracts the first matching preferred key from an object', () => {
    const value = { observation: 'npm worm campaign', confidence: 'high', evidence: 'corpus' }
    expect(asDisplayText(value, ['observation', 'text'])).toBe('npm worm campaign')
  })

  it('falls back to the second preferred key when the first is absent', () => {
    expect(asDisplayText({ text: 'fallback' }, ['observation', 'text'])).toBe('fallback')
  })

  it('falls back to JSON.stringify when no preferred key matches', () => {
    const result = asDisplayText({ foo: 'bar' }, ['observation', 'text'])
    expect(result).toContain('foo')
    expect(result).toContain('bar')
  })

  it('coerces non-string, non-object values', () => {
    expect(asDisplayText(42)).toBe('42')
    expect(asDisplayText(null)).toBe('')
    expect(asDisplayText(undefined)).toBe('')
  })
})

describe('AnalysisTab — regression for object-shaped key_observations (issue-local-017)', () => {
  beforeEach(() => {
    vi.mocked(api.threatHunting.getRunStatus).mockReset()
    vi.mocked(api.threatHunting.listIocs).mockReset()
    vi.mocked(api.threatHunting.listEvidence).mockReset()
  })

  it('renders a live-observed object-shaped key_observations entry without crashing', async () => {
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue({
      hunt_package_id: 'pkg-1',
      run_id: 'run-1',
      generation_status: 'completed',
      threat_context: {
        summary: 's',
        confidence: 'high',
        key_observations: [
          {
            observation: 'npm worm campaign using stolen OIDC tokens',
            confidence: 'high',
            evidence: 'corpus mentions GitHub Actions cache poisoning',
          },
          'a plain string observation too',
        ],
      },
    })
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
    vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AnalysisTab pkgId="pkg-1" runId="run-1" />
      </QueryClientProvider>,
    )

    await waitFor(() =>
      expect(screen.getByText(/npm worm campaign using stolen OIDC tokens/)).toBeInTheDocument(),
    )
    expect(screen.getByText('a plain string observation too')).toBeInTheDocument()
  })
})
