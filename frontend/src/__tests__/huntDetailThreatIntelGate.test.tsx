/**
 * Tests for issue-local-022 (item 3): Re-run and report generation must be
 * gated while a Threat Intel analysis is running for the active run
 * (run.threat_intel_status === 'running') — previously there was no such
 * gate, so a re-run or report regeneration could race an in-flight Threat
 * Intel analysis writing to the same run.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THuntPackageRun } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      threatHunting: {
        ...actual.api.threatHunting,
        getPackage: vi.fn(),
        listEvidence: vi.fn(),
        listIocs: vi.fn(),
        listRuns: vi.fn(),
        getRunStatus: vi.fn(),
        listRunResults: vi.fn(),
        getRunReport: vi.fn(),
        listRunComments: vi.fn(),
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
import HuntDetail from '../pages/threat-hunting/HuntDetail'

function makePkg(overrides: Partial<THuntPackage> = {}): THuntPackage {
  return {
    id: 'pkg-1',
    name: 'Test Package',
    description: '',
    status: 'approved',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 1,
    generation_status: 'completed',
    phases: [],
    total_elapsed_s: null,
    run_created_at: '2026-01-01T00:00:00Z',
    runs: [],
    run_count: 1,
    ...overrides,
  }
}

function makeRun(overrides: Partial<THuntPackageRun> = {}): THuntPackageRun {
  return {
    id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    llm_model: 'gpt-oss',
    research_effort: 'high',
    created_at: '2026-01-01T00:00:00Z',
    phases: [],
    ...overrides,
  } as THuntPackageRun
}

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <HuntDetail pkgId="pkg-1" onBack={() => {}} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.threatHunting.getPackage).mockResolvedValue(makePkg())
  vi.mocked(api.threatHunting.listEvidence).mockResolvedValue([])
  vi.mocked(api.threatHunting.listIocs).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunStatus).mockRejectedValue(new Error('no status'))
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
})

describe('HuntDetail Threat Intel in-progress gate (issue-local-022 item 3)', () => {
  it('disables the Re-run button while threat_intel_status is running', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ threat_intel_status: 'running' }),
    ])
    renderDetail()
    const btn = await screen.findByRole('button', { name: /Re-run/ })
    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute('title', expect.stringMatching(/Threat Intel analysis is still running/))
  })

  it('leaves the Re-run button enabled once threat_intel_status clears', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ threat_intel_status: null }),
    ])
    renderDetail()
    const btn = await screen.findByRole('button', { name: /Re-run/ })
    expect(btn).not.toBeDisabled()
  })

  it('does not open the Re-run dialog when clicked while disabled', async () => {
    vi.mocked(api.threatHunting.listRuns).mockResolvedValue([
      makeRun({ threat_intel_status: 'running' }),
    ])
    renderDetail()
    const btn = await screen.findByRole('button', { name: /Re-run/ })
    fireEvent.click(btn)
    expect(screen.queryByText('Re-run Hunt Package')).not.toBeInTheDocument()
  })
})
