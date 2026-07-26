/**
 * Tests for issue-local-022 (item 6): HuntDetail.tsx's IOCs tab now shows
 * the richer enriched RetrohuntPanel (All/Sanitized/Removed + verdict
 * toggles) once the active run's Deep Retrohunt Lead exists, instead of
 * always showing the older plain flat extracted_iocs list — the flat list
 * remains only as a fallback for runs that haven't reached that pipeline
 * step yet.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { THuntPackage, THuntPackageRun, THExtractedIOC, THGenerationRecord } from '../api/client'

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
    status: 'completed',
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    evidence_count: 1,
    generation_status: 'completed',
    phases: [],
    total_elapsed_s: 1.2,
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

function makeExtractedIoc(overrides: Partial<THExtractedIOC> = {}): THExtractedIOC {
  return {
    id: 'ioc-1',
    hunt_package_id: 'pkg-1',
    evidence_item_id: 'ev-1',
    ioc: 'flat.example',
    ioc_type: 'domain',
    ioc_description: '',
    noise_score: 0.1,
    flagged_noisy: false,
    action: 'keep',
    ...overrides,
  } as THExtractedIOC
}

function makeGenRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    id: 'run-1',
    run_id: 'run-1',
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    ...overrides,
  } as THGenerationRecord
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
  vi.mocked(api.threatHunting.listRuns).mockResolvedValue([makeRun()])
  vi.mocked(api.threatHunting.listRunResults).mockResolvedValue([])
  vi.mocked(api.threatHunting.getRunReport).mockRejectedValue(new Error('no report'))
  vi.mocked(api.threatHunting.listRunComments).mockResolvedValue([])
})

describe('HuntDetail IOCs tab consolidation (issue-local-022 item 6)', () => {
  it('shows the RetrohuntPanel (Sanitized/All/Removed filter) once the run has a deep_retrohunt lead', async () => {
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([makeExtractedIoc()])
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue(
      makeGenRecord({
        deep_retrohunt: {
          sanitized_iocs: [
            {
              ioc: 'enriched.example',
              ioc_type: 'domain',
              ioc_description: '',
              noise_score: 0.1,
              noise_reasons: [],
              search_token: 'tok',
              action: 'keep',
            },
          ],
          ioc_csv: '',
          total_ioc_count: 1,
          noisy_ioc_count: 0,
          high_noise_ioc_count: 0,
          spl_draft: '',
          spl_macro_name: 'macro',
          search_hint: '',
          analyst_notes: '',
          llm_parse_error: false,
        },
      }),
    )
    renderDetail()

    // IOCs tab is not active by default (Evidence is) — switch to it.
    fireEvent.click(await screen.findByRole('button', { name: 'IOCs' }))

    expect(await screen.findByText('Deep Retrohunt Lead')).toBeInTheDocument()
    expect(screen.getByText('enriched.example')).toBeInTheDocument()
    // The old flat-list-only IOC ("flat.example") must not appear — the
    // enriched table replaces it, it doesn't sit alongside it.
    expect(screen.queryByText('flat.example')).not.toBeInTheDocument()
  })

  it('falls back to the flat IOC list when the run has no deep_retrohunt lead yet', async () => {
    vi.mocked(api.threatHunting.listIocs).mockResolvedValue([makeExtractedIoc()])
    vi.mocked(api.threatHunting.getRunStatus).mockResolvedValue(makeGenRecord({ deep_retrohunt: null }))
    renderDetail()

    fireEvent.click(await screen.findByRole('button', { name: 'IOCs' }))

    expect(await screen.findByText('flat.example')).toBeInTheDocument()
    expect(screen.queryByText('Deep Retrohunt Lead')).not.toBeInTheDocument()
  })
})
