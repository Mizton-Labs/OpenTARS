/**
 * ThreatHuntingDetail — detail page for a single hunt package.
 * Accessed via the nested route threat-hunting/:id.
 * Reads the package id from useParams() and renders HuntDetail.
 */
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import HuntDetail from './HuntDetail'

export default function ThreatHuntingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  // issue-local-034: `?run=<runId>` deep-links to a specific run — set by
  // Data Explorer's Run column (a hypothesis/lead/query/IOC/SIEM-search row
  // links to the exact run it came from, not just the package's newest
  // run). HuntDetail's own initialRunId prop already falls back to the
  // newest run when this doesn't match any run in the package.
  const [searchParams] = useSearchParams()
  const runId = searchParams.get('run') ?? undefined
  // issue-local-040: `?tab=analysis` set by ThreatHuntingNew.tsx right after
  // the evidence-upload wizard closes — the general default tab stays
  // 'evidence' for every other page load (revisiting an existing package).
  const initialTab = searchParams.get('tab') === 'analysis' ? 'analysis' : undefined

  if (!id) return null

  return (
    <HuntDetail
      pkgId={id}
      initialRunId={runId}
      initialTab={initialTab}
      // issue-local-032: '..' now resolves to the Dashboard, not the package
      // list — this page is only reached FROM the package list (or a direct
      // link), so "back" should return there, not to the Dashboard.
      onBack={() => navigate('../packages', { relative: 'path' })}
    />
  )
}
