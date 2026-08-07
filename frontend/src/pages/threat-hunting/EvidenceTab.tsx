/**
 * EvidenceTab — issue-local-023: two-pane Evidence tab (sidebar list on the
 * left, content viewer on the right), replacing the old flat metadata-only
 * card list that gave no way to see what was actually uploaded/extracted.
 *
 * Fully self-contained — owns its own evidence query (shares the
 * `['th-evidence', pkgId]` cache with HuntDetail.tsx's own fetch, no
 * duplicate network request), delete flow, and selection state — matching
 * the pattern of other extracted tab components (ThreatIntelTab.tsx,
 * ComparisonAssessmentTab.tsx).
 *
 * The content pane itself is `EvidenceContent.tsx` (extracted issue-local-034
 * so Data Explorer's evidence rows can reuse the exact same preview — see
 * that file for the PDF/text/"not processed" rendering rules).
 */

import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Clock, CheckCircle, AlertTriangle, Trash2 } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem } from '../../api/client'
import ConfirmDialog from '../../components/ConfirmDialog'
import EvidenceContent from './EvidenceContent'

const PARSE_STATUS_ICON: Record<string, React.ReactNode> = {
  ok: <CheckCircle className="w-3.5 h-3.5 text-green-400" />,
  partial: <Clock className="w-3.5 h-3.5 text-amber-400" />,
  error: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
}

export default function EvidenceTab({
  pkgId,
  isResearcher,
  hasRuns,
  onGoToAnalysis,
}: {
  pkgId: string
  isResearcher: boolean
  /** issue-local-040: whether this package has ever had a generation run
   *  started — drives the "analysis hasn't started" notice below, distinct
   *  from the "no evidence at all" case just below it. */
  hasRuns?: boolean
  onGoToAnalysis?: () => void
}) {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  const { data: evidence = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  // Auto-select the first item when the list loads, or re-select once the
  // currently-selected item is deleted / no longer present.
  useEffect(() => {
    if (evidence.length === 0) {
      setSelectedId(null)
      return
    }
    if (!selectedId || !evidence.some((e) => e.id === selectedId)) {
      setSelectedId(evidence[0].id)
    }
  }, [evidence, selectedId])

  const deleteMut = useMutation({
    mutationFn: (itemId: string) => api.threatHunting.deleteEvidence(pkgId, itemId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-evidence', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setConfirmDeleteId(null)
    },
  })

  if (evidence.length === 0) {
    return <p className="text-sm text-gray-500 text-center py-8">No evidence items yet.</p>
  }

  // issue-local-040: evidence rows exist right at upload time, but their
  // content only gets fetched/parsed once a run's intake_classifier step
  // actually processes them — before the first run starts, this pane has
  // nothing meaningful to show even though evidence.length > 0.
  if (!hasRuns) {
    return (
      <div className="text-center py-10 space-y-3">
        <p className="text-sm text-gray-400 max-w-sm mx-auto">
          Evidence has been added, but the run hasn&apos;t started yet — its content isn&apos;t
          fetched or parsed until the analysis pipeline runs.
        </p>
        {onGoToAnalysis && (
          <button type="button" className="btn-primary text-sm" onClick={onGoToAnalysis}>
            Go to Analysis to start the run
          </button>
        )}
      </div>
    )
  }

  const selected = (evidence as THEvidenceItem[]).find((e) => e.id === selectedId)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[minmax(220px,1fr)_minmax(0,2fr)] gap-4">
      {/* Sidebar list */}
      <div className="space-y-1 lg:max-h-[70vh] lg:overflow-y-auto">
        {(evidence as THEvidenceItem[]).map((item) => (
          <div
            key={item.id}
            role="button"
            tabIndex={0}
            onClick={() => setSelectedId(item.id)}
            onKeyDown={(e) => e.key === 'Enter' && setSelectedId(item.id)}
            className={clsx(
              'w-full flex items-start gap-2 rounded-lg px-3 py-2 text-left transition-colors border cursor-pointer',
              item.id === selectedId
                ? 'bg-brand-900/20 border-brand-500 text-brand-100'
                : 'bg-gray-800/40 border-transparent hover:border-gray-700 text-gray-300',
            )}
          >
            <div className="mt-0.5 shrink-0">
              {item.parse_status === 'pending' ? (
                <Clock className="w-3.5 h-3.5 text-blue-500" />
              ) : (
                PARSE_STATUS_ICON[item.parse_status] ?? PARSE_STATUS_ICON.ok
              )}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{item.label || item.source_ref}</p>
              <p className="text-[11px] text-gray-500">{item.item_type}</p>
            </div>
            {isResearcher && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  setConfirmDeleteId(item.id)
                }}
                className="p-1 text-gray-600 hover:text-red-400 shrink-0"
                title="Remove"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Content card */}
      <div className="card min-h-[320px] flex flex-col">
        {selected && <EvidenceContent item={selected} pkgId={pkgId} />}
      </div>

      {confirmDeleteId && (
        <ConfirmDialog
          title="Delete Evidence Item?"
          message="This permanently removes this evidence item. If analysis has been run, the results will not be affected."
          confirmLabel="Delete"
          onConfirm={() => deleteMut.mutate(confirmDeleteId)}
          onCancel={() => setConfirmDeleteId(null)}
        />
      )}
    </div>
  )
}
