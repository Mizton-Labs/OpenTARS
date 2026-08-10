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
import { Clock, CheckCircle, AlertTriangle, Trash2, Pencil, Plus, Check, X } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem } from '../../api/client'
import ConfirmDialog from '../../components/ConfirmDialog'
import EvidenceContent from './EvidenceContent'
import AddEvidenceModal from './AddEvidenceModal'

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
  // issue-local-042 (item 23): Add Item moved here from HuntDetail.tsx's
  // top button bar — evidence management (add/rename/delete) now lives
  // entirely in this tab instead of being split across two places.
  const [showAddItem, setShowAddItem] = useState(false)
  const [renamingId, setRenamingId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')

  const { data: evidence = [] } = useQuery({
    queryKey: ['th-evidence', pkgId],
    queryFn: () => api.threatHunting.listEvidence(pkgId),
  })

  const invalidateEvidence = () => {
    qc.invalidateQueries({ queryKey: ['th-evidence', pkgId] })
    qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
    qc.invalidateQueries({ queryKey: ['th-packages'] })
  }

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
      invalidateEvidence()
      setConfirmDeleteId(null)
    },
  })

  const renameMut = useMutation({
    mutationFn: ({ itemId, label }: { itemId: string; label: string }) =>
      api.threatHunting.updateEvidence(pkgId, itemId, { label }),
    onSuccess: () => {
      invalidateEvidence()
      setRenamingId(null)
    },
  })

  const startRename = (item: THEvidenceItem) => {
    setRenamingId(item.id)
    setRenameValue(item.label || item.source_ref)
  }

  const addItemButton = isResearcher && (
    <button
      type="button"
      className="btn-secondary flex items-center gap-2 text-sm"
      onClick={() => setShowAddItem(true)}
    >
      <Plus className="w-4 h-4" />
      Add Item
    </button>
  )

  const addItemModal = showAddItem && (
    <AddEvidenceModal
      pkgId={pkgId}
      onClose={() => setShowAddItem(false)}
      onAdded={() => {
        invalidateEvidence()
        setShowAddItem(false)
      }}
    />
  )

  if (evidence.length === 0) {
    return (
      <div className="text-center py-8 space-y-3">
        <p className="text-sm text-gray-500">No evidence items yet.</p>
        {addItemButton}
        {addItemModal}
      </div>
    )
  }

  // issue-local-040: evidence rows exist right at upload time, but their
  // content only gets fetched/parsed once a run's intake_classifier step
  // actually processes them — before the first run starts, the content
  // pane has nothing meaningful to show even though evidence.length > 0.
  // issue-local-042 (item 23): the list itself (with add/rename/delete)
  // stays visible either way — only the content pane's message changes.
  const selected = (evidence as THEvidenceItem[]).find((e) => e.id === selectedId)

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-end">{addItemButton}</div>
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(220px,1fr)_minmax(0,2fr)] gap-4">
        {/* Sidebar list */}
        <div className="space-y-1 lg:max-h-[70vh] lg:overflow-y-auto">
          {(evidence as THEvidenceItem[]).map((item) => (
            <div
              key={item.id}
              role={renamingId === item.id ? undefined : 'button'}
              tabIndex={renamingId === item.id ? undefined : 0}
              onClick={() => renamingId !== item.id && setSelectedId(item.id)}
              onKeyDown={(e) => renamingId !== item.id && e.key === 'Enter' && setSelectedId(item.id)}
              className={clsx(
                'w-full flex items-start gap-2 rounded-lg px-3 py-2 text-left transition-colors border',
                renamingId === item.id ? 'cursor-default' : 'cursor-pointer',
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
                {renamingId === item.id ? (
                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    <input
                      autoFocus
                      className="input text-sm py-0.5 flex-1 min-w-0"
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && renameValue.trim()) {
                          renameMut.mutate({ itemId: item.id, label: renameValue.trim() })
                        } else if (e.key === 'Escape') {
                          setRenamingId(null)
                        }
                      }}
                    />
                    <button
                      className="p-1 text-gray-500 hover:text-green-400 shrink-0"
                      disabled={!renameValue.trim() || renameMut.isPending}
                      onClick={() => renameMut.mutate({ itemId: item.id, label: renameValue.trim() })}
                      title="Save"
                    >
                      <Check className="w-3.5 h-3.5" />
                    </button>
                    <button
                      className="p-1 text-gray-500 hover:text-gray-300 shrink-0"
                      onClick={() => setRenamingId(null)}
                      title="Cancel"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <>
                    <p className="text-sm font-medium truncate">{item.label || item.source_ref}</p>
                    <p className="text-[11px] text-gray-500">{item.item_type}</p>
                  </>
                )}
              </div>
              {isResearcher && renamingId !== item.id && (
                <div className="flex items-center gap-0.5 shrink-0">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      startRename(item)
                    }}
                    className="p-1 text-gray-600 hover:text-gray-300"
                    title="Rename"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      setConfirmDeleteId(item.id)
                    }}
                    className="p-1 text-gray-600 hover:text-red-400"
                    title="Remove"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Content card */}
        <div className="card min-h-[320px] flex flex-col">
          {!hasRuns ? (
            <div className="text-center py-10 space-y-3 m-auto">
              <p className="text-sm text-gray-400 max-w-sm mx-auto">
                Not retrieved yet — this item&apos;s content isn&apos;t fetched or parsed until
                the analysis pipeline runs.
              </p>
              {onGoToAnalysis && (
                <button type="button" className="btn-primary text-sm" onClick={onGoToAnalysis}>
                  Go to Analysis to start the run
                </button>
              )}
            </div>
          ) : (
            selected && <EvidenceContent item={selected} pkgId={pkgId} />
          )}
        </div>
      </div>

      {addItemModal}

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
