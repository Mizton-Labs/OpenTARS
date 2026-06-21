import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Loader2, CheckCircle, AlertTriangle,
  ChevronDown, ChevronRight, Code2, Target, Brain, Crosshair, Radar,
} from 'lucide-react'
import { clsx } from 'clsx'
import {
  api,
  type THGenerationRecord,
  type THHypothesis,
  type THHuntingLead,
  type THQueryDraft,
  type THHuntTask,
} from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import RetrohuntPanel from './RetrohuntPanel'

export default function AnalysisTab({ pkgId }: { pkgId: string }) {
  const { isResearcher } = useAuth()
  const qc = useQueryClient()
  const [approvalNotes, setApprovalNotes] = useState('')
  const [showApproveForm, setShowApproveForm] = useState(false)

  // Poll generation status - refetch every 3s when running
  const { data: genRecord, isLoading } = useQuery({
    queryKey: ['th-generation', pkgId],
    queryFn: () => api.threatHunting.getGenerationStatus(pkgId).catch(() => null),
    refetchInterval: (query) => {
      const status = (query.state.data as THGenerationRecord | null)?.generation_status
      return status === 'running' ? 3000 : false
    },
  })

  const startMut = useMutation({
    mutationFn: () => api.threatHunting.startGeneration(pkgId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId] })
    },
  })

  const approveMut = useMutation({
    mutationFn: () => api.threatHunting.approveGeneration(pkgId, approvalNotes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setShowApproveForm(false)
    },
  })

  const rejectMut = useMutation({
    mutationFn: () => api.threatHunting.rejectGeneration(pkgId, approvalNotes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['th-generation', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-package', pkgId] })
      qc.invalidateQueries({ queryKey: ['th-packages'] })
    },
  })

  if (isLoading) {
    return <div className="text-sm text-gray-500 text-center py-8">Loading...</div>
  }

  const status = genRecord?.generation_status

  // No generation yet — show start button
  if (!genRecord || status === 'error') {
    return (
      <div className="space-y-4">
        {status === 'error' && (
          <div className="rounded-lg border border-red-800/40 bg-red-900/10 p-3 text-xs text-red-400">
            <p className="font-medium mb-1">Generation failed</p>
            {genRecord?.generation_errors?.map((e: string, i: number) => (
              <p key={i}>• {e}</p>
            ))}
          </div>
        )}
        <div className="card text-center py-10 space-y-4">
          <Brain className="w-10 h-10 text-gray-600 mx-auto" />
          <div>
            <p className="text-sm font-medium text-gray-200">Generate Hunting Package</p>
            <p className="text-xs text-gray-500 mt-1">
              The LLM agent pipeline will analyze all evidence items and produce:
              threat context, hunting hypotheses, leads, TTP analysis, and SIEM query drafts.
            </p>
          </div>
          {isResearcher ? (
            <button
              className="btn-primary flex items-center gap-2 mx-auto"
              disabled={startMut.isPending}
              onClick={() => startMut.mutate()}
            >
              {startMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {startMut.isPending ? 'Starting...' : 'Generate'}
            </button>
          ) : (
            <p className="text-xs text-gray-600">Requires threat-researcher or admin role.</p>
          )}
        </div>
      </div>
    )
  }

  // Running — show progress
  if (status === 'running') {
    const currentStep = genRecord?.current_step || 'initializing'
    return (
      <div className="card space-y-4">
        <div className="flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
          <div>
            <p className="text-sm font-medium text-gray-200">Generating hunt package...</p>
            <p className="text-xs text-gray-500">Current step: <span className="text-blue-400">{currentStep.replace(/_/g, ' ')}</span></p>
          </div>
        </div>
        <div className="space-y-1.5">
          {[
            'intake_classifier',
            'threat_context_builder',
            'hypothesis_generator',
            'hunting_lead_planner',
            'ttp_analyst',
            'query_drafting_agent',
          ].map((step) => {
            const completed = genRecord?.completed_steps?.includes(step)
            const active = genRecord?.current_step === step
            return (
              <div key={step} className={clsx('flex items-center gap-2 text-xs', completed ? 'text-green-400' : active ? 'text-blue-400' : 'text-gray-600')}>
                {completed ? <CheckCircle className="w-3.5 h-3.5" /> : active ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <div className="w-3.5 h-3.5 rounded-full border border-gray-700" />}
                {step.replace(/_/g, ' ')}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  // Awaiting approval — show full draft review
  if (status === 'awaiting_approval') {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <p className="text-sm font-semibold text-amber-400">Awaiting Operator Review</p>
          </div>
          {isResearcher && (
            <div className="flex gap-2">
              <button
                className="btn-ghost text-xs text-red-400 hover:text-red-300"
                disabled={rejectMut.isPending}
                onClick={() => rejectMut.mutate()}
              >
                {rejectMut.isPending ? 'Rejecting...' : 'Reject'}
              </button>
              <button
                className="btn-primary text-xs"
                onClick={() => setShowApproveForm(!showApproveForm)}
              >
                Approve
              </button>
            </div>
          )}
        </div>

        {showApproveForm && isResearcher && (
          <div className="border border-green-800/40 bg-green-900/10 rounded-lg p-3 space-y-2">
            <p className="text-xs text-gray-400">Approval notes (optional):</p>
            <textarea
              className="input w-full h-16 resize-none text-xs"
              placeholder="Add notes about this approval..."
              value={approvalNotes}
              onChange={(e) => setApprovalNotes(e.target.value)}
            />
            <div className="flex gap-2 justify-end">
              <button className="btn-ghost text-xs" onClick={() => setShowApproveForm(false)}>Cancel</button>
              <button
                className="btn-primary text-xs"
                disabled={approveMut.isPending}
                onClick={() => approveMut.mutate()}
              >
                {approveMut.isPending ? 'Approving...' : 'Confirm Approval'}
              </button>
            </div>
          </div>
        )}

        <HuntingPackageDraft record={genRecord} pkgId={pkgId} />
      </div>
    )
  }

  // Approved / completed — read-only view
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <CheckCircle className="w-4 h-4 text-green-400" />
        <p className="text-sm font-semibold text-green-400">Hunt Package Approved</p>
      </div>
      <HuntingPackageDraft record={genRecord} pkgId={pkgId} readOnly />
    </div>
  )
}

// ── Draft review component ────────────────────────────────────────────────────

function HuntingPackageDraft({
  record,
  pkgId,
  readOnly: _readOnly = false,
}: {
  record: THGenerationRecord
  pkgId: string
  readOnly?: boolean
}) {
  return (
    <div className="space-y-5">
      {/* Threat Context */}
      {record.threat_context && <ThreatContextCard ctx={record.threat_context} />}

      {/* Deep Retrohunt Lead */}
      {record.deep_retrohunt && (
        <CollapsibleSection
          title={`Deep Retrohunt Lead — ${record.deep_retrohunt.total_ioc_count} IOCs`}
          icon={Radar}
          defaultOpen
        >
          <RetrohuntPanel retrohunt={record.deep_retrohunt} pkgId={pkgId} />
        </CollapsibleSection>
      )}

      {/* Hypotheses */}
      {record.hypotheses && record.hypotheses.length > 0 && (
        <CollapsibleSection title={`Hypotheses (${record.hypotheses.length})`} icon={Brain} defaultOpen>
          <div className="space-y-3">
            {record.hypotheses.map((h: THHypothesis) => (
              <div key={h.id} className="border border-gray-700 rounded-lg p-3 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-brand-400 font-mono">{h.id}</span>
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded', h.relevance === 'high' ? 'bg-red-900/30 text-red-400' : h.relevance === 'medium' ? 'bg-amber-900/30 text-amber-400' : 'bg-gray-800 text-gray-500')}>
                    {h.relevance}
                  </span>
                </div>
                <p className="text-sm font-medium text-gray-200">{h.title}</p>
                <p className="text-xs text-gray-400">{h.description}</p>
                {h.justification && <p className="text-xs text-gray-500 italic">{h.justification}</p>}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Hunting Leads */}
      {record.hunting_leads && record.hunting_leads.length > 0 && (
        <CollapsibleSection title={`Hunting Leads (${record.hunting_leads.length})`} icon={Target}>
          <div className="space-y-3">
            {record.hunting_leads.map((lead: THHuntingLead) => (
              <div key={lead.id} className="border border-gray-700 rounded-lg p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-brand-400 font-mono">{lead.id}</span>
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded', lead.priority === 'high' ? 'bg-red-900/30 text-red-400' : lead.priority === 'medium' ? 'bg-amber-900/30 text-amber-400' : 'bg-gray-800 text-gray-500')}>
                    {lead.priority}
                  </span>
                </div>
                <p className="text-sm font-medium text-gray-200">{lead.title}</p>
                <p className="text-xs text-gray-400">{lead.description}</p>
                {lead.tasks && lead.tasks.length > 0 && (
                  <div className="pl-3 border-l border-gray-700 space-y-1.5 mt-2">
                    {lead.tasks.map((task: THHuntTask) => (
                      <div key={task.id}>
                        <p className="text-xs text-gray-300 font-medium">{task.id}: {task.title}</p>
                        <p className="text-[10px] text-gray-500">{task.description}</p>
                        {task.query_hint && <p className="text-[10px] text-gray-600 font-mono">Hint: {task.query_hint}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* TTP Analysis */}
      {record.ttp_analysis && (
        <CollapsibleSection title="Behavioral TTP Analysis" icon={Crosshair}>
          <div className="space-y-3">
            {record.ttp_analysis.summary && (
              <p className="text-xs text-gray-300">{record.ttp_analysis.summary}</p>
            )}
            {record.ttp_analysis.techniques?.map((t) => (
              <div key={t.technique_id} className="border border-gray-700 rounded p-2.5 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-brand-400">{t.technique_id}</span>
                  <span className="text-[10px] text-gray-500">{t.tactic}</span>
                </div>
                <p className="text-xs font-medium text-gray-200">{t.technique_name}</p>
                <p className="text-[10px] text-gray-500">{t.description}</p>
              </div>
            ))}
            {record.ttp_analysis.detection_opportunities?.length > 0 && (
              <div>
                <p className="text-xs font-medium text-gray-400 mb-1">Detection Opportunities:</p>
                <ul className="space-y-0.5">
                  {record.ttp_analysis.detection_opportunities.map((opp, i) => (
                    <li key={i} className="text-xs text-gray-500 flex gap-1.5"><span className="text-brand-600">•</span>{opp}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Query Drafts */}
      {record.query_drafts && record.query_drafts.length > 0 && (
        <CollapsibleSection title={`Query Drafts (${record.query_drafts.length})`} icon={Code2}>
          <div className="space-y-3">
            {record.query_drafts.map((q: THQueryDraft) => (
              <div key={q.id} className="border border-gray-700 rounded-lg p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono uppercase">{q.language}</span>
                  <p className="text-xs font-medium text-gray-200">{q.title}</p>
                </div>
                {q.description && <p className="text-[10px] text-gray-500">{q.description}</p>}
                <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-[10px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">{q.query}</pre>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Errors */}
      {record.generation_errors && record.generation_errors.length > 0 && (
        <div className="rounded-lg border border-amber-800/40 bg-amber-900/10 p-3 space-y-1">
          <p className="text-xs font-medium text-amber-400">Generation warnings:</p>
          {record.generation_errors.map((e: string, i: number) => (
            <p key={i} className="text-[10px] text-amber-500">• {e}</p>
          ))}
        </div>
      )}
    </div>
  )
}

function ThreatContextCard({ ctx }: { ctx: Record<string, unknown> }) {
  if (ctx.parse_error) {
    return (
      <div className="card space-y-2">
        <p className="text-sm font-semibold text-gray-200">Threat Context</p>
        <p className="text-xs text-gray-500 whitespace-pre-wrap">{String(ctx.raw_response || '')}</p>
      </div>
    )
  }
  // Normalise unknown fields to strings for safe JSX rendering
  const summary      = typeof ctx.summary      === 'string' ? ctx.summary      : ''
  const threatActor  = typeof ctx.threat_actor  === 'string' ? ctx.threat_actor  : ''
  const campaignName = typeof ctx.campaign_name === 'string' ? ctx.campaign_name : ''
  const confidence   = typeof ctx.confidence   === 'string' ? ctx.confidence   : ''
  return (
    <div className="card space-y-3">
      <p className="text-sm font-semibold text-gray-200">Threat Context</p>
      {summary      && <p className="text-xs text-gray-300">{summary}</p>}
      <div className="grid grid-cols-2 gap-2 text-xs">
        {threatActor  && <div><span className="text-gray-500">Actor: </span><span className="text-gray-300">{threatActor}</span></div>}
        {campaignName && <div><span className="text-gray-500">Campaign: </span><span className="text-gray-300">{campaignName}</span></div>}
        {confidence   && <div><span className="text-gray-500">Confidence: </span><span className={clsx(confidence === 'high' ? 'text-green-400' : confidence === 'medium' ? 'text-amber-400' : 'text-gray-400')}>{confidence}</span></div>}
      </div>
      {Array.isArray(ctx.key_observations) && ctx.key_observations.length > 0 && (
        <div>
          <p className="text-[10px] text-gray-500 font-medium mb-1">Key observations:</p>
          <ul className="space-y-0.5">
            {(ctx.key_observations as string[]).map((obs, i) => (
              <li key={i} className="text-[10px] text-gray-400 flex gap-1.5"><span className="text-brand-600">•</span>{obs}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function CollapsibleSection({
  title,
  icon: Icon,
  defaultOpen = false,
  children,
}: {
  title: string
  icon: React.ElementType
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800/40 hover:bg-gray-800/70 transition-colors"
        onClick={() => setOpen(!open)}
      >
        <Icon className="w-4 h-4 text-brand-400 shrink-0" />
        <span className="text-sm font-medium text-gray-200 flex-1 text-left">{title}</span>
        {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  )
}
