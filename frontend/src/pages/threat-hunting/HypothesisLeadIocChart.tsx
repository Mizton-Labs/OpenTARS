/**
 * HypothesisLeadIocChart — issue-local-022 item 2.
 *
 * A relationship-overview graph shown above the Analysis tab's flat
 * collapsible lists (Threat Context / Hypotheses / Hunting Leads / ...):
 * three tiers, left to right — Hypotheses -> Hunting Leads -> IOCs — so an
 * analyst can see at a glance whether a hypothesis has one or several
 * hunting leads, and which IOCs are/aren't cited by any hypothesis
 * ("coverage"). A "Deep view" toggle overlays this run's Threat Intel
 * analysis (threat actors / malware families / campaigns / MITRE
 * techniques) as a fourth tier.
 *
 * Deliberately a NEW component, not a mode on WorkflowVisualizer/
 * ReactFlowVisualizer — those render the fixed LangGraph pipeline-status
 * graph; this renders a DATA-relationship graph with a different node set
 * entirely. It reuses the same library (@xyflow/react, already a project
 * dependency) and the same dark-theme node/edge color conventions as
 * ReactFlowVisualizer.tsx for visual consistency.
 *
 * Coverage definition (confirmed design decision): an IOC counts as
 * "covered" iff it is cited in at least one NON-discarded hypothesis's
 * ioc_basis. Sanitized-out (action='remove') IOCs are excluded from the
 * covered/uncovered coverage stat entirely and rendered as their own
 * "removed" category instead of being judged uncovered.
 *
 * Deep View edges are necessarily coarse (confirmed design decision): the
 * Threat Intel analysis is run/package-level, with no field linking an
 * individual actor/malware family/campaign to an individual IOC or
 * hypothesis. Those entities connect to a single small "This run" hub node
 * via dashed edges, visually distinct from the precise Hyp->Lead/Hyp->IOC
 * edges. The one genuinely precise Deep View edge is `correlated_iocs`
 * (this run's IOC seen in another hunt package) — drawn directly from the
 * matching IOC node.
 */

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ReactFlow, Background, Controls, type Node, type Edge } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { clsx } from 'clsx'
import {
  api,
  type THGenerationRecord,
  type THExtractedIOC,
  type THHypothesis,
  type THHuntingLead,
} from '../../api/client'

const TIER_X = { hyp: 0, lead: 320, ioc: 680, intel: 1040 }
const ROW_H = 60

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

type Palette = { bg: string; border: string; color: string }

const PALETTE = {
  high: { bg: '#7f1d1d', border: '#ef4444', color: '#fee2e2' },
  medium: { bg: '#78350f', border: '#f59e0b', color: '#fef3c7' },
  low: { bg: '#1f2937', border: '#374151', color: '#9ca3af' },
  covered: { bg: '#14532d', border: '#22c55e', color: '#d1fae5' },
  uncovered: { bg: '#78350f', border: '#f59e0b', color: '#fef3c7' },
  removed: { bg: '#3f1414', border: '#7f1d1d', color: '#fca5a5' },
  actor: { bg: '#7f1d1d', border: '#ef4444', color: '#fee2e2' },
  malware: { bg: '#1f2937', border: '#4b5563', color: '#d1d5db' },
  campaign: { bg: '#312e81', border: '#818cf8', color: '#e0e7ff' },
  ttp: { bg: '#2d1b69', border: '#7c3aed', color: '#c4b5fd' },
  hub: { bg: '#134e4a', border: '#2dd4bf', color: '#ccfbf1' },
  muted: { bg: '#111827', border: '#374151', color: '#4b5563' },
} satisfies Record<string, Palette>

function levelPalette(level: 'high' | 'medium' | 'low' | undefined): Palette {
  return PALETTE[level ?? 'low'] ?? PALETTE.low
}

function nodeStyle(p: Palette, opts: { dashed?: boolean; muted?: boolean } = {}) {
  const pal = opts.muted ? PALETTE.muted : p
  return {
    background: pal.bg,
    border: `1px ${opts.dashed ? 'dashed' : 'solid'} ${pal.border}`,
    color: pal.color,
    borderRadius: '8px',
    padding: '6px 10px',
    fontSize: '11px',
    fontWeight: 500,
    minWidth: '150px',
    maxWidth: '220px',
    textAlign: 'center' as const,
    whiteSpace: 'pre-line' as const,
  }
}

const hypNodeId = (h: THHypothesis) => `hyp:${h.id}`
const leadNodeId = (l: THHuntingLead) => `lead:${l.id}`
const iocNodeId = (iocValue: string) => `ioc:${iocValue}`
const HUB_NODE_ID = 'intel-hub'

export default function HypothesisLeadIocChart({
  record,
  iocs,
  pkgId,
  runId,
}: {
  record: THGenerationRecord
  iocs: THExtractedIOC[]
  pkgId: string
  runId?: string
}) {
  const [deepView, setDeepView] = useState(false)

  const hypotheses = useMemo(() => record.hypotheses ?? [], [record.hypotheses])
  const leads = useMemo(() => record.hunting_leads ?? [], [record.hunting_leads])
  const techniques = useMemo(() => record.ttp_analysis?.techniques ?? [], [record.ttp_analysis])

  // Same query key ThreatIntelTab.tsx uses — shares its cache, so toggling
  // Deep View after visiting that tab is instant, and this never fires the
  // fetch at all while the toggle is off.
  const { data: intel } = useQuery({
    queryKey: ['th-threat-intel', pkgId, runId],
    queryFn: () => (runId ? api.threatHunting.getRunThreatIntel(pkgId, runId).catch(() => null) : Promise.resolve(null)),
    enabled: deepView && !!runId,
  })

  const keptIocs = useMemo(() => iocs.filter((i) => i.action !== 'remove'), [iocs])
  const removedIocs = useMemo(() => iocs.filter((i) => i.action === 'remove'), [iocs])

  // Coverage: cited by >=1 NON-discarded hypothesis's ioc_basis. Removed
  // IOCs are excluded from this stat entirely (their own category below).
  const coveredIocValues = useMemo(() => {
    const set = new Set<string>()
    for (const h of hypotheses) {
      if (h.discarded) continue
      for (const v of h.ioc_basis ?? []) set.add(v)
    }
    return set
  }, [hypotheses])

  const uncoveredCount = useMemo(
    () => keptIocs.filter((i) => !coveredIocValues.has(i.ioc)).length,
    [keptIocs, coveredIocValues],
  )

  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = []
    const edges: Edge[] = []

    hypotheses.forEach((h, i) => {
      nodes.push({
        id: hypNodeId(h),
        position: { x: TIER_X.hyp, y: i * ROW_H },
        data: { label: `${h.id}\n${truncate(h.title, 36)}${h.discarded ? '\n(discarded)' : ''}` },
        style: nodeStyle(levelPalette(h.relevance), { dashed: !!h.discarded, muted: !!h.discarded }),
      })
    })

    leads.forEach((l, i) => {
      nodes.push({
        id: leadNodeId(l),
        position: { x: TIER_X.lead, y: i * ROW_H },
        data: { label: `${l.id}\n${truncate(l.title, 36)}${l.discarded ? '\n(discarded)' : ''}` },
        style: nodeStyle(levelPalette(l.priority), { dashed: !!l.discarded, muted: !!l.discarded }),
      })
      const hyp = hypotheses.find((h) => h.id === l.hypothesis_id)
      if (hyp) {
        edges.push({
          id: `e-hl-${l.id}`,
          source: hypNodeId(hyp),
          target: leadNodeId(l),
          style: { stroke: '#4b5563', strokeWidth: 1.5 },
        })
      }
    })

    // IOC tier: covered/uncovered (from this run's kept IOCs), then removed,
    // then any ioc_basis value not present in the run's IOC list at all
    // (defensive — keeps every citation visible even if data is unusual).
    let row = 0
    const iocRow = new Map<string, number>()
    for (const ioc of keptIocs) {
      const covered = coveredIocValues.has(ioc.ioc)
      nodes.push({
        id: iocNodeId(ioc.ioc),
        position: { x: TIER_X.ioc, y: row * ROW_H },
        data: { label: truncate(ioc.ioc, 28) },
        style: nodeStyle(covered ? PALETTE.covered : PALETTE.uncovered, { dashed: !covered }),
      })
      iocRow.set(ioc.ioc, row)
      row += 1
    }
    for (const ioc of removedIocs) {
      nodes.push({
        id: iocNodeId(ioc.ioc),
        position: { x: TIER_X.ioc, y: row * ROW_H },
        data: { label: `${truncate(ioc.ioc, 28)}\n(removed)` },
        style: nodeStyle(PALETTE.removed, { dashed: true }),
      })
      iocRow.set(ioc.ioc, row)
      row += 1
    }
    const knownIocValues = new Set(iocs.map((i) => i.ioc))
    const extraCited = new Set<string>()
    for (const h of hypotheses) {
      for (const v of h.ioc_basis ?? []) {
        if (!knownIocValues.has(v)) extraCited.add(v)
      }
    }
    for (const v of extraCited) {
      nodes.push({
        id: iocNodeId(v),
        position: { x: TIER_X.ioc, y: row * ROW_H },
        data: { label: truncate(v, 28) },
        style: nodeStyle(PALETTE.covered),
      })
      iocRow.set(v, row)
      row += 1
    }

    // Hypothesis -> IOC edges (ioc_basis is on the hypothesis, so this
    // skips the lead tier spatially) — a lighter, dashed line so the
    // "fan-out to leads" structure (the main tree) stays visually primary.
    hypotheses.forEach((h) => {
      for (const v of h.ioc_basis ?? []) {
        if (!iocRow.has(v)) continue
        edges.push({
          id: `e-hi-${h.id}-${v}`,
          source: hypNodeId(h),
          target: iocNodeId(v),
          style: { stroke: '#3b82f6', strokeWidth: 1, strokeDasharray: '4 2' },
        })
      }
    })

    if (deepView && intel) {
      const hasIntelContent =
        intel.threat_actors.length > 0 ||
        intel.malware_families.length > 0 ||
        intel.campaigns.length > 0 ||
        techniques.length > 0 ||
        intel.correlated_iocs.length > 0

      if (hasIntelContent) {
        nodes.push({
          id: HUB_NODE_ID,
          position: { x: TIER_X.intel - 180, y: (row * ROW_H) / 2 },
          data: { label: 'This run\n(Threat Intel)' },
          style: nodeStyle(PALETTE.hub),
        })

        let intelRow = 0
        const pushIntelNode = (id: string, label: string, palette: Palette) => {
          nodes.push({
            id,
            position: { x: TIER_X.intel, y: intelRow * ROW_H },
            data: { label: truncate(label, 28) },
            style: nodeStyle(palette),
          })
          edges.push({
            id: `e-hub-${id}`,
            source: HUB_NODE_ID,
            target: id,
            style: { stroke: '#2dd4bf', strokeWidth: 1, strokeDasharray: '3 3' },
          })
          intelRow += 1
        }

        intel.threat_actors.forEach((a, i) => pushIntelNode(`actor:${i}:${a.name}`, `👤 ${a.name}`, PALETTE.actor))
        intel.malware_families.forEach((m, i) => pushIntelNode(`malware:${i}:${m}`, `🦠 ${m}`, PALETTE.malware))
        intel.campaigns.forEach((c, i) => pushIntelNode(`campaign:${i}:${c.name}`, `🎯 ${c.name}`, PALETTE.campaign))
        techniques.forEach((t) =>
          pushIntelNode(`ttp:${t.technique_id}`, `${t.technique_id} ${t.technique_name}`, PALETTE.ttp),
        )

        // The one precise Deep View edge: correlated_iocs links a specific
        // IOC (already in Tier 3) to another hunt package that also saw it.
        intel.correlated_iocs.forEach((corr, i) => {
          if (!iocRow.has(corr.ioc)) return
          const corrId = `corr:${i}:${corr.ioc}`
          nodes.push({
            id: corrId,
            position: { x: TIER_X.intel, y: intelRow * ROW_H },
            data: { label: `↔ ${truncate(corr.hunt_name, 22)}` },
            style: nodeStyle(PALETTE.hub, { dashed: true }),
          })
          edges.push({
            id: `e-corr-${i}`,
            source: iocNodeId(corr.ioc),
            target: corrId,
            style: { stroke: '#2dd4bf', strokeWidth: 1.5 },
          })
          intelRow += 1
        })
      }
    }

    return { nodes, edges }
  }, [hypotheses, leads, iocs, keptIocs, removedIocs, coveredIocValues, deepView, intel, techniques])

  const graphHeight = Math.max(300, Math.max(hypotheses.length, leads.length, keptIocs.length + removedIocs.length) * ROW_H + 80)

  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <p className="text-sm font-semibold text-gray-200">Relationship Overview</p>
          <p className="text-[11px] text-gray-500 mt-0.5">
            {hypotheses.length} hypothes{hypotheses.length === 1 ? 'is' : 'es'} · {leads.length} hunting lead
            {leads.length === 1 ? '' : 's'} · {keptIocs.length} IOC{keptIocs.length === 1 ? '' : 's'}
            {uncoveredCount > 0 && (
              <span className="text-amber-400"> · {uncoveredCount} uncovered</span>
            )}
            {removedIocs.length > 0 && (
              <span className="text-red-400"> · {removedIocs.length} removed</span>
            )}
          </p>
        </div>
        <button
          className="text-sm text-gray-400 flex items-center gap-1.5 cursor-pointer select-none hover:text-gray-200 transition-colors"
          onClick={() => setDeepView((v) => !v)}
          title="Overlay this run's Threat Intel analysis (threat actors, malware families, campaigns, MITRE techniques)"
        >
          <span
            className={clsx(
              'inline-block w-3 h-3 border rounded-sm flex-shrink-0 transition-colors',
              deepView ? 'bg-brand-500 border-brand-400' : 'bg-transparent border-gray-600',
            )}
          />
          Deep view
        </button>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-gray-500">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: PALETTE.covered.border }} /> Covered IOC</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block border border-dashed" style={{ borderColor: PALETTE.uncovered.border }} /> Uncovered IOC</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: PALETTE.removed.border }} /> Removed IOC</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: PALETTE.high.border }} /> High relevance/priority</span>
        {deepView && (
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: PALETTE.hub.border }} /> Threat Intel (aggregate)</span>
        )}
      </div>

      {hypotheses.length === 0 && leads.length === 0 && keptIocs.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-6">Nothing to chart yet.</p>
      ) : (
        <div className="rounded-lg border border-gray-700 overflow-hidden" style={{ height: graphHeight }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            fitView
            proOptions={{ hideAttribution: true }}
            colorMode="dark"
          >
            <Background color="#374151" gap={16} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      )}
    </div>
  )
}
