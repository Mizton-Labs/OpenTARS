/**
 * MermaidVisualizer — lazy-loaded Mermaid flowchart for the agent pipeline.
 * Loaded only when the user selects "Mermaid" visualization style.
 *
 * issue-006-C: adds Threat Intel source nodes at the top of the diagram
 * (above intake_classifier), sourced from step_logs[intake_classifier].intake_sources.
 *
 * Current additions:
 *   - Part 1a: evidence nodes use stadium shape ([...]) and teal classDef
 *   - Part 1b: showSubtasks prop — renders subtask child nodes per step
 *   - Part 1c: active node pulse animation injected into SVG after render
 */

import { useEffect, useRef, useState } from 'react'
import { type THGenerationRecord } from '../../api/client'

const STEP_LABELS: Record<string, string> = {
  // Pipeline
  intake_classifier: 'Intake Classifier',
  threat_context_builder: 'Threat Context Builder',
  deep_retrohunt_planner: 'Deep Retrohunt Planner',
  hypothesis_generator: 'Hypothesis Generator',
  hunting_lead_planner: 'Hunting Lead Planner',
  ttp_analyst: 'TTP Analyst',
  query_drafting_agent: 'Query Drafting Agent',
  // SIEM execution
  siem_connect: 'SIEM Connect',
  siem_submit: 'SIEM Submit',
  siem_poll: 'SIEM Poll',
  siem_fetch: 'SIEM Fetch',
  siem_interpret: 'SIEM Interpret',
  // Report generation
  report_assemble: 'Assemble Report',
  report_exec_summary: 'Exec Summary',
  report_findings: 'Findings',
  report_render: 'Render Report',
}

function buildMermaidDiagram(genRecord: THGenerationRecord, showSubtasks = false): string {
  const completed = new Set(genRecord.completed_steps ?? [])
  const active = genRecord.current_step ?? ''

  const nodeStyle = (id: string): string => {
    if (completed.has(id)) return `style ${id} fill:#14532d,stroke:#22c55e,color:#d1fae5`
    if (active === id) return `style ${id} fill:#1e3a5f,stroke:#3b82f6,color:#bfdbfe`
    return `style ${id} fill:#1f2937,stroke:#374151,color:#6b7280`
  }

  // issue-006-C: extract intake sources from step_logs
  const intakeLog = (genRecord.step_logs ?? []).find((l) => l.step === 'intake_classifier')
  const intakeSources = intakeLog?.intake_sources ?? []

  const lines: string[] = ['flowchart TD']

  // Source nodes — stadium shape ([...]) for Part 1a
  if (intakeSources.length > 0) {
    for (let i = 0; i < intakeSources.length; i++) {
      const src = intakeSources[i]
      const safeLabel = (src.label || src.item_type || `source_${i}`)
        .replace(/"/g, "'")
        .slice(0, 30)
      const nodeId = `src_${i}`
      // Stadium shape uses ([ ... ])
      lines.push(`  ${nodeId}(["${safeLabel}\\n(${src.item_type})"])`)
    }
    lines.push('')
  }

  // Pipeline nodes
  lines.push(
    `  intake_classifier["${STEP_LABELS.intake_classifier}"]`,
    `  threat_context_builder["${STEP_LABELS.threat_context_builder}"]`,
    `  deep_retrohunt_planner["${STEP_LABELS.deep_retrohunt_planner}"]`,
    `  hypothesis_generator["${STEP_LABELS.hypothesis_generator}"]`,
    `  hunting_lead_planner["${STEP_LABELS.hunting_lead_planner}"]`,
    `  ttp_analyst["${STEP_LABELS.ttp_analyst}"]`,
    `  query_drafting_agent["${STEP_LABELS.query_drafting_agent}"]`,
    '',
  )

  // Approval gate
  lines.push('  approval_gate{{"Approval Gate"}}', '')

  // SIEM execution nodes (issue-local-009)
  lines.push(
    `  siem_connect["${STEP_LABELS.siem_connect}"]`,
    `  siem_submit["${STEP_LABELS.siem_submit}"]`,
    `  siem_poll["${STEP_LABELS.siem_poll}"]`,
    `  siem_fetch["${STEP_LABELS.siem_fetch}"]`,
    `  siem_interpret["${STEP_LABELS.siem_interpret}"]`,
    '',
  )

  // Report generation nodes (issue-local-009)
  lines.push(
    `  report_assemble["${STEP_LABELS.report_assemble}"]`,
    `  report_exec_summary["${STEP_LABELS.report_exec_summary}"]`,
    `  report_findings["${STEP_LABELS.report_findings}"]`,
    `  report_render["${STEP_LABELS.report_render}"]`,
    '',
  )

  // Subtask nodes (Part 1b) — subroutine shape {[ ... ]}
  if (showSubtasks) {
    for (const stepLog of (genRecord.step_logs ?? [])) {
      const toolsUsed = stepLog.tools_used ?? []
      for (let i = 0; i < toolsUsed.length; i++) {
        const subId = `sub_${stepLog.step}_${i}`
        const toolName = toolsUsed[i].replace(/"/g, "'")
        lines.push(`  ${subId}[["${toolName}"]]`)
      }
    }
    lines.push('')
  }

  // Source → intake_classifier edges
  for (let i = 0; i < intakeSources.length; i++) {
    lines.push(`  src_${i} --> intake_classifier`)
  }

  // Pipeline edges
  lines.push(
    '  intake_classifier --> threat_context_builder',
    '  intake_classifier --> deep_retrohunt_planner',
    '  threat_context_builder --> hypothesis_generator',
    '  deep_retrohunt_planner --> hypothesis_generator',
    '  hypothesis_generator --> hunting_lead_planner',
    '  hunting_lead_planner --> ttp_analyst',
    '  ttp_analyst --> query_drafting_agent',
    '  query_drafting_agent --> approval_gate',
    '',
  )

  // Execution edges (issue-local-009)
  lines.push(
    '  approval_gate --> siem_connect',
    '  siem_connect --> siem_submit',
    '  siem_submit --> siem_poll',
    '  siem_poll --> siem_fetch',
    '  siem_fetch --> siem_interpret',
    '  siem_interpret --> report_assemble',
    '',
  )

  // Report edges (issue-local-009)
  lines.push(
    '  report_assemble --> report_exec_summary',
    '  report_exec_summary --> report_findings',
    '  report_findings --> report_render',
    '',
  )

  // Subtask edges (Part 1b)
  if (showSubtasks) {
    for (const stepLog of (genRecord.step_logs ?? [])) {
      const toolsUsed = stepLog.tools_used ?? []
      for (let i = 0; i < toolsUsed.length; i++) {
        const subId = `sub_${stepLog.step}_${i}`
        lines.push(`  ${stepLog.step} --> ${subId}`)
      }
    }
    lines.push('')
  }

  // Style pipeline nodes
  for (const id of Object.keys(STEP_LABELS)) {
    lines.push(`  ${nodeStyle(id)}`)
  }

  // Approval gate style
  lines.push('  style approval_gate fill:#78350f,stroke:#f59e0b,color:#fef3c7')

  // Part 1a: classDef for evidence nodes (teal category)
  lines.push('  classDef evidence fill:#0e4f4f,stroke:#14b8a6,color:#ccfbf1')
  // classDef for subtask nodes (violet/purple)
  lines.push('  classDef subtask fill:#2d1b69,stroke:#7c3aed,color:#c4b5fd')

  // Style source nodes — color varies by sub_status (issue-local-011 Part 7c)
  for (let i = 0; i < intakeSources.length; i++) {
    const subStatus = intakeSources[i].sub_status
    let fill: string
    let stroke: string
    if (subStatus === 'ok') {
      fill = '#14532d'; stroke = '#22c55e'
    } else if (subStatus === 'error') {
      fill = '#7f1d1d'; stroke = '#ef4444'
    } else {
      // partial, pending, or undefined → teal (Part 1a: distinct from amber agent style)
      fill = '#0e4f4f'; stroke = '#14b8a6'
    }
    lines.push(`  style src_${i} fill:${fill},stroke:${stroke},color:#ccfbf1`)
    // Also assign to classDef evidence (additional styling via class)
    lines.push(`  class src_${i} evidence`)
  }

  // Assign subtask class
  if (showSubtasks) {
    for (const stepLog of (genRecord.step_logs ?? [])) {
      const toolsUsed = stepLog.tools_used ?? []
      for (let i = 0; i < toolsUsed.length; i++) {
        const subId = `sub_${stepLog.step}_${i}`
        lines.push(`  class ${subId} subtask`)
      }
    }
  }

  return lines.join('\n')
}

export default function MermaidVisualizer({
  genRecord,
  showSubtasks = false,
}: {
  genRecord: THGenerationRecord
  showSubtasks?: boolean
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function render() {
      try {
        const mermaid = (await import('mermaid')).default
        mermaid.initialize({
          startOnLoad: false,
          theme: 'dark',
          themeVariables: {
            background: '#111827',
            primaryColor: '#1f2937',
            primaryTextColor: '#e5e7eb',
            lineColor: '#4b5563',
          },
        })

        const diagram = buildMermaidDiagram(genRecord, showSubtasks)
        const { svg } = await mermaid.render(`mermaid-pipeline-${Date.now()}`, diagram)

        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg
          setError(null)

          // Part 1c: inject active node pulse animation into the SVG
          const active = genRecord.current_step
          const container = containerRef.current
          const styleEl = document.createElement('style')
          styleEl.textContent = [
            '@keyframes nodeGlow {',
            '  0%,100% { filter: drop-shadow(0 0 6px #3b82f6); }',
            '  50%      { filter: drop-shadow(0 0 14px #3b82f6); }',
            '}',
            '.active-node rect { animation: nodeGlow 1.5s ease-in-out infinite; }',
          ].join('\n')
          container.querySelector('svg')?.appendChild(styleEl)

          if (active) {
            const activeEl = container.querySelector(`#${CSS.escape(active)}`)
            activeEl?.classList.add('active-node')
          }
        }
      } catch (err) {
        if (!cancelled) setError(String(err))
      }
    }

    render()
    return () => {
      cancelled = true
    }
    // Re-render whenever the active step, completed set, or showSubtasks changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [genRecord.current_step, genRecord.completed_steps?.length, showSubtasks])

  if (error) {
    return (
      <div className="rounded border border-red-800/30 bg-red-900/10 p-3 text-sm text-red-400">
        Mermaid render error: {error}
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className="w-full overflow-x-auto rounded-lg border border-gray-700 bg-gray-900/50 p-3 min-h-[200px]"
    />
  )
}
