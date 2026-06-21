/**
 * MermaidVisualizer — lazy-loaded Mermaid flowchart for the agent pipeline.
 * Loaded only when the user selects "Mermaid" visualization style.
 */

import { useEffect, useRef, useState } from 'react'
import { type THGenerationRecord } from '../../api/client'

const STEP_LABELS: Record<string, string> = {
  intake_classifier: 'Intake Classifier',
  threat_context_builder: 'Threat Context Builder',
  deep_retrohunt_planner: 'Deep Retrohunt Planner',
  hypothesis_generator: 'Hypothesis Generator',
  hunting_lead_planner: 'Hunting Lead Planner',
  ttp_analyst: 'TTP Analyst',
  query_drafting_agent: 'Query Drafting Agent',
}

function buildMermaidDiagram(genRecord: THGenerationRecord): string {
  const completed = new Set(genRecord.completed_steps ?? [])
  const active = genRecord.current_step ?? ''

  const nodeStyle = (id: string): string => {
    if (completed.has(id)) return `style ${id} fill:#14532d,stroke:#22c55e,color:#d1fae5`
    if (active === id) return `style ${id} fill:#1e3a5f,stroke:#3b82f6,color:#bfdbfe`
    return `style ${id} fill:#1f2937,stroke:#374151,color:#6b7280`
  }

  const lines: string[] = [
    'flowchart TD',
    `  intake_classifier["${STEP_LABELS.intake_classifier}"]`,
    `  threat_context_builder["${STEP_LABELS.threat_context_builder}"]`,
    `  deep_retrohunt_planner["${STEP_LABELS.deep_retrohunt_planner}"]`,
    `  hypothesis_generator["${STEP_LABELS.hypothesis_generator}"]`,
    `  hunting_lead_planner["${STEP_LABELS.hunting_lead_planner}"]`,
    `  ttp_analyst["${STEP_LABELS.ttp_analyst}"]`,
    `  query_drafting_agent["${STEP_LABELS.query_drafting_agent}"]`,
    '',
    '  intake_classifier --> threat_context_builder',
    '  intake_classifier --> deep_retrohunt_planner',
    '  threat_context_builder --> hypothesis_generator',
    '  deep_retrohunt_planner --> hypothesis_generator',
    '  hypothesis_generator --> hunting_lead_planner',
    '  hunting_lead_planner --> ttp_analyst',
    '  ttp_analyst --> query_drafting_agent',
    '',
  ]

  for (const id of Object.keys(STEP_LABELS)) {
    lines.push(`  ${nodeStyle(id)}`)
  }

  return lines.join('\n')
}

export default function MermaidVisualizer({ genRecord }: { genRecord: THGenerationRecord }) {
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

        const diagram = buildMermaidDiagram(genRecord)
        const { svg } = await mermaid.render(`mermaid-pipeline-${Date.now()}`, diagram)

        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg
          setError(null)
        }
      } catch (err) {
        if (!cancelled) setError(String(err))
      }
    }

    render()
    return () => {
      cancelled = true
    }
    // Re-render whenever the active step or completed set changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [genRecord.current_step, genRecord.completed_steps?.length])

  if (error) {
    return (
      <div className="rounded border border-red-800/30 bg-red-900/10 p-3 text-xs text-red-400">
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
