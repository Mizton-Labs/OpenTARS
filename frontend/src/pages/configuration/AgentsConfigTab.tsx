/**
 * Agents Configuration Tab — issue-local-004 / issue-007
 *
 * Controls:
 *   1. Agentic Workflow Verbosity  (info | verbose | debug)
 *   2. Visualization Style         (timeline | mermaid | reactflow)
 *      — only meaningful / shown when verbosity is verbose or debug
 *   3. Agent Tools & Document Parsers  (per-tool enable/disable, issue-007)
 */

import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Activity, BarChart2, GitFork, Layers, Save, Loader2, Wrench, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type ToolCatalogEntry } from '../../api/client'

// ── Verbosity option definitions ──────────────────────────────────────────────

type VerbosityLevel = 'info' | 'verbose' | 'debug'
type VisualizationStyle = 'timeline' | 'mermaid' | 'reactflow'

const VERBOSITY_OPTIONS: { id: VerbosityLevel; label: string; description: string }[] = [
  {
    id: 'info',
    label: 'Info',
    description:
      'Shows the current processing step from the agents. Clean and only with the summary of activities done by the agents.',
  },
  {
    id: 'verbose',
    label: 'Verbose',
    description:
      'Dynamic view of how agents perform actions: data passed between agents, tools called, item counts, and per-step timing. Rendered as an animated pipeline in the selected visualization style.',
  },
  {
    id: 'debug',
    label: 'Debug',
    description:
      'Everything in Verbose plus a live log textbox at the bottom showing all backend pipeline log lines scoped to the current hunt run.',
  },
]

const VISUALIZATION_OPTIONS: {
  id: VisualizationStyle
  label: string
  description: string
  icon: React.ElementType
}[] = [
  {
    id: 'timeline',
    label: 'Timeline',
    description: 'Animated vertical step list with per-step status, timing, and item counts. No extra dependencies.',
    icon: Activity,
  },
  {
    id: 'mermaid',
    label: 'Mermaid Flowchart',
    description: 'Live Mermaid flowchart diagram of the agent graph that updates as steps complete.',
    icon: GitFork,
  },
  {
    id: 'reactflow',
    label: 'React Flow Graph',
    description: 'Interactive node/edge graph with live highlighting of active and completed agents.',
    icon: BarChart2,
  },
]

// ── Component ─────────────────────────────────────────────────────────────────

export default function AgentsConfigTab() {
  const qc = useQueryClient()

  const { data: verbosityData, isLoading: vLoading } = useQuery({
    queryKey: ['agent-verbosity'],
    queryFn: () => api.getAgentVerbosity(),
  })
  const { data: vizData, isLoading: vizLoading } = useQuery({
    queryKey: ['agent-visualization'],
    queryFn: () => api.getAgentVisualization(),
  })
  // issue-007: agent tools + document parsers
  const { data: toolsData, isLoading: toolsLoading } = useQuery({
    queryKey: ['agent-tools'],
    queryFn: () => api.getAgentTools(),
  })
  const { data: catalogData, isLoading: catalogLoading } = useQuery({
    queryKey: ['agent-tools-catalog'],
    queryFn: () => api.getAgentToolsCatalog(),
  })

  const [verbosity, setVerbosity] = useState<VerbosityLevel>('info')
  const [visualization, setVisualization] = useState<VisualizationStyle>('timeline')
  const [toolsEnabled, setToolsEnabled] = useState<Record<string, boolean>>({})
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (verbosityData?.agent_workflow_verbosity) {
      setVerbosity(verbosityData.agent_workflow_verbosity as VerbosityLevel)
    }
  }, [verbosityData])

  useEffect(() => {
    if (vizData?.agent_workflow_visualization) {
      setVisualization(vizData.agent_workflow_visualization as VisualizationStyle)
    }
  }, [vizData])

  useEffect(() => {
    if (toolsData?.agent_tools) {
      setToolsEnabled(toolsData.agent_tools)
    }
  }, [toolsData])

  const saveMut = useMutation({
    mutationFn: async () => {
      await api.setAgentVerbosity(verbosity)
      await api.setAgentVisualization(visualization)
      await api.setAgentTools(toolsEnabled)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-verbosity'] })
      qc.invalidateQueries({ queryKey: ['agent-visualization'] })
      qc.invalidateQueries({ queryKey: ['agent-tools'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const isLoading = vLoading || vizLoading || toolsLoading || catalogLoading

  // Compare local tools map against server value
  const toolsDirty = Object.keys(toolsEnabled).some(
    (k) => toolsEnabled[k] !== (toolsData?.agent_tools?.[k] ?? true),
  )
  const isDirty =
    verbosity !== (verbosityData?.agent_workflow_verbosity ?? 'info') ||
    visualization !== (vizData?.agent_workflow_visualization ?? 'timeline') ||
    toolsDirty

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-500 py-8">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading agent configuration…
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Header */}
      <div>
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Layers className="w-4 h-4 text-brand-400" />
          Agents Configuration
        </h3>
        <p className="text-xs text-gray-500 mt-1">
          Configure how the agentic workflow is displayed while the pipeline is running.
          Changes take effect on the next hunt generation run.
        </p>
      </div>

      {/* Verbosity */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
          Agentic Workflow Verbosity
        </p>
        <div className="space-y-2">
          {VERBOSITY_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              onClick={() => setVerbosity(opt.id)}
              className={clsx(
                'w-full text-left rounded-lg border px-4 py-3 transition-colors',
                verbosity === opt.id
                  ? 'border-brand-500 bg-brand-900/20'
                  : 'border-gray-700 hover:border-gray-500 bg-gray-800/30',
              )}
            >
              <div className="flex items-center gap-2">
                <div
                  className={clsx(
                    'w-3.5 h-3.5 rounded-full border-2 shrink-0',
                    verbosity === opt.id ? 'border-brand-400 bg-brand-400' : 'border-gray-600',
                  )}
                />
                <span
                  className={clsx(
                    'text-sm font-medium',
                    verbosity === opt.id ? 'text-brand-300' : 'text-gray-300',
                  )}
                >
                  {opt.label}
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1 pl-5">{opt.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Visualization style — only shown when verbose or debug */}
      {verbosity !== 'info' && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            Visualization Style
          </p>
          <p className="text-xs text-gray-500">
            Applies to Verbose and Debug modes. Sets how the live agent workflow is rendered in
            the Hunt Package Analysis tab while the pipeline is running.
          </p>
          <div className="space-y-2">
            {VISUALIZATION_OPTIONS.map((opt) => {
              const Icon = opt.icon
              return (
                <button
                  key={opt.id}
                  onClick={() => setVisualization(opt.id)}
                  className={clsx(
                    'w-full text-left rounded-lg border px-4 py-3 transition-colors',
                    visualization === opt.id
                      ? 'border-brand-500 bg-brand-900/20'
                      : 'border-gray-700 hover:border-gray-500 bg-gray-800/30',
                  )}
                >
                  <div className="flex items-center gap-2">
                    <div
                      className={clsx(
                        'w-3.5 h-3.5 rounded-full border-2 shrink-0',
                        visualization === opt.id
                          ? 'border-brand-400 bg-brand-400'
                          : 'border-gray-600',
                      )}
                    />
                    <Icon
                      className={clsx(
                        'w-3.5 h-3.5 shrink-0',
                        visualization === opt.id ? 'text-brand-400' : 'text-gray-500',
                      )}
                    />
                    <span
                      className={clsx(
                        'text-sm font-medium',
                        visualization === opt.id ? 'text-brand-300' : 'text-gray-300',
                      )}
                    >
                      {opt.label}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1 pl-[42px]">{opt.description}</p>
                </button>
              )
            })}
          </div>

          {/* Visualization notes */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/20 px-3 py-2 text-xs text-gray-500">
            <p className="font-medium text-gray-400 mb-1">Visualization notes</p>
            <ul className="space-y-0.5">
              <li>• <span className="text-gray-300">Timeline</span> — built-in, no extra bundle weight, works offline.</li>
              <li>• <span className="text-gray-300">Mermaid</span> — loaded on demand (~500 KB). Requires network on first use.</li>
              <li>• <span className="text-gray-300">React Flow</span> — loaded on demand (~200 KB). Interactive graph with zoom/pan.</li>
            </ul>
            <p className="mt-1.5 text-gray-600">
              For richer external visualizations consider{' '}
              <span className="font-mono text-gray-500">LangSmith</span> or{' '}
              <span className="font-mono text-gray-500">LangGraph Studio</span> which provide
              full trace replay, token accounting, and agent graph inspection.
            </p>
          </div>
        </div>
      )}

      {/* ── Agent Tools & Document Parsers (issue-007) ────────────────────── */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Wrench className="w-4 h-4 text-brand-400" />
          <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            Agent Tools &amp; Document Parsers
          </p>
        </div>
        <p className="text-xs text-gray-500">
          Enable or disable individual tools that agents can call during a hunt pipeline run.
          Disabled tools are hard-excluded — the LLM will not be offered them.
          Changes take effect on the next generation run.
        </p>

        {catalogLoading || toolsLoading ? (
          <div className="flex items-center gap-2 text-xs text-gray-500 py-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Loading tools…
          </div>
        ) : (
          <div className="space-y-2">
            {(catalogData?.catalog ?? []).map((tool: ToolCatalogEntry) => {
              const enabled = toolsEnabled[tool.name] ?? true
              const isUnavailable = !tool.available
              return (
                <div
                  key={tool.name}
                  className={clsx(
                    'rounded-lg border px-4 py-3 space-y-1.5 transition-colors',
                    isUnavailable
                      ? 'border-gray-800/40 bg-gray-900/20 opacity-60'
                      : enabled
                        ? 'border-gray-700 bg-gray-800/30'
                        : 'border-gray-800/40 bg-gray-900/20',
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={clsx(
                          'text-sm font-medium',
                          isUnavailable ? 'text-gray-600' : enabled ? 'text-gray-200' : 'text-gray-500',
                        )}>
                          {tool.label}
                        </span>
                        <span className={clsx(
                          'text-[9px] font-mono px-1.5 py-0.5 rounded border',
                          tool.category === 'document_parser'
                            ? 'bg-amber-900/20 text-amber-400 border-amber-800/30'
                            : 'bg-purple-900/20 text-purple-400 border-purple-800/30',
                        )}>
                          {tool.category === 'document_parser' ? 'parser' : 'agent tool'}
                        </span>
                        {isUnavailable && (
                          <span className="text-[9px] text-gray-600 font-mono">
                            not installed
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">
                        {tool.description}
                      </p>
                      <p className="text-[10px] text-gray-600 mt-0.5 italic">
                        {tool.used_by_description}
                      </p>
                    </div>
                    {/* Toggle pill */}
                    <button
                      type="button"
                      role="switch"
                      aria-checked={enabled}
                      disabled={isUnavailable}
                      onClick={() =>
                        setToolsEnabled((prev) => ({ ...prev, [tool.name]: !enabled }))
                      }
                      className={clsx(
                        'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 transition-colors duration-200',
                        isUnavailable
                          ? 'cursor-not-allowed border-gray-700 bg-gray-800'
                          : enabled
                            ? 'border-green-500 bg-green-600'
                            : 'border-gray-600 bg-gray-700',
                      )}
                    >
                      <span
                        className={clsx(
                          'pointer-events-none inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform duration-200',
                          enabled ? 'translate-x-3.5' : 'translate-x-0.5',
                          'mt-[1px]',
                        )}
                      />
                    </button>
                  </div>

                  {/* Implication warning shown when tool is disabled */}
                  {!enabled && !isUnavailable && (
                    <div className="flex items-start gap-1.5 rounded border border-amber-800/30 bg-amber-900/10 px-2 py-1.5">
                      <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
                      <p className="text-[10px] text-amber-300/80 leading-relaxed">
                        {tool.implication_if_disabled}
                      </p>
                    </div>
                  )}

                  {/* Not-installed note for docling */}
                  {isUnavailable && (
                    <div className="flex items-start gap-1.5 rounded border border-gray-700/30 bg-gray-900/10 px-2 py-1.5">
                      <AlertTriangle className="w-3 h-3 text-gray-600 shrink-0 mt-0.5" />
                      <p className="text-[10px] text-gray-600 leading-relaxed">
                        {tool.name === 'docling'
                          ? 'Docling is installed automatically at startup via requirements.txt. If unavailable, restart the app to trigger installation.'
                          : 'This tool is not available in the current environment.'}
                      </p>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Save button */}
      <div className="flex items-center gap-3">
        <button
          className="btn-primary flex items-center gap-2 text-sm"
          disabled={!isDirty || saveMut.isPending}
          onClick={() => saveMut.mutate()}
        >
          {saveMut.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          {saveMut.isPending ? 'Saving…' : 'Save'}
        </button>
        {saved && <span className="text-xs text-green-400">Saved.</span>}
        {saveMut.isError && (
          <span className="text-xs text-red-400">Save failed. Try again.</span>
        )}
      </div>
    </div>
  )
}
