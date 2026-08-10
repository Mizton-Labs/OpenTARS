/**
 * pipelineLogUtils — issue-local-021: verbosity-gated "Pipeline Log" console
 * content for WorkflowVisualizer.tsx's TimelineVisualizer.
 *
 * Split into its own file (rather than living inline in WorkflowVisualizer.tsx)
 * so these pure functions are unit-testable without mounting the component
 * tree, and so the file only exports components (react-refresh convention).
 */
import type { THGenerationRecord, THStepLog, THTokenUsage } from '../../api/client'

const TOKEN_USAGE_FIELDS: (keyof THTokenUsage)[] = [
  'input_tokens',
  'output_tokens',
  'cache_read_tokens',
  'cache_creation_tokens',
  'total_tokens',
]

/** issue-local-041: sum every step's token usage into one run-level total —
 *  mirrors db.py's _sum_token_usage exactly (a field stays absent from the
 *  total if no step reported it; the whole result is null if nothing did). */
export function sumTokenUsage(stepLogs: THStepLog[] | null | undefined): Partial<THTokenUsage> | null {
  const totals: Partial<THTokenUsage> = {}
  let seenAny = false
  for (const log of stepLogs ?? []) {
    const tokens = log.tokens
    if (!tokens) continue
    for (const field of TOKEN_USAGE_FIELDS) {
      const value = tokens[field]
      if (typeof value === 'number') {
        totals[field] = (totals[field] ?? 0) + value
        seenAny = true
      }
    }
  }
  return seenAny ? totals : null
}

/** At 'detailed' verbosity, only surface debug_lines that explain *why*
 * something happened (errors, disabled/fallback paths) — the mechanical
 * TOOL_CALL/TOOL_RESULT/LLM_CALL/LLM_RESPONSE trace requires 'verbose' or
 * 'debug' (issue-local-041: renamed from the old 3-tier verbose/debug). */
export function isReasoningDebugLine(line: string): boolean {
  return /ERROR|DISABLED|FAILED/i.test(line)
}

/** issue-local-041: identifies buildPipelineLogLines' own
 * "=== <Component Label> ===" section-header lines, so the 'debug'-tier
 * console can highlight which agent/component produced the lines below it. */
export function isPipelineLogSectionHeader(line: string): boolean {
  return /^=== .+ ===$/.test(line)
}

/** Build the Pipeline Log console's line buffer for one generation record,
 * grouped by step and filtered per verbosity. */
export function buildPipelineLogLines(
  genRecord: THGenerationRecord,
  verbosity: 'detailed' | 'verbose' | 'debug',
  steps: { id: string; label: string }[],
): string[] {
  const stepLogs: Record<string, THStepLog> = {}
  for (const log of genRecord.step_logs ?? []) {
    stepLogs[log.step] = log
  }
  const fullTrace = verbosity === 'verbose' || verbosity === 'debug'
  const lines: string[] = []
  for (const step of steps) {
    const log = stepLogs[step.id]
    const stepLines = log?.debug_lines ?? []
    if (!stepLines.length) continue
    const visible = fullTrace ? stepLines : stepLines.filter(isReasoningDebugLine)
    if (!visible.length) continue
    lines.push(`=== ${step.label} ===`)
    lines.push(...visible)
  }
  return lines
}
