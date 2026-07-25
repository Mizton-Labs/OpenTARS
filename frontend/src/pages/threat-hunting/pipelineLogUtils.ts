/**
 * pipelineLogUtils — issue-local-021: verbosity-gated "Pipeline Log" console
 * content for WorkflowVisualizer.tsx's TimelineVisualizer.
 *
 * Split into its own file (rather than living inline in WorkflowVisualizer.tsx)
 * so these pure functions are unit-testable without mounting the component
 * tree, and so the file only exports components (react-refresh convention).
 */
import type { THGenerationRecord, THStepLog } from '../../api/client'

/** At 'verbose' verbosity, only surface debug_lines that explain *why*
 * something happened (errors, disabled/fallback paths) — the mechanical
 * TOOL_CALL/TOOL_RESULT/LLM_CALL/LLM_RESPONSE trace is 'debug'-only. */
export function isReasoningDebugLine(line: string): boolean {
  return /ERROR|DISABLED|FAILED/i.test(line)
}

/** Build the Pipeline Log console's line buffer for one generation record,
 * grouped by step and filtered per verbosity. */
export function buildPipelineLogLines(
  genRecord: THGenerationRecord,
  verbosity: 'verbose' | 'debug',
  steps: { id: string; label: string }[],
): string[] {
  const stepLogs: Record<string, THStepLog> = {}
  for (const log of genRecord.step_logs ?? []) {
    stepLogs[log.step] = log
  }
  const debug = verbosity === 'debug'
  const lines: string[] = []
  for (const step of steps) {
    const log = stepLogs[step.id]
    const stepLines = log?.debug_lines ?? []
    if (!stepLines.length) continue
    const visible = debug ? stepLines : stepLines.filter(isReasoningDebugLine)
    if (!visible.length) continue
    lines.push(`=== ${step.label} ===`)
    lines.push(...visible)
  }
  return lines
}
