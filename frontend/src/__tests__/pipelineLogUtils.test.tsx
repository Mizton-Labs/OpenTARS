/**
 * Tests for issue-local-021's verbosity-gated Pipeline Log console content
 * (pipelineLogUtils.ts) — issue-local-041 renamed the tiers: 'detailed'
 * (old 'verbose') shows only error/disabled/failed reasoning lines,
 * 'verbose' (old 'debug') and 'debug' (new, deepest) both show the full raw
 * trace.
 */
import { describe, it, expect } from 'vitest'
import {
  isReasoningDebugLine,
  isPipelineLogSectionHeader,
  buildPipelineLogLines,
  sumTokenUsage,
} from '../pages/threat-hunting/pipelineLogUtils'
import type { THGenerationRecord, THStepLog } from '../api/client'

const STEPS = [
  { id: 'ttp_analyst', label: 'TTP Analyst' },
  { id: 'hypothesis_generator', label: 'Hypothesis Generator' },
]

function makeRecord(overrides: Partial<THGenerationRecord> = {}): THGenerationRecord {
  return {
    hunt_package_id: 'pkg-1',
    generation_status: 'completed',
    completed_steps: [],
    step_logs: [],
    ...overrides,
  } as THGenerationRecord
}

describe('isReasoningDebugLine', () => {
  it('matches ERROR lines', () => {
    expect(isReasoningDebugLine('LLM_ERROR: something broke')).toBe(true)
  })
  it('matches DISABLED lines', () => {
    expect(isReasoningDebugLine('LLM_DISABLED: skipping')).toBe(true)
  })
  it('matches FAILED lines', () => {
    expect(isReasoningDebugLine('TOOL_FAILED: x')).toBe(true)
  })
  it('does not match mechanical trace lines', () => {
    expect(isReasoningDebugLine('LLM_CALL: requesting analysis')).toBe(false)
    expect(isReasoningDebugLine('LLM_RESPONSE: 3 items parsed')).toBe(false)
    expect(isReasoningDebugLine('TOOL_CALL: search({})')).toBe(false)
  })
})

describe('buildPipelineLogLines', () => {
  it("detailed: only includes reasoning lines, omitting steps with none (issue-local-041: renamed from old 'verbose')", () => {
    const record = makeRecord({
      step_logs: [
        {
          step: 'ttp_analyst',
          status: 'ok',
          elapsed_s: 0,
          debug_lines: ['LLM_CALL: requesting TTP analysis', 'LLM_RESPONSE: 2 techniques parsed'],
        },
        {
          step: 'hypothesis_generator',
          status: 'error',
          elapsed_s: 0,
          debug_lines: ['LLM_CALL: requesting hypotheses', 'LLM_ERROR: timeout'],
        },
      ],
    })

    const lines = buildPipelineLogLines(record, 'detailed', STEPS)

    // ttp_analyst had no reasoning lines -> its header is omitted entirely.
    expect(lines).not.toContain('=== TTP Analyst ===')
    expect(lines).not.toContain('LLM_CALL: requesting TTP analysis')

    // hypothesis_generator had one reasoning line -> header + that line only.
    expect(lines).toContain('=== Hypothesis Generator ===')
    expect(lines).toContain('LLM_ERROR: timeout')
    expect(lines).not.toContain('LLM_CALL: requesting hypotheses')
  })

  it.each(['verbose', 'debug'] as const)(
    "%s: includes every line, unfiltered (issue-local-041: 'verbose' renamed from old 'debug'; new 'debug' behaves the same here)",
    (tier) => {
      const record = makeRecord({
        step_logs: [
          {
            step: 'ttp_analyst',
            status: 'ok',
            elapsed_s: 0,
            debug_lines: ['LLM_CALL: requesting TTP analysis', 'LLM_RESPONSE: 2 techniques parsed'],
          },
        ],
      })

      const lines = buildPipelineLogLines(record, tier, STEPS)

      expect(lines).toContain('=== TTP Analyst ===')
      expect(lines).toContain('LLM_CALL: requesting TTP analysis')
      expect(lines).toContain('LLM_RESPONSE: 2 techniques parsed')
    },
  )

  it('returns an empty array when no step has debug_lines', () => {
    const record = makeRecord({
      step_logs: [{ step: 'ttp_analyst', status: 'ok', elapsed_s: 0 }],
    })
    expect(buildPipelineLogLines(record, 'debug', STEPS)).toEqual([])
    expect(buildPipelineLogLines(record, 'verbose', STEPS)).toEqual([])
    expect(buildPipelineLogLines(record, 'detailed', STEPS)).toEqual([])
  })
})

describe('sumTokenUsage (issue-local-041)', () => {
  it('sums across every step that reported usage', () => {
    const stepLogs: THStepLog[] = [
      { step: 'a', status: 'ok', elapsed_s: 1, tokens: { input_tokens: 10, output_tokens: 5, cache_read_tokens: null, cache_creation_tokens: null, total_tokens: 15 } },
      { step: 'b', status: 'ok', elapsed_s: 1, tokens: { input_tokens: 20, output_tokens: 8, cache_read_tokens: null, cache_creation_tokens: null, total_tokens: 28 } },
    ]
    expect(sumTokenUsage(stepLogs)).toEqual({ input_tokens: 30, output_tokens: 13, total_tokens: 43 })
  })

  it('returns null when no step reported usage', () => {
    const stepLogs: THStepLog[] = [{ step: 'a', status: 'ok', elapsed_s: 1 }]
    expect(sumTokenUsage(stepLogs)).toBeNull()
  })

  it('returns null for an empty or missing step_logs array', () => {
    expect(sumTokenUsage([])).toBeNull()
    expect(sumTokenUsage(null)).toBeNull()
    expect(sumTokenUsage(undefined)).toBeNull()
  })
})

describe('isPipelineLogSectionHeader (issue-local-041)', () => {
  it('matches a "=== Component ===" header line', () => {
    expect(isPipelineLogSectionHeader('=== TTP Analyst ===')).toBe(true)
  })
  it('does not match an ordinary log line', () => {
    expect(isPipelineLogSectionHeader('LLM_CALL: requesting TTP analysis')).toBe(false)
  })
})
