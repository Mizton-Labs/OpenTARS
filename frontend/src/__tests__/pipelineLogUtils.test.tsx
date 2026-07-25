/**
 * Tests for issue-local-021's verbosity-gated Pipeline Log console content
 * (pipelineLogUtils.ts) — 'verbose' shows only error/disabled/failed
 * reasoning lines, 'debug' shows the full raw trace.
 */
import { describe, it, expect } from 'vitest'
import { isReasoningDebugLine, buildPipelineLogLines } from '../pages/threat-hunting/pipelineLogUtils'
import type { THGenerationRecord } from '../api/client'

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
  it('verbose: only includes reasoning lines, omitting steps with none', () => {
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

    const lines = buildPipelineLogLines(record, 'verbose', STEPS)

    // ttp_analyst had no reasoning lines -> its header is omitted entirely.
    expect(lines).not.toContain('=== TTP Analyst ===')
    expect(lines).not.toContain('LLM_CALL: requesting TTP analysis')

    // hypothesis_generator had one reasoning line -> header + that line only.
    expect(lines).toContain('=== Hypothesis Generator ===')
    expect(lines).toContain('LLM_ERROR: timeout')
    expect(lines).not.toContain('LLM_CALL: requesting hypotheses')
  })

  it('debug: includes every line, unfiltered', () => {
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

    const lines = buildPipelineLogLines(record, 'debug', STEPS)

    expect(lines).toContain('=== TTP Analyst ===')
    expect(lines).toContain('LLM_CALL: requesting TTP analysis')
    expect(lines).toContain('LLM_RESPONSE: 2 techniques parsed')
  })

  it('returns an empty array when no step has debug_lines', () => {
    const record = makeRecord({
      step_logs: [{ step: 'ttp_analyst', status: 'ok', elapsed_s: 0 }],
    })
    expect(buildPipelineLogLines(record, 'debug', STEPS)).toEqual([])
    expect(buildPipelineLogLines(record, 'verbose', STEPS)).toEqual([])
  })
})
