/**
 * Tests for ReportMarkdown (issue-local-042, item 4b) — the markdown
 * renderer for narrative LLM-authored report/analysis text, so an inline
 * fenced code block (e.g. an SPL snippet the model wrote into its prose)
 * gets the same code-card treatment as the app's structured query-draft
 * cards, instead of showing literal backticks. Same security policy as
 * components/MarkdownMessage.tsx (no raw HTML, links, or images) since this
 * text ultimately derives from evidence a hunt is investigating.
 */
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import ReportMarkdown from '../components/ReportMarkdown'

describe('ReportMarkdown', () => {
  it('renders plain prose as a paragraph', () => {
    render(<ReportMarkdown>{'APT42 targets defense contractors.'}</ReportMarkdown>)
    expect(screen.getByText('APT42 targets defense contractors.')).toBeInTheDocument()
  })

  it('renders a fenced code block with the code-card styling, not literal backticks', () => {
    const text = 'Run this query:\n\n```spl\nindex=dns dest_ip=1.2.3.4\n```\n\nto confirm.'
    render(<ReportMarkdown>{text}</ReportMarkdown>)
    expect(screen.queryByText(/```/)).not.toBeInTheDocument()
    const code = screen.getByText('index=dns dest_ip=1.2.3.4')
    expect(code.tagName).toBe('CODE')
    expect(code.closest('pre')).toHaveClass('bg-gray-950')
  })

  it('renders inline code spans with the same green/monospace treatment', () => {
    render(<ReportMarkdown>{'The macro `hunt_macro_1` searches recent logs.'}</ReportMarkdown>)
    const code = screen.getByText('hunt_macro_1')
    expect(code.tagName).toBe('CODE')
    expect(code).toHaveClass('text-green-400')
  })

  it('strips links to plain text (security: never render clickable indicator links)', () => {
    render(<ReportMarkdown>{'See [evil.example](http://evil.example) for details.'}</ReportMarkdown>)
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    expect(screen.getByText('evil.example')).toBeInTheDocument()
  })

  it('strips images to alt text only (security: never fetch an image URL)', () => {
    render(<ReportMarkdown>{'![diagram](http://evil.example/track.png)'}</ReportMarkdown>)
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.getByText('diagram')).toBeInTheDocument()
  })
})
