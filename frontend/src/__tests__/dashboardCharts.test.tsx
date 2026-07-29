/**
 * Tests for HuntDashboard's visual building blocks (issue-local-034):
 * BarBreakdown pagination (10/page), PieChart rendering, and TimelineChart
 * rendering. StatCard is covered indirectly via huntDashboard.test.tsx.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect } from 'vitest'
import { Shield } from 'lucide-react'
import { BarBreakdown, PieChart, TimelineChart } from '../pages/threat-hunting/DashboardCharts'

describe('BarBreakdown — pagination (issue-local-034)', () => {
  function modelRows(n: number): [string, number][] {
    return Array.from({ length: n }, (_, i) => [`model-${i}`, n - i])
  }

  it('shows no pagination controls at or under 10 rows', () => {
    render(<BarBreakdown title="Runs by Model" icon={Shield} rows={modelRows(10)} />)

    expect(screen.getByText('model-0')).toBeInTheDocument()
    expect(screen.getByText('model-9')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /next page/i })).not.toBeInTheDocument()
  })

  it('shows only the first 10 rows and paginates beyond that', async () => {
    const user = userEvent.setup()
    render(<BarBreakdown title="Runs by Model" icon={Shield} rows={modelRows(25)} />)

    expect(screen.getByText('model-0')).toBeInTheDocument()
    expect(screen.getByText('model-9')).toBeInTheDocument()
    expect(screen.queryByText('model-10')).not.toBeInTheDocument()
    expect(screen.getByText(/page 1 of 3/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /next page/i }))

    expect(screen.getByText('model-10')).toBeInTheDocument()
    expect(screen.queryByText('model-0')).not.toBeInTheDocument()
  })

  it('renders an empty state with no rows', () => {
    render(<BarBreakdown title="Runs by Model" icon={Shield} rows={[]} />)

    expect(screen.getByText(/no data yet/i)).toBeInTheDocument()
  })

  it('calls onClick when the header is clicked, without affecting pagination', async () => {
    const user = userEvent.setup()
    let clicked = false
    render(
      <BarBreakdown
        title="Runs by Model"
        icon={Shield}
        rows={modelRows(5)}
        onClick={() => {
          clicked = true
        }}
      />,
    )

    await user.click(screen.getByRole('button', { name: /runs by model/i }))

    expect(clicked).toBe(true)
  })
})

describe('PieChart (issue-local-034)', () => {
  it('renders a legend entry per slice with percentage', () => {
    render(
      <PieChart
        title="Evidence by Type"
        icon={Shield}
        rows={[
          ['file', 75],
          ['url', 25],
        ]}
      />,
    )

    expect(screen.getByText('file')).toBeInTheDocument()
    expect(screen.getByText('75 (75%)')).toBeInTheDocument()
    expect(screen.getByText('url')).toBeInTheDocument()
    expect(screen.getByText('25 (25%)')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /evidence by type pie chart/i })).toBeInTheDocument()
  })

  it('renders an empty state with no rows', () => {
    render(<PieChart title="Evidence by Type" icon={Shield} rows={[]} />)

    expect(screen.getByText(/no data yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  it('is clickable when onClick is passed', async () => {
    const user = userEvent.setup()
    let clicked = false
    render(
      <PieChart
        title="Evidence by Type"
        icon={Shield}
        rows={[['file', 1]]}
        onClick={() => {
          clicked = true
        }}
      />,
    )

    await user.click(screen.getByRole('button', { name: /evidence by type/i }))

    expect(clicked).toBe(true)
  })
})

describe('TimelineChart (issue-local-034)', () => {
  it('renders a total and the first/last date labels', () => {
    render(
      <TimelineChart
        title="Hunts per Day"
        icon={Shield}
        data={[
          { date: '2026-01-01', count: 3 },
          { date: '2026-01-02', count: 5 },
          { date: '2026-01-05', count: 2 },
        ]}
      />,
    )

    expect(screen.getByText('Hunts per Day')).toBeInTheDocument()
    expect(screen.getByText('Total: 10')).toBeInTheDocument()
    expect(screen.getByText('2026-01-01')).toBeInTheDocument()
    expect(screen.getByText('2026-01-05')).toBeInTheDocument()
  })

  it('renders an empty state with no data', () => {
    render(<TimelineChart title="Hunts per Day" icon={Shield} data={[]} />)

    expect(screen.getByText(/no data yet/i)).toBeInTheDocument()
  })
})
