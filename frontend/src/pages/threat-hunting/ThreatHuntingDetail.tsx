/**
 * ThreatHuntingDetail — detail page for a single hunt package.
 * Accessed via the nested route threat-hunting/:id.
 * Reads the package id from useParams() and renders HuntDetail.
 */
import { useNavigate, useParams } from 'react-router-dom'
import HuntDetail from './HuntDetail'

export default function ThreatHuntingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  if (!id) return null

  return (
    <HuntDetail
      pkgId={id}
      // issue-local-032: '..' now resolves to the Dashboard, not the package
      // list — this page is only reached FROM the package list (or a direct
      // link), so "back" should return there, not to the Dashboard.
      onBack={() => navigate('../packages', { relative: 'path' })}
    />
  )
}
