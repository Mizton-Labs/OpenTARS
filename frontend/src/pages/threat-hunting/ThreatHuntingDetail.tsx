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
      onBack={() => navigate('..', { relative: 'path' })}
    />
  )
}
