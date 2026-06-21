import { useState } from 'react'
import { X, FileUp, Globe, MessageSquare, Rss, Loader2, CheckCircle, AlertTriangle } from 'lucide-react'
import { api, type THEvidenceItem } from '../../api/client'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'

type AddMode = 'file' | 'url' | 'text' | 'watcher' | null

export default function AddEvidenceModal({
  pkgId,
  onClose,
  onAdded,
}: {
  pkgId: string
  onClose: () => void
  onAdded: () => void
}) {
  const [addMode, setAddMode] = useState<AddMode>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [added, setAdded] = useState<THEvidenceItem | null>(null)

  // File state
  const [file, setFile] = useState<File | null>(null)
  const [fileLabel, setFileLabel] = useState('')
  const [parserMode, setParserMode] = useState('auto')
  // URL state
  const [url, setUrl] = useState('')
  const [urlLabel, setUrlLabel] = useState('')
  // Text state
  const [text, setText] = useState('')
  const [textLabel, setTextLabel] = useState('')
  // Watcher state
  const [watcherId, setWatcherId] = useState('')
  const [watcherLabel, setWatcherLabel] = useState('')

  const { data: watchers = [] } = useQuery({
    queryKey: ['watchers'],
    queryFn: api.watchers.list,
    enabled: addMode === 'watcher',
  })

  // issue-007: fetch agent-tools catalog to check docling availability + enabled
  const { data: catalogData } = useQuery({
    queryKey: ['agent-tools-catalog'],
    queryFn: () => api.getAgentToolsCatalog(),
    staleTime: 60_000,
    enabled: addMode === 'file',
  })
  const doclingEntry = catalogData?.catalog?.find((e) => e.name === 'docling')
  const doclingAvailable = doclingEntry?.available ?? false

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      let item: THEvidenceItem | null = null
      if (addMode === 'file' && file) {
        item = await api.threatHunting.addEvidenceFile(pkgId, file, parserMode)
      } else if (addMode === 'url' && url) {
        item = await api.threatHunting.addEvidenceUrl(pkgId, { url, label: urlLabel })
      } else if (addMode === 'text' && text) {
        item = await api.threatHunting.addEvidenceText(pkgId, { text, label: textLabel })
      } else if (addMode === 'watcher' && watcherId) {
        item = await api.threatHunting.addEvidenceWatcher(pkgId, { watcher_id: watcherId, label: watcherLabel })
      }
      if (item) { setAdded(item); onAdded() }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
          <h2 className="text-base font-semibold text-gray-100">Add Hunt Package Item</h2>
          <button className="btn-ghost p-1.5" onClick={onClose}><X className="w-4 h-4" /></button>
        </div>
        <div className="p-5 space-y-4">
          {error && <p className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" />{error}</p>}
          {added && <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" />Added: {added.label}</p>}

          {!addMode && (
            <div className="grid grid-cols-2 gap-2">
              {([
                { kind: 'file' as const, icon: FileUp, label: 'File' },
                { kind: 'url' as const, icon: Globe, label: 'URL' },
                { kind: 'text' as const, icon: MessageSquare, label: 'Manual Text' },
                { kind: 'watcher' as const, icon: Rss, label: 'Watcher Feed' },
              ]).map(({ kind, icon: Icon, label }) => (
                <button
                  key={kind}
                  className="flex items-center gap-2 p-3 rounded-lg border border-gray-700 hover:border-brand-600/60 hover:bg-brand-900/10 transition-colors"
                  onClick={() => setAddMode(kind)}
                >
                  <Icon className="w-4 h-4 text-brand-400" />
                  <span className="text-sm text-gray-200">{label}</span>
                </button>
              ))}
            </div>
          )}

          {addMode === 'file' && (
            <div className="space-y-3">
              <input type="file" className="input w-full text-sm" accept=".pdf,.doc,.docx,.txt,.md,.csv,.tsv,.json,.ndjson,.xml,.gz,.zip" onChange={(e) => { const f = e.target.files?.[0] ?? null; setFile(f); if (f && !fileLabel) setFileLabel(f.name) }} />
              <input className="input w-full text-sm" placeholder="Label" value={fileLabel} onChange={(e) => setFileLabel(e.target.value)} />
              <select
                className="input w-full text-sm"
                value={parserMode}
                onChange={(e) => setParserMode(e.target.value)}
              >
                <option value="auto">Parser: auto{doclingAvailable ? ' (prefers Docling)' : ' (PyMuPDF)'}</option>
                <option value="pymupdf">PyMuPDF — fast, plain text</option>
                <option
                  value="docling"
                  disabled={!doclingAvailable}
                  className={clsx(!doclingAvailable && 'text-gray-600')}
                >
                  Docling — high-quality Markdown{!doclingAvailable ? ' (not installed)' : ''}
                </option>
              </select>
              {parserMode === 'docling' && !doclingAvailable && (
                <div className="flex items-center gap-1.5 text-[10px] text-amber-400">
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  Docling is not yet installed — selection will fall back to PyMuPDF.
                  Restart the app to trigger installation.
                </div>
              )}
            </div>
          )}
          {addMode === 'url' && (
            <div className="space-y-3">
              <input type="url" className="input w-full font-mono text-sm" placeholder="https://..." value={url} onChange={(e) => setUrl(e.target.value)} />
              <input className="input w-full text-sm" placeholder="Label (optional)" value={urlLabel} onChange={(e) => setUrlLabel(e.target.value)} />
            </div>
          )}
          {addMode === 'text' && (
            <div className="space-y-3">
              <input className="input w-full text-sm" placeholder="Label (optional)" value={textLabel} onChange={(e) => setTextLabel(e.target.value)} />
              <textarea className="input w-full h-32 resize-none font-mono text-xs" placeholder="Paste threat intel, IOCs, notes..." value={text} onChange={(e) => setText(e.target.value)} />
            </div>
          )}
          {addMode === 'watcher' && (
            <div className="space-y-3">
              <select className="input w-full text-sm" value={watcherId} onChange={(e) => setWatcherId(e.target.value)}>
                <option value="">Select watcher...</option>
                {(watchers as { id: string; name: string }[]).map((w) => (
                  <option key={w.id} value={w.id}>{w.name}</option>
                ))}
              </select>
              <input className="input w-full text-sm" placeholder="Label (optional)" value={watcherLabel} onChange={(e) => setWatcherLabel(e.target.value)} />
            </div>
          )}
        </div>
        <div className="flex justify-between px-5 py-4 border-t border-gray-800">
          <button className="btn-ghost text-sm" onClick={addMode ? () => setAddMode(null) : onClose}>
            {addMode ? 'Back' : 'Close'}
          </button>
          {addMode && (
            <button
              className="btn-primary text-sm"
              disabled={busy || (addMode === 'file' && !file) || (addMode === 'url' && !url) || (addMode === 'text' && !text.trim()) || (addMode === 'watcher' && !watcherId)}
              onClick={submit}
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Add Item'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
