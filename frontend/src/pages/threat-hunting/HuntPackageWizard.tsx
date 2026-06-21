import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, FileUp, Globe, MessageSquare, Rss, Loader2, CheckCircle, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem } from '../../api/client'

type Step = 'identity' | 'evidence' | 'review'

type PendingItem =
  | { kind: 'file'; file: File; label: string; parserMode: string }
  | { kind: 'url'; url: string; label: string }
  | { kind: 'text'; text: string; label: string }
  | { kind: 'watcher'; watcherId: string; label: string }

export default function HuntPackageWizard({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (id: string) => void
}) {
  const qc = useQueryClient()
  const [step, setStep] = useState<Step>('identity')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [pkgId, setPkgId] = useState<string | null>(null)
  const [items, setItems] = useState<PendingItem[]>([])
  const [addMode, setAddMode] = useState<'file' | 'url' | 'text' | 'watcher' | null>(null)
  const [addedItems, setAddedItems] = useState<THEvidenceItem[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Step 1: create the package
  const createMut = useMutation({
    mutationFn: () => api.threatHunting.createPackage({ name: name.trim(), description }),
    onSuccess: (pkg) => {
      setPkgId(pkg.id)
      qc.invalidateQueries({ queryKey: ['th-packages'] })
      setStep('evidence')
    },
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
  })

  async function submitItem() {
    if (!pkgId) return
    setBusy(true)
    setError(null)
    try {
      let item: THEvidenceItem | null = null
      if (addMode === 'file') {
        const p = items.find((i) => i.kind === 'file') as Extract<PendingItem, { kind: 'file' }> | undefined
        if (p) item = await api.threatHunting.addEvidenceFile(pkgId, p.file, p.parserMode)
      } else if (addMode === 'url') {
        const p = items.find((i) => i.kind === 'url') as Extract<PendingItem, { kind: 'url' }> | undefined
        if (p) item = await api.threatHunting.addEvidenceUrl(pkgId, { url: p.url, label: p.label })
      } else if (addMode === 'text') {
        const p = items.find((i) => i.kind === 'text') as Extract<PendingItem, { kind: 'text' }> | undefined
        if (p) item = await api.threatHunting.addEvidenceText(pkgId, { text: p.text, label: p.label })
      } else if (addMode === 'watcher') {
        const p = items.find((i) => i.kind === 'watcher') as Extract<PendingItem, { kind: 'watcher' }> | undefined
        if (p) item = await api.threatHunting.addEvidenceWatcher(pkgId, { watcher_id: p.watcherId, label: p.label })
      }
      if (item) setAddedItems((prev) => [...prev, item!])
      setItems([])
      setAddMode(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
          <h2 className="text-base font-semibold text-gray-100">New Hunt Package</h2>
          <button className="btn-ghost p-1.5" onClick={onClose}><X className="w-4 h-4" /></button>
        </div>

        {/* Step indicator */}
        <div className="flex gap-1 px-5 py-3 border-b border-gray-800 text-xs">
          {(['identity', 'evidence', 'review'] as Step[]).map((s, i) => (
            <span key={s} className={clsx('flex items-center gap-1', step === s ? 'text-brand-400 font-semibold' : 'text-gray-600')}>
              {i > 0 && <span className="text-gray-700 mx-1">›</span>}
              {i + 1}. {s.charAt(0).toUpperCase() + s.slice(1)}
            </span>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {error && (
            <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/20 border border-red-800/40 rounded p-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {/* Step 1: Identity */}
          {step === 'identity' && (
            <div className="space-y-4">
              <div>
                <label className="label">Package Name *</label>
                <input
                  className="input w-full"
                  placeholder="e.g. APT29 Campaign Investigation"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoFocus
                />
              </div>
              <div>
                <label className="label">Description</label>
                <textarea
                  className="input w-full h-20 resize-none"
                  placeholder="Brief description of the hunting objective..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
            </div>
          )}

          {/* Step 2: Evidence */}
          {step === 'evidence' && (
            <div className="space-y-4">
              <p className="text-sm text-gray-400">Add evidence items to this hunt package. You can add more later.</p>

              {/* Added items list */}
              {addedItems.length > 0 && (
                <div className="space-y-1.5">
                  {addedItems.map((item) => (
                    <div key={item.id} className="flex items-center gap-2 text-xs text-gray-300 bg-gray-800/60 rounded px-3 py-2">
                      <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      <span className="truncate flex-1">{item.label || item.source_ref}</span>
                      <span className="text-gray-600">{item.item_type}</span>
                      <span className={clsx('text-[10px]', item.parse_status === 'ok' ? 'text-green-500' : 'text-amber-400')}>
                        {item.parse_status}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Add item type selector */}
              {!addMode && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">Add hunt package item:</p>
                  <div className="grid grid-cols-2 gap-2">
                    {([
                      { kind: 'file', icon: FileUp, label: 'File', desc: 'PDF, DOCX, TXT, CSV, JSON…' },
                      { kind: 'url', icon: Globe, label: 'URL', desc: 'Fetch article or page' },
                      { kind: 'text', icon: MessageSquare, label: 'Manual Text', desc: 'Paste text or notes' },
                      { kind: 'watcher', icon: Rss, label: 'Watcher Feed', desc: 'Import watcher events' },
                    ] as const).map(({ kind, icon: Icon, label, desc }) => (
                      <button
                        key={kind}
                        className="flex items-start gap-3 p-3 rounded-lg border border-gray-700 hover:border-brand-600/60 hover:bg-brand-900/10 transition-colors text-left"
                        onClick={() => { setAddMode(kind); setItems([]) }}
                      >
                        <Icon className="w-4 h-4 text-brand-400 mt-0.5 shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-gray-200">{label}</p>
                          <p className="text-[10px] text-gray-500">{desc}</p>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Add item forms */}
              {addMode === 'file' && (
                <AddFileForm
                  onSubmit={(file, label, parserMode) => {
                    setItems([{ kind: 'file', file, label, parserMode }])
                  }}
                  onCancel={() => setAddMode(null)}
                  onAdd={submitItem}
                  busy={busy}
                />
              )}
              {addMode === 'url' && (
                <AddUrlForm
                  onSubmit={(url, label) => setItems([{ kind: 'url', url, label }])}
                  onCancel={() => setAddMode(null)}
                  onAdd={submitItem}
                  busy={busy}
                />
              )}
              {addMode === 'text' && (
                <AddTextForm
                  onSubmit={(text, label) => setItems([{ kind: 'text', text, label }])}
                  onCancel={() => setAddMode(null)}
                  onAdd={submitItem}
                  busy={busy}
                />
              )}
              {addMode === 'watcher' && (
                <AddWatcherForm
                  onSubmit={(watcherId, label) => setItems([{ kind: 'watcher', watcherId, label }])}
                  onCancel={() => setAddMode(null)}
                  onAdd={submitItem}
                  busy={busy}
                />
              )}
            </div>
          )}

          {/* Step 3: Review */}
          {step === 'review' && pkgId && (
            <div className="space-y-3">
              <div className="card space-y-2">
                <p className="text-sm font-semibold text-gray-200">{name}</p>
                {description && <p className="text-xs text-gray-500">{description}</p>}
                <p className="text-xs text-gray-400">{addedItems.length} evidence item{addedItems.length !== 1 ? 's' : ''} added</p>
              </div>
              <p className="text-xs text-gray-500">
                The hunt package has been created. You can add more evidence and start the LLM analysis from the package detail page.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-between items-center px-5 py-4 border-t border-gray-800">
          <button className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
          <div className="flex gap-2">
            {step === 'evidence' && (
              <button className="btn-secondary text-sm" onClick={() => setStep('review')}>
                Skip to Review
              </button>
            )}
            {step === 'identity' && (
              <button
                className="btn-primary text-sm"
                disabled={!name.trim() || createMut.isPending}
                onClick={() => createMut.mutate()}
              >
                {createMut.isPending ? 'Creating…' : 'Next: Add Evidence'}
              </button>
            )}
            {step === 'evidence' && !addMode && (
              <button className="btn-primary text-sm" onClick={() => setStep('review')}>
                Next: Review
              </button>
            )}
            {step === 'review' && pkgId && (
              <button className="btn-primary text-sm" onClick={() => onCreated(pkgId)}>
                Open Hunt Package
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Add item sub-forms ────────────────────────────────────────────────────────

function AddFileForm({
  onSubmit, onCancel, onAdd, busy,
}: {
  onSubmit: (file: File, label: string, parserMode: string) => void
  onCancel: () => void
  onAdd: () => void
  busy: boolean
}) {
  const [file, setFile] = useState<File | null>(null)
  const [label, setLabel] = useState('')
  const [parserMode, setParserMode] = useState('auto')

  return (
    <div className="border border-gray-700 rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-gray-300">Add File</p>
      <input
        type="file"
        className="input text-sm"
        accept=".pdf,.doc,.docx,.txt,.md,.csv,.tsv,.json,.ndjson,.xml,.gz,.zip"
        onChange={(e) => {
          const f = e.target.files?.[0] ?? null
          setFile(f)
          if (f && !label) setLabel(f.name)
          if (f) onSubmit(f, label || f.name, parserMode)
        }}
      />
      <div className="flex gap-2">
        <div className="flex-1">
          <label className="label text-xs">Label</label>
          <input className="input w-full text-sm" value={label} onChange={(e) => { setLabel(e.target.value); if (file) onSubmit(file, e.target.value, parserMode) }} placeholder="Display name" />
        </div>
        <div>
          <label className="label text-xs">Parser</label>
          <select className="input text-sm" value={parserMode} onChange={(e) => { setParserMode(e.target.value); if (file) onSubmit(file, label, e.target.value) }}>
            <option value="auto">auto</option>
            <option value="pymupdf">PyMuPDF</option>
            <option value="marker">Marker</option>
          </select>
        </div>
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-xs" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-xs" disabled={!file || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Add'}
        </button>
      </div>
    </div>
  )
}

function AddUrlForm({
  onSubmit, onCancel, onAdd, busy,
}: {
  onSubmit: (url: string, label: string) => void
  onCancel: () => void
  onAdd: () => void
  busy: boolean
}) {
  const [url, setUrl] = useState('')
  const [label, setLabel] = useState('')

  return (
    <div className="border border-gray-700 rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-gray-300">Add URL</p>
      <div>
        <label className="label text-xs">URL *</label>
        <input className="input w-full font-mono text-sm" type="url" placeholder="https://..." value={url} onChange={(e) => { setUrl(e.target.value); onSubmit(e.target.value, label) }} />
      </div>
      <div>
        <label className="label text-xs">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(url, e.target.value) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-xs" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-xs" disabled={!url.startsWith('http') || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Fetch & Add'}
        </button>
      </div>
    </div>
  )
}

function AddTextForm({
  onSubmit, onCancel, onAdd, busy,
}: {
  onSubmit: (text: string, label: string) => void
  onCancel: () => void
  onAdd: () => void
  busy: boolean
}) {
  const [text, setText] = useState('')
  const [label, setLabel] = useState('')

  return (
    <div className="border border-gray-700 rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-gray-300">Add Manual Text</p>
      <div>
        <label className="label text-xs">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(text, e.target.value) }} />
      </div>
      <div>
        <label className="label text-xs">Text *</label>
        <textarea className="input w-full h-32 resize-none font-mono text-xs" placeholder="Paste threat intel, IOCs, notes..." value={text} onChange={(e) => { setText(e.target.value); onSubmit(e.target.value, label) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-xs" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-xs" disabled={!text.trim() || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Add'}
        </button>
      </div>
    </div>
  )
}

function AddWatcherForm({
  onSubmit, onCancel, onAdd, busy,
}: {
  onSubmit: (watcherId: string, label: string) => void
  onCancel: () => void
  onAdd: () => void
  busy: boolean
}) {
  const [watcherId, setWatcherId] = useState('')
  const [label, setLabel] = useState('')

  // Load available watchers
  const { data: watchers = [] } = useQuery({
    queryKey: ['watchers'],
    queryFn: api.watchers.list,
  })

  return (
    <div className="border border-gray-700 rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-gray-300">Import from Watcher</p>
      <div>
        <label className="label text-xs">Watcher *</label>
        <select className="input w-full text-sm" value={watcherId} onChange={(e) => { setWatcherId(e.target.value); onSubmit(e.target.value, label) }}>
          <option value="">Select a watcher...</option>
          {watchers.map((w: { id: string; name: string }) => (
            <option key={w.id} value={w.id}>{w.name}</option>
          ))}
        </select>
      </div>
      <div>
        <label className="label text-xs">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(watcherId, e.target.value) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-xs" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-xs" disabled={!watcherId || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Import'}
        </button>
      </div>
    </div>
  )
}
