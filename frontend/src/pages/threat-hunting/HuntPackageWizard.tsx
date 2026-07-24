import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, FileUp, Globe, MessageSquare, Rss, Loader2, CheckCircle, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'
import { api, type THEvidenceItem, type UploadProgress } from '../../api/client'
import FileDropzone from '../../components/FileDropzone'

type Step = 'identity' | 'evidence' | 'review'

type PendingItem =
  | { kind: 'file'; files: File[]; parserMode: string }
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
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null)

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
    setUploadProgress(null)
    try {
      if (addMode === 'file') {
        const p = items.find((i) => i.kind === 'file') as Extract<PendingItem, { kind: 'file' }> | undefined
        if (p) {
          // Upload each file sequentially
          for (const file of p.files) {
            const item = await api.threatHunting.addEvidenceFile(pkgId, file, p.parserMode, setUploadProgress)
            setAddedItems((prev) => [...prev, item])
            setUploadProgress(null)
          }
        }
      } else if (addMode === 'url') {
        const p = items.find((i) => i.kind === 'url') as Extract<PendingItem, { kind: 'url' }> | undefined
        if (p) {
          const item = await api.threatHunting.addEvidenceUrl(pkgId, { url: p.url, label: p.label })
          setAddedItems((prev) => [...prev, item])
        }
      } else if (addMode === 'text') {
        const p = items.find((i) => i.kind === 'text') as Extract<PendingItem, { kind: 'text' }> | undefined
        if (p) {
          const item = await api.threatHunting.addEvidenceText(pkgId, { text: p.text, label: p.label })
          setAddedItems((prev) => [...prev, item])
        }
      } else if (addMode === 'watcher') {
        const p = items.find((i) => i.kind === 'watcher') as Extract<PendingItem, { kind: 'watcher' }> | undefined
        if (p) {
          const item = await api.threatHunting.addEvidenceWatcher(pkgId, { watcher_id: p.watcherId, label: p.label })
          setAddedItems((prev) => [...prev, item])
        }
      }
      setItems([])
      setAddMode(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
      setUploadProgress(null)
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
        <div className="flex gap-1 px-5 py-3 border-b border-gray-800 text-sm">
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
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-900/20 border border-red-800/40 rounded p-2">
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
                    <div key={item.id} className="flex items-center gap-2 text-sm text-gray-300 bg-gray-800/60 rounded px-3 py-2">
                      <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      <span className="truncate flex-1">{item.label || item.source_ref}</span>
                      <span className="text-gray-600">{item.item_type}</span>
                      <span className={clsx('text-[11px]', item.parse_status === 'ok' ? 'text-green-500' : 'text-amber-400')}>
                        {item.parse_status}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Add item type selector */}
              {!addMode && (
                <div>
                  <p className="text-sm text-gray-500 mb-2">Add hunt package item:</p>
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
                          <p className="text-[11px] text-gray-500">{desc}</p>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Add item forms */}
              {addMode === 'file' && (
                <AddFileForm
                  onSubmit={(files, parserMode) => {
                    setItems([{ kind: 'file', files, parserMode }])
                  }}
                  onCancel={() => setAddMode(null)}
                  onAdd={submitItem}
                  busy={busy}
                  uploadProgress={uploadProgress}
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
                {description && <p className="text-sm text-gray-500">{description}</p>}
                <p className="text-sm text-gray-400">{addedItems.length} evidence item{addedItems.length !== 1 ? 's' : ''} added</p>
              </div>
              <p className="text-sm text-gray-500">
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
  onSubmit, onCancel, onAdd, busy, uploadProgress,
}: {
  onSubmit: (files: File[], parserMode: string) => void
  onCancel: () => void
  onAdd: () => void
  busy: boolean
  uploadProgress: UploadProgress | null
}) {
  const [files, setFiles] = useState<File[]>([])
  const [parserMode, setParserMode] = useState('auto')

  function formatSize(bytes: number): string {
    return bytes >= 1_048_576
      ? `${(bytes / 1_048_576).toFixed(1)} MB`
      : `${(bytes / 1024).toFixed(0)} KB`
  }

  function handleFiles(newFiles: File[]) {
    setFiles(newFiles)
    onSubmit(newFiles, parserMode)
  }

  return (
    <div className="border border-gray-700 rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-gray-300">Add Files</p>
      <FileDropzone
        accept=".pdf,.doc,.docx,.txt,.md,.csv,.tsv,.json,.ndjson,.xml,.gz,.zip"
        onFiles={handleFiles}
        disabled={busy}
      />
      {/* Selected files list */}
      {files.length > 0 && (
        <div className="space-y-1">
          {files.map((f, i) => (
            <div key={i} className="flex items-center justify-between text-sm text-gray-400">
              <span className="truncate flex-1">{f.name}</span>
              <span className="text-gray-600 ml-2 shrink-0">{formatSize(f.size)}</span>
            </div>
          ))}
        </div>
      )}
      {/* Upload progress bar */}
      {uploadProgress && (
        <div className="space-y-1">
          <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full bg-brand-500 rounded-full transition-all"
              style={{ width: `${uploadProgress.pct}%` }}
            />
          </div>
          <p className="text-[11px] text-gray-500">
            Uploading… {uploadProgress.pct}%
            {uploadProgress.total > 0 && (
              <span className="ml-1 opacity-60">
                ({(uploadProgress.loaded / 1024).toFixed(0)} / {(uploadProgress.total / 1024).toFixed(0)} KB)
              </span>
            )}
          </p>
        </div>
      )}
      <div>
        <label className="label text-sm">Parser</label>
        <select
          className="input text-sm"
          value={parserMode}
          onChange={(e) => { setParserMode(e.target.value); if (files.length > 0) onSubmit(files, e.target.value) }}
        >
          <option value="auto">Auto</option>
          <option value="pymupdf">PyMuPDF</option>
          <option value="docling">Docling (ML)</option>
        </select>
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-sm" onClick={onCancel} disabled={busy}>Cancel</button>
        <button className="btn-primary text-sm" disabled={files.length === 0 || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : `Add${files.length > 1 ? ` ${files.length} files` : ''}`}
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
        <label className="label text-sm">URL *</label>
        <input className="input w-full font-mono text-sm" type="url" placeholder="https://..." value={url} onChange={(e) => { setUrl(e.target.value); onSubmit(e.target.value, label) }} />
      </div>
      <div>
        <label className="label text-sm">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(url, e.target.value) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-sm" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-sm" disabled={!url.startsWith('http') || busy} onClick={onAdd}>
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
        <label className="label text-sm">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(text, e.target.value) }} />
      </div>
      <div>
        <label className="label text-sm">Text *</label>
        <textarea className="input w-full h-32 resize-none font-mono text-sm" placeholder="Paste threat intel, IOCs, notes..." value={text} onChange={(e) => { setText(e.target.value); onSubmit(e.target.value, label) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-sm" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-sm" disabled={!text.trim() || busy} onClick={onAdd}>
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
        <label className="label text-sm">Watcher *</label>
        <select className="input w-full text-sm" value={watcherId} onChange={(e) => { setWatcherId(e.target.value); onSubmit(e.target.value, label) }}>
          <option value="">Select a watcher...</option>
          {watchers.map((w: { id: string; name: string }) => (
            <option key={w.id} value={w.id}>{w.name}</option>
          ))}
        </select>
      </div>
      <div>
        <label className="label text-sm">Label</label>
        <input className="input w-full text-sm" placeholder="Optional display name" value={label} onChange={(e) => { setLabel(e.target.value); onSubmit(watcherId, e.target.value) }} />
      </div>
      <div className="flex gap-2 justify-end">
        <button className="btn-ghost text-sm" onClick={onCancel}>Cancel</button>
        <button className="btn-primary text-sm" disabled={!watcherId || busy} onClick={onAdd}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Import'}
        </button>
      </div>
    </div>
  )
}
