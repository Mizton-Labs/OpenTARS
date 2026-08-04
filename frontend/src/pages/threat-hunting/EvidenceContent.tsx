/**
 * EvidenceContent — the evidence preview pane, extracted from EvidenceTab.tsx
 * (issue-local-034) so Data Explorer's evidence rows can reuse the exact same
 * preview (PDF iframe / extracted-text / "not processed") instead of
 * duplicating it, given both call sites need the same full evidence item
 * (extracted_text, mime_type, parse_status, ...) that a lightweight list row
 * doesn't carry.
 *
 * Content rendering:
 *   - Pending (parse hasn't run yet) -> "fetched during analysis" placeholder.
 *   - PDF (heuristic: mime_type or filename extension) -> native browser
 *     <iframe> against the backend's magic-byte-verified PDF route. The
 *     heuristic only decides whether to ATTEMPT the iframe; the backend is
 *     the actual security boundary (see routes_threat_hunting.py's
 *     get_evidence_pdf docstring) and independently re-verifies.
 *   - Otherwise, non-empty extracted_text -> rendered in full (React text
 *     content — inherently XSS-safe, no dangerouslySetInnerHTML).
 *   - Otherwise -> "not processed" placeholder (binary files, per spec).
 *   - A "Download original" link is always available for file-type items,
 *     regardless of whether an in-app preview exists.
 */
import { Clock, Download, FileText } from 'lucide-react'
import { api, type THEvidenceItem } from '../../api/client'

export function isPdfItem(item: THEvidenceItem): boolean {
  return item.mime_type === 'application/pdf' || item.label.toLowerCase().endsWith('.pdf')
}

export default function EvidenceContent({ item, pkgId }: { item: THEvidenceItem; pkgId: string }) {
  if (item.parse_status === 'pending') {
    return (
      <div className="flex-1 flex items-center justify-center gap-2 text-sm text-blue-400 font-mono py-8">
        <Clock className="w-4 h-4" /> Pending — fetched during analysis
      </div>
    )
  }

  const isPdf = isPdfItem(item)

  return (
    <div className="space-y-3 flex-1 flex flex-col min-h-0">
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-gray-200 truncate">{item.label || item.source_ref}</p>
          <div className="flex items-center gap-2 flex-wrap mt-0.5">
            <span className="text-[11px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{item.item_type}</span>
            {item.parser_used && <span className="text-[11px] text-gray-500">{item.parser_used}</span>}
            {item.parse_warnings.length > 0 && (
              <span className="text-[11px] text-amber-500">
                {item.parse_warnings.length} warning{item.parse_warnings.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
          {item.source_ref && item.item_type === 'url' && (
            <p className="text-[11px] text-gray-600 font-mono truncate mt-0.5">
              {item.final_url || item.source_ref}
            </p>
          )}
        </div>
        {/* Consistent affordance across every content type — file-type
            items always have a blob to download, even without a preview. */}
        {item.item_type === 'file' && (
          <a
            className="btn-ghost text-sm flex items-center gap-1 shrink-0"
            href={api.threatHunting.getEvidenceDownloadUrl(pkgId, item.id)}
            title="Download original file"
          >
            <Download className="w-3.5 h-3.5" /> Download
          </a>
        )}
      </div>

      {isPdf ? (
        <iframe
          src={api.threatHunting.getEvidencePdfUrl(pkgId, item.id)}
          title={item.label || 'PDF preview'}
          className="w-full flex-1 min-h-[400px] rounded border border-gray-800 bg-white"
        />
      ) : item.extracted_text ? (
        <pre className="flex-1 min-h-[300px] max-h-[65vh] overflow-auto whitespace-pre-wrap break-words text-[12px] text-gray-300 bg-gray-950 border border-gray-800 rounded p-3 font-mono">
          {item.extracted_text}
        </pre>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 text-sm text-gray-500 py-8">
          <FileText className="w-8 h-8 text-gray-700" />
          Preview not available for this file type.
        </div>
      )}
    </div>
  )
}
