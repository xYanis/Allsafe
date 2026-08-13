import MarkdownNote from './MarkdownNote.jsx'

// Affiche un texte complet associé à une vuln — annotation manuelle ("en
// attente de correctif", "faux positif") ou justificatif technique du patch
// check ("Correctif détecté") — les tableaux ne montrent qu'un extrait
// tronqué en ligne, voire aucun aperçu pour le justificatif de patch check.
//
// `text` (rendu en Markdown) couvre le cas simple — une seule annotation
// d'analyste. `blocks` (liste de { heading, body, markdown }) sert au
// justificatif de clôture, qui concatène l'annotation libre de l'analyste
// (Markdown) et le résultat technique du patch check (texte système brut,
// jamais interprété comme Markdown — un caractère `*`/`_` incident dans une
// version de paquet ne doit pas se retrouver en italique).
export default function AnnotationDetailModal({
  vuln, label, color, date, onClose,
  text = vuln.notes, blocks, title = 'Annotation', emptyText = 'Aucune annotation',
}) {
  const isEmpty = blocks ? blocks.length === 0 : !text
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold font-mono" style={{ color }}>{vuln.cve?.cve_id}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {label} — {vuln.asset?.name}{date ? ` · ${new Date(date).toLocaleDateString('fr-FR')}` : ''}
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          {!blocks && <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>{title}</p>}
          {isEmpty ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{emptyText}</p>
          ) : blocks ? (
            blocks.map((b, i) => (
              <div key={i}>
                <p className="text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-muted)' }}>{b.heading}</p>
                {b.markdown
                  ? <MarkdownNote text={b.body} />
                  : <p className="text-sm whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>{b.body}</p>}
              </div>
            ))
          ) : (
            <MarkdownNote text={text} />
          )}
        </div>
      </div>
    </div>
  )
}
