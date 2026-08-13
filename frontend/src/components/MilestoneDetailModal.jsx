import MarkdownNote from './MarkdownNote.jsx'

// Relit ce qui a été consigné pour un jalon NIS 2 déjà marqué envoyé (justification,
// auteur, date) — la timeline garde tout, mais fouiller la chronologie pour retrouver
// une seule entrée est peu pratique. Générique, contrairement à AnnotationDetailModal.jsx
// (trop couplé à la forme d'une vulnérabilité vuln.cve/vuln.asset).
export default function MilestoneDetailModal({ title, subtitle, date, author, text, onClose }) {
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {subtitle}
              {author ? ` · ${author}` : ''}
              {date ? ` · ${new Date(date).toLocaleString('fr-FR')}` : ''}
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6">
          {text ? <MarkdownNote text={text} /> : <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucune note consignée.</p>}
        </div>
      </div>
    </div>
  )
}
