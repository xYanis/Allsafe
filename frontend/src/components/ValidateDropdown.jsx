import { useState, useEffect, useRef } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'

export default function ValidateDropdown({ onSelect, detected, label = '✓ Corrigé', initialNote = '' }) {
  // `names` bascule déjà sur FAKE_VALIDATORS en mode Présentation, centralisé dans
  // AnalystContext.jsx (31/07/2026) — plus besoin de le refaire ici.
  const { names } = useAnalysts()
  const [open, setOpen] = useState(false)
  // Pré-rempli depuis le justificatif technique du patch check (04/08/2026, demande
  // explicite : ne pas laisser l'analyste retaper ce que l'app vient déjà de montrer) —
  // reste librement modifiable/effaçable avant validation, jamais imposé.
  const [note, setNote] = useState(initialNote)
  const [menuStyle, setMenuStyle] = useState({})
  const btnRef = useRef(null)
  const menuRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = e => {
      if (
        btnRef.current && !btnRef.current.contains(e.target) &&
        menuRef.current && !menuRef.current.contains(e.target)
      ) setOpen(false)
    }
    const onKeyDown = e => { if (e.key === 'Escape') { setNote(''); setOpen(false) } }
    document.addEventListener('mousedown', handler)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', handler)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  function toggle() {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      // Ouvre en dessous par défaut, remonte si pas assez de place
      const spaceBelow = window.innerHeight - r.bottom
      const menuH = 280
      if (spaceBelow < menuH) {
        setMenuStyle({ position: 'fixed', bottom: window.innerHeight - r.top + 4, right: window.innerWidth - r.right, zIndex: 9999 })
      } else {
        setMenuStyle({ position: 'fixed', top: r.bottom + 4, right: window.innerWidth - r.right, zIndex: 9999 })
      }
    }
    setOpen(o => !o)
  }

  // Note libre, jamais obligatoire (contrairement à AnnotationModal utilisé
  // pour "en attente"/"faux positif") — corriger une vuln non-CRITICAL reste
  // une action rapide, l'annotation n'est qu'un complément optionnel.
  function select(name) {
    onSelect(name, note.trim() || undefined)
    setNote('')
    setOpen(false)
  }

  const bg  = detected ? 'rgba(63,185,80,0.2)' : 'rgba(63,185,80,0.1)'
  const bdr = detected ? 'rgba(63,185,80,0.5)' : 'rgba(63,185,80,0.2)'

  return (
    <>
      <button
        ref={btnRef}
        onClick={toggle}
        className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-[background-color,transform] duration-150 flex items-center gap-1 active:scale-[0.97]"
        style={{ background: bg, color: '#3fb950', border: `1px solid ${bdr}` }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(63,185,80,0.3)'}
        onMouseLeave={e => e.currentTarget.style.background = bg}
      >
        {label}
        <svg style={{ width: 10, height: 10, flexShrink: 0 }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div
          ref={menuRef}
          style={{
            ...menuStyle,
            minWidth: 260,
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 10,
            boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
            overflow: 'hidden',
          }}
        >
          <div className="px-3 pt-2.5 pb-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
            <label className="text-[10px] font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>
              Annotation <span className="normal-case font-normal" style={{ opacity: 0.7 }}>(facultative)</span>
            </label>
            <textarea
              autoFocus
              value={note}
              onChange={e => setNote(e.target.value)}
              onClick={e => e.stopPropagation()}
              rows={3}
              placeholder="Ex : build vérifié, KB4489899 installé…"
              className="w-full text-xs rounded-lg px-2 py-1.5 outline-none resize-none transition-colors"
              style={{ background: 'var(--bg-app)', border: `1px solid ${note ? 'rgba(63,185,80,0.4)' : 'var(--border)'}`, color: 'var(--text-primary)' }}
            />
          </div>
          <p className="px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
            Validé par
          </p>
          {names.map(name => (
            <button
              key={name}
              onClick={() => select(name)}
              className="w-full text-left text-xs px-3 py-2.5 transition-colors"
              style={{ color: 'var(--text-secondary)' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(63,185,80,0.1)'; e.currentTarget.style.color = '#3fb950' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-secondary)' }}
            >
              {name}
            </button>
          ))}
        </div>
      )}
    </>
  )
}
