import { useState, useEffect, useRef } from 'react'

// Dropdown multi-select des actifs — un, plusieurs, ou tous (case vide = tous).
// Même pattern que SourceDropdown (Watch.jsx), en liste plate (pas de groupes).
// Partagé par Dashboard.jsx et Reports.jsx.
export default function AssetDropdown({ assetList, selected, onChange }) {
  const [open, setOpen] = useState(false)
  // Recherche texte (04/08/2026, demande explicite) — la liste plate devient
  // pénible à parcourir au clic passé quelques dizaines d'actifs (72 sur ce parc).
  // Filtre seulement l'affichage : `assetList` complet reste la source de vérité
  // pour résoudre le libellé du bouton (nom du seul actif sélectionné, etc.).
  const [search, setSearch] = useState('')
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // Repart d'une recherche vide à chaque réouverture — éviter de retrouver un
  // filtre périmé d'une session de clics précédente.
  useEffect(() => { if (!open) setSearch('') }, [open])

  function toggle(id) {
    onChange(selected.includes(id) ? selected.filter(s => s !== id) : [...selected, id])
  }

  const filtered = search.trim()
    ? assetList.filter(a => a.name.toLowerCase().includes(search.trim().toLowerCase()))
    : assetList

  const label = selected.length === 0
    ? 'Tous les actifs'
    : selected.length === 1
      ? (assetList.find(a => a.id === selected[0])?.name ?? '1 actif')
      : `${selected.length} actifs`

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 text-xs px-2.5 py-1.5 rounded-lg"
        style={{
          background: selected.length > 0 ? 'rgba(88,166,255,0.1)' : 'var(--bg-secondary)',
          color: selected.length > 0 ? '#58a6ff' : 'var(--text-secondary)',
          border: selected.length > 0 ? '1px solid rgba(88,166,255,0.3)' : '1px solid var(--border)',
        }}
      >
        {label}
        <svg className="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={open ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7'} />
        </svg>
      </button>

      {open && (
        <div
          className="absolute z-50 mt-1 rounded-xl overflow-hidden flex flex-col"
          style={{
            top: '100%', left: 0, minWidth: 220, maxHeight: 320,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          }}
        >
          {assetList.length > 0 && (
            <div className="px-2 pt-2 pb-1.5 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
              <input
                autoFocus
                value={search}
                onChange={e => setSearch(e.target.value)}
                onClick={e => e.stopPropagation()}
                placeholder="Rechercher un actif…"
                className="w-full text-xs px-2.5 py-1.5 rounded-lg outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
              />
            </div>
          )}
          <div style={{ overflowY: 'auto' }}>
          {assetList.length === 0 && (
            <p className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>Aucun actif</p>
          )}
          {assetList.length > 0 && filtered.length === 0 && (
            <p className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>Aucun actif trouvé.</p>
          )}
          {filtered.map(a => (
            <label key={a.id}
              className="flex items-center gap-2.5 px-4 py-1.5 cursor-pointer text-sm"
              style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <input
                type="checkbox"
                checked={selected.includes(a.id)}
                onChange={() => toggle(a.id)}
                className="w-3.5 h-3.5 accent-blue-500 flex-shrink-0"
              />
              {a.name}
            </label>
          ))}
          </div>
          {selected.length > 0 && (
            <div className="px-4 py-2.5 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={() => onChange([])} className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Tout décocher — revenir à "Tous les actifs"
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
