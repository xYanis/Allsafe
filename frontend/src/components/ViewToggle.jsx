import { MODULES } from '../constants/modules.js'

// Bascule Tableau/Cartes (23/08/2026 sur Watch.jsx, étendu à FuiteDeDonnees.jsx le même jour
// — demande explicite : "la même bascule que sur veille technologique") — icônes en primitives
// SVG (lignes/rects) plutôt qu'un chemin Heroicons mémorisé, pour une géométrie garantie sans
// risque de mauvais tracé. Couleur fixe CyberVeille : les deux pages consommatrices sont
// toutes les deux ce module (Watch.jsx, FuiteDeDonnees.jsx) — pas de prop `accent` tant qu'une
// 3e page d'un autre module n'en a pas besoin.
const ACCENT = MODULES.cyberveille.color

export default function ViewToggle({ mode, onChange }) {
  const btnStyle = active => ({
    background: active ? ACCENT : 'var(--bg-secondary)',
    color: active ? MODULES.cyberveille.dark : 'var(--text-muted)',
  })
  return (
    <div className="inline-flex rounded-lg overflow-hidden flex-shrink-0" style={{ border: '1px solid var(--border)' }}>
      <button onClick={() => onChange('table')} title="Vue tableau" className="p-1.5 transition-colors" style={btnStyle(mode === 'table')}>
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <line x1="4" y1="7" x2="20" y2="7" strokeWidth="2" strokeLinecap="round" />
          <line x1="4" y1="12" x2="20" y2="12" strokeWidth="2" strokeLinecap="round" />
          <line x1="4" y1="17" x2="20" y2="17" strokeWidth="2" strokeLinecap="round" />
        </svg>
      </button>
      <button onClick={() => onChange('cards')} title="Vue cartes" className="p-1.5 transition-colors" style={btnStyle(mode === 'cards')}>
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <rect x="4" y="4" width="7" height="7" rx="1.5" strokeWidth="2" />
          <rect x="13" y="4" width="7" height="7" rx="1.5" strokeWidth="2" />
          <rect x="4" y="13" width="7" height="7" rx="1.5" strokeWidth="2" />
          <rect x="13" y="13" width="7" height="7" rx="1.5" strokeWidth="2" />
        </svg>
      </button>
    </div>
  )
}
