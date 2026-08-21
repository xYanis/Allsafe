import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { moduleForPath } from '../constants/modules.js'
import { guideForPath } from '../constants/pageGuides.js'
import { useGuidePreference } from '../contexts/GuidePreferenceContext.jsx'
import OsLogo from './OsLogo.jsx'

// Guide pas à pas flottant (19/08/2026, demande utilisateur — un guide d'aide sur chaque page).
// Monté UNE seule fois dans Layout.jsx ; il résout le contenu selon la route courante
// (constants/pageGuides.js) et se thème avec la couleur du module (constants/modules.js). Masqué
// globalement via la préférence guidesHidden (Paramètres > Apparence). Généralise l'ancien
// AgentGuide : le rendu « paquets » (logo OS + commandes) reste disponible pour l'entrée /agents.

function PackageRow({ os, label, desc, cmds }) {
  return (
    <li className="mt-3">
      <div className="flex items-start gap-2">
        <span className="flex-shrink-0 mt-0.5"><OsLogo os={os} size={18} /></span>
        <span className="min-w-0">
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{label}</span>
          <span className="block text-xs" style={{ color: 'var(--text-muted)' }}>{desc}</span>
        </span>
      </div>
      {cmds && (
        <pre className="mt-1.5 ml-7 text-xs rounded-lg px-3 py-2 overflow-x-auto"
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
          <code>{cmds.join('\n')}</code>
        </pre>
      )}
    </li>
  )
}

export default function PageGuide() {
  const { pathname } = useLocation()
  const { guidesHidden } = useGuidePreference()
  const [open, setOpen] = useState(false)

  const guide = guideForPath(pathname)
  const mod = moduleForPath(pathname)
  const color = mod?.color || 'var(--accent-blue)'
  const darkText = mod?.dark || '#0d1117'

  // Fermer la modale à chaque changement de route (sinon elle resterait ouverte en naviguant).
  useEffect(() => { setOpen(false) }, [pathname])

  useEffect(() => {
    if (!open) return
    const onKey = e => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open])

  // Pas de guide pour cette route, ou masqué par préférence → rien du tout.
  if (!guide || guidesHidden) return null

  return (
    <>
      {/* Bouton flottant bas-droite — z-40, sous les modales (z-50). */}
      <button onClick={() => setOpen(true)} title={`Guide — ${guide.title.replace(/^Guide — /, '')}`}
        aria-label="Ouvrir le guide de cette page"
        className="fixed bottom-6 right-6 z-40 w-12 h-12 rounded-full flex items-center justify-center shadow-lg transition-transform hover:scale-105"
        style={{ background: color, color: darkText }}>
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
        </svg>
      </button>

      {open && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={() => setOpen(false)}>
          <div className="max-w-2xl w-full rounded-2xl animate-modal-in max-h-[85vh] flex flex-col"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 flex items-start justify-between gap-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{guide.title}</h2>
                {guide.subtitle && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{guide.subtitle}</p>}
              </div>
              <button onClick={() => setOpen(false)} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>

            <div className="overflow-auto p-6 space-y-5">
              {guide.steps.map((step, i) => (
                <div key={i} className="flex gap-3.5">
                  <span className="flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold"
                    style={{ background: `${color}22`, color }}>
                    {i + 1}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{step.title}</p>
                    <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)', lineHeight: 1.5 }}>{step.body}</p>
                    {step.packages && (
                      <ul className="mt-1">
                        {step.packages.map((p, k) => <PackageRow key={k} {...p} />)}
                      </ul>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <div className="px-6 py-3 flex justify-end" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={() => setOpen(false)}
                className="text-sm px-4 py-2 rounded-lg font-medium"
                style={{ background: color, color: darkText }}>
                J'ai compris
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
