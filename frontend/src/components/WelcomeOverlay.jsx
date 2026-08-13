import { useEffect, useState } from 'react'
import { autoBasculeSummary, securityEventsCount, incidentsPendingCount } from '../api/client.js'

const AUTO_DISMISS_MS = 9000  // filet de sécurité si l'utilisateur ne clique jamais
const EXIT_MS = 380

// Récap post-connexion, à terme moins anecdotique que décoratif : CBR tournera en continu
// (cycles autonomes de nuit, cf. tasks/scheduled_tasks.py) et personne ne regarde l'écran en
// permanence — ce court résumé sert à rattraper ce qui s'est passé depuis la dernière visite,
// avec les MÊMES sources déjà exposées ailleurs dans l'app (cloche 🔔/bandeau de rattrapage du
// Dashboard, badges Sécurité/Incidents de la sidebar) plutôt qu'un nouveau système parallèle.
// `last_seen_auto_bascule` (localStorage) est lu ici mais jamais réécrit — Dashboard.jsx reste
// seul propriétaire du repère, pour ne pas lui voler sa propre fenêtre de rattrapage.
async function loadRecap() {
  const since = localStorage.getItem('last_seen_auto_bascule')
  const [bascule, security, nis2] = await Promise.allSettled([
    since ? autoBasculeSummary(since, 1) : Promise.resolve(null),
    securityEventsCount(),
    incidentsPendingCount(),
  ])

  const lines = []
  const b = bascule.status === 'fulfilled' ? bascule.value?.data : null
  if (b?.total > 0) {
    lines.push({ icon: '🔄', text: `${b.total} bascule${b.total > 1 ? 's' : ''} automatique${b.total > 1 ? 's' : ''} de vulnérabilité depuis votre dernière visite` })
  }
  const s = security.status === 'fulfilled' ? security.value?.data : null
  if (s?.unacknowledged > 0) {
    lines.push({ icon: '🛡️', text: `${s.unacknowledged} alerte${s.unacknowledged > 1 ? 's' : ''} de sécurité non acquittée${s.unacknowledged > 1 ? 's' : ''}` })
  }
  const n = nis2.status === 'fulfilled' ? nis2.value?.data : null
  const nis2Total = (n?.overdue || 0) + (n?.imminent || 0)
  if (nis2Total > 0) {
    lines.push({ icon: '⏰', text: `${nis2Total} échéance${nis2Total > 1 ? 's' : ''} NIS 2 à traiter` })
  }
  return lines
}

// Écran de bienvenue affiché une fois après connexion, réservé au compte admin pour l'instant
// (cf. Home.jsx). Se dissipe au clic (bouton ou fond) — filet de sécurité à 9s si l'utilisateur
// ne clique jamais, mais du contenu à lire ne doit pas disparaître tout seul trop tôt.
//
// `onExitStart` (dès le clic, avant le fondu) vs `onDone` (une fois le fondu terminé, EXIT_MS
// plus tard) : Home.jsx s'en sert pour monter son propre en-tête/tuiles PENDANT que cet écran se
// floute/s'efface, plutôt qu'après coup — les deux animations se chevauchent (le flou de sortie
// masque le raccord) au lieu de révéler une Home déjà figée, statique, une fois l'écran disparu.
export default function WelcomeOverlay({ onExitStart, onDone }) {
  const [exiting, setExiting] = useState(false)
  const [recap, setRecap] = useState(null) // null = chargement

  useEffect(() => {
    let cancelled = false
    loadRecap().then(lines => { if (!cancelled) setRecap(lines) }).catch(() => { if (!cancelled) setRecap([]) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    const t = setTimeout(dismiss, AUTO_DISMISS_MS)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function dismiss() {
    setExiting(e => {
      if (!e) {
        onExitStart?.()
        setTimeout(() => onDone?.(), EXIT_MS)
      }
      return true
    })
  }

  return (
    <div className={`welcome-overlay${exiting ? ' welcome-overlay-exit' : ''}`} style={{ background: 'var(--bg-app)' }} onClick={dismiss}>
      <div className="home-glow home-glow--high" />
      <div className="relative z-10 flex flex-col items-center text-center w-full max-w-sm px-6" onClick={e => e.stopPropagation()}>
        <span className="welcome-crown-wrap">
          <span className="welcome-crown-glow" aria-hidden="true" />
          <span className="welcome-crown" role="img" aria-hidden="true">👑</span>
        </span>
        <h1 className="welcome-title text-4xl font-bold tracking-tight">
          Bienvenue Boss !
        </h1>
        <p className="welcome-sub text-sm mt-2" style={{ color: 'var(--text-secondary)' }}>
          {recap === null ? 'Vérification en cours…'
            : recap.length === 0 ? 'Rien à signaler depuis votre dernière visite.'
            : 'Depuis votre dernière visite :'}
        </p>

        {recap && recap.length > 0 && (
          <div className="w-full mt-4 space-y-2">
            {recap.map((line, i) => (
              <div key={i} className="welcome-recap-row flex items-center gap-2.5 text-sm rounded-xl px-3 py-2.5 text-left"
                style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', animationDelay: `${260 + i * 70}ms` }}>
                <span className="text-base flex-shrink-0">{line.icon}</span>
                <span style={{ color: 'var(--text-primary)' }}>{line.text}</span>
              </div>
            ))}
          </div>
        )}

        <button onClick={dismiss}
          className="welcome-continue mt-5 text-xs px-4 py-2 rounded-lg font-medium"
          style={{ background: 'color-mix(in srgb, var(--brand) 15%, transparent)', color: 'var(--brand)', border: '1px solid color-mix(in srgb, var(--brand) 35%, transparent)' }}>
          Continuer →
        </button>
      </div>
    </div>
  )
}
