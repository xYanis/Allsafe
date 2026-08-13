// Empilement de notifications éphémères, ancré en bas à droite — pour un
// événement qui se produit **pendant que la page est déjà ouverte** (ex :
// bascule automatique détectée en direct par le polling du Dashboard).
//
// Complémentaire, pas un remplacement du bandeau de rattrapage
// (`autoBasculeSummary`, cf. Dashboard.jsx) : celui-ci résume ce qui s'est
// passé pendant une absence (cycle de nuit, onglet fermé) — un toast ne peut
// par nature notifier que d'un événement survenu pendant que quelqu'un
// regarde déjà l'écran, ça ne couvre pas le même cas.
//
// Composant partagé (et non gardé local à Dashboard.jsx) : le pattern
// "notifier d'un événement en direct" n'a rien de spécifique au patch check,
// une 2e page qui en aurait besoin le réutilise sans dupliquer l'empilement/
// les timers (principe "penser scalable", CLAUDE.md).

const VARIANTS = {
  // Vert — correctif détecté (même couleur que le badge "Patched").
  success: { color: '#3fb950', background: 'rgba(63,185,80,0.12)', border: 'rgba(63,185,80,0.4)' },
  // Violet — faux positif qualifié (même couleur que son badge dans "traitées").
  violet:  { color: '#a371f7', background: 'rgba(163,113,247,0.12)', border: 'rgba(163,113,247,0.4)' },
  info:    { color: '#58a6ff', background: 'rgba(88,166,255,0.12)', border: 'rgba(88,166,255,0.4)' },
  // Rouge — même couleur que les badges/erreurs CRITICAL ailleurs dans l'app.
  error:   { color: '#f85149', background: 'rgba(248,81,73,0.12)', border: 'rgba(248,81,73,0.4)' },
}

function ToastIcon({ variant }) {
  if (variant === 'success') {
    return (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    )
  }
  if (variant === 'violet') {
    return (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
      </svg>
    )
  }
  if (variant === 'error') {
    return (
      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 4.75c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
    )
  }
  return (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  )
}

// `toasts` : [{ id, message, variant, leaving }]. `leaving` déclenche
// l'animation de sortie avant que l'appelant ne retire réellement l'entrée
// (cf. Dashboard.jsx `dismissToast`) — sans ça, la sortie serait instantanée.
export default function ToastStack({ toasts, onDismiss }) {
  if (!toasts.length) return null
  return (
    <div className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2 items-end pointer-events-none" style={{ maxWidth: 380 }}>
      {toasts.map(t => {
        const v = VARIANTS[t.variant] || VARIANTS.info
        return (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start gap-2.5 px-4 py-3 rounded-xl shadow-lg text-sm ${t.leaving ? 'animate-toast-out' : 'animate-toast-in'}`}
            style={{ background: 'var(--bg-card)', border: `1px solid ${v.border}`, boxShadow: '0 8px 24px rgba(0,0,0,0.35)' }}
          >
            <span style={{ color: v.color }} className="mt-0.5"><ToastIcon variant={t.variant} /></span>
            <span className="flex-1" style={{ color: 'var(--text-secondary)' }}>{t.message}</span>
            <button onClick={() => onDismiss(t.id)} className="p-0.5 rounded flex-shrink-0" style={{ color: 'var(--text-muted)' }} title="Fermer">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        )
      })}
    </div>
  )
}
