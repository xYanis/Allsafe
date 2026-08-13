import { useEffect, useState } from 'react'
import { CbrLogoTile } from './CbrMark.jsx'

// Écran de transition affiché à la déconnexion — pendant du WelcomeOverlay
// (post-login) côté sortie. Sans lui, `logout()` bascule `user` sur `null`
// instantanément et `ProtectedRoute` redirige vers /login dans le même
// rendu : un cut sec depuis n'importe quelle page, sans transition (demande
// explicite de l'utilisateur). Non interactif — pas de bouton "continuer"
// comme WelcomeOverlay, la déconnexion est déjà décidée, il n'y a rien à
// confirmer une deuxième fois.
const HOLD_MS = 550
const EXIT_MS = 380

export default function LogoutOverlay({ onExitStart, onDone }) {
  const [exiting, setExiting] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => {
      setExiting(true)
      onExitStart?.()
      setTimeout(() => onDone?.(), EXIT_MS)
    }, HOLD_MS)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className={`welcome-overlay${exiting ? ' welcome-overlay-exit' : ''}`} style={{ background: 'var(--bg-app)' }}>
      <div className="home-glow" />
      <div className="relative z-10 flex flex-col items-center text-center">
        <CbrLogoTile size={56} rounded={18} className="brand-pop mb-3" />
        <p className="logout-text text-sm" style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Déconnexion…
        </p>
      </div>
    </div>
  )
}
