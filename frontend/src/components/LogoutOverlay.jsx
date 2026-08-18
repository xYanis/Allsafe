import { useEffect, useState } from 'react'
import { CbrLogoTile } from './CbrMark.jsx'

// Écran de transition affiché à la déconnexion — pendant du WelcomeOverlay
// (post-login) côté sortie. Sans lui, `logout()` bascule `user` sur `null`
// instantanément et `ProtectedRoute` redirige vers /login dans le même
// rendu : un cut sec depuis n'importe quelle page, sans transition (demande
// explicite de l'utilisateur). Non interactif — pas de bouton "continuer"
// comme WelcomeOverlay, la déconnexion est déjà décidée, il n'y a rien à
// confirmer une deuxième fois.
// Logo en grand + wordmark dégradé dessous (18/08/2026, demande explicite :
// "la même chose en terme d'animation" que le splash d'ouverture de Login.jsx)
// — mêmes classes partagées (`brand-splash-title`/`brand-splash-exit`, cf.
// index.css) et mêmes durées : connexion et déconnexion sont toutes deux des
// écrans "une fois par session", pas une UI vue en boucle, le même temps de
// pose est justifié des deux côtés.
const HOLD_MS = 2600
const EXIT_MS = 550

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
      <div className="relative z-10 flex flex-col items-center gap-4 text-center">
        <CbrLogoTile size={96} rounded={26} className="brand-pop" />
        <p className="brand-splash-title text-3xl font-bold tracking-tight" style={{ fontFamily: 'var(--font-mono)', animationDelay: '650ms' }}>
          Déconnexion…
        </p>
      </div>
    </div>
  )
}
