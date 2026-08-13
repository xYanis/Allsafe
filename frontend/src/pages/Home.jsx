import { useEffect, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { MODULES } from '../constants/modules.js'
import { useAuth } from '../contexts/AuthContext.jsx'
import { canAccessPage } from '../utils/pageAccess.js'
import WelcomeOverlay from '../components/WelcomeOverlay.jsx'
import { CbrLogoTile } from '../components/CbrMark.jsx'

const ARROW = (
  <svg className="home-arrow w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5-5 5M6 12h12" />
  </svg>
)

const HOME_MODULES = [
  {
    to: '/dashboard', label: 'CyberVuln', color: MODULES.cybervuln.color, moduleKey: 'cybervuln',
    desc: 'Gestion de vulnérabilités — Dashboard, actifs, CVE',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>,
  },
  {
    to: '/incidents', label: 'Incidents', color: MODULES.incidents.color, moduleKey: 'incidents',
    desc: 'Registre d\'incidents — suivi des délais légaux de notification NIS 2',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 18a3.75 3.75 0 00.495-7.468 5.99 5.99 0 00-1.925 3.547 5.975 5.975 0 01-2.133-1.001A3.75 3.75 0 0012 18z" /></svg>,
  },
  {
    to: '/veille', label: 'CyberVeille', color: MODULES.cyberveille.color, moduleKey: 'cyberveille',
    desc: 'Veille technologique NIS 2 + surveillance identités',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  },
  {
    to: '/inventaire', label: 'Inventaire', color: MODULES.inventaire.color, moduleKey: 'inventaire',
    desc: 'Patrimoine IT — specs matérielles et applications installées par actif',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" /></svg>,
  },
  {
    to: '/audits', label: 'Sécurité', color: MODULES.securite.color, moduleKey: 'securite', soon: true,
    desc: 'Audits, Bastion — audits de sécurité et accès serveurs critiques',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
  },
  {
    to: '/documentation', label: 'Documentation', color: MODULES.documentation.color, moduleKey: 'documentation',
    desc: 'Gouvernance NIS 2 (PSSI, chartes, organigramme) + prise de notes personnelle',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>,
  },
  {
    to: '/reports', label: 'Rapports', color: MODULES.rapports.color, moduleKey: 'rapports',
    desc: 'Rapport exécutif CVE, rapport Veille, rapport Surveillance',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>,
  },
  {
    to: '/settings', label: 'Paramètres', color: MODULES.parametres.color, moduleKey: 'parametres',
    desc: 'Réglages généraux — thème, sécurité, administration',
    icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  },
]

// Cadence de la cascade, en deux temps bien distincts (demande explicite, 11/08/2026) : logo +
// titre d'abord (0-210ms, cf. en-tête ci-dessous), un vrai temps de pause, PUIS les tuiles —
// contrairement à l'ancien réglage (260ms) qui les faisait démarrer avant même que le titre ait
// fini d'apparaître, les deux temps se lisaient comme un seul mouvement plutôt que deux étapes.
const TILE_BASE_DELAY = 520

// Spotlight à inertie : le gradient (::after) rattrape le curseur avec un léger
// retard (lissage exponentiel), effet plus « vivant » qu'un suivi instantané.
// État par tuile dans une WeakMap ; boucle rAF qui s'arrête une fois stabilisée
// (pas de boucle permanente). Écriture directe sur la tuile → aucun re-render.
const _spot = new WeakMap()

function _tick(t) {
  const s = _spot.get(t)
  if (!s) return
  const k = 0.16   // 0..1 : plus petit = plus d'inertie
  s.cx += (s.tx - s.cx) * k
  s.cy += (s.ty - s.cy) * k
  t.style.setProperty('--mx', `${s.cx}px`)
  t.style.setProperty('--my', `${s.cy}px`)
  if (Math.abs(s.tx - s.cx) > 0.5 || Math.abs(s.ty - s.cy) > 0.5) {
    s.raf = requestAnimationFrame(() => _tick(t))
  } else { s.raf = 0 }
}

function handleMove(e) {
  const t = e.currentTarget
  const r = t.getBoundingClientRect()
  const tx = e.clientX - r.left
  const ty = e.clientY - r.top
  let s = _spot.get(t)
  if (!s) {   // 1er mouvement : on démarre pile sous le curseur (pas de saut)
    s = { cx: tx, cy: ty, tx, ty, raf: 0 }
    _spot.set(t, s)
    t.style.setProperty('--mx', `${tx}px`)
    t.style.setProperty('--my', `${ty}px`)
  }
  s.tx = tx; s.ty = ty
  if (!s.raf) s.raf = requestAnimationFrame(() => _tick(t))
}

function handleLeave(e) {
  const t = e.currentTarget
  const s = _spot.get(t)
  if (s && s.raf) cancelAnimationFrame(s.raf)
  _spot.delete(t)   // prochaine entrée : re-init sous le curseur
}

export default function Home() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user } = useAuth()
  // Une seule fois par connexion (state de navigation posé par Login.jsx, pas de
  // sessionStorage) — réservé au compte admin pour l'instant. Lu une fois via
  // l'initialiseur paresseux de useState, puis le state est effacé ci-dessous
  // pour qu'un rechargement de la page Home ne le rejoue pas.
  const [showWelcome, setShowWelcome] = useState(() => Boolean(location.state?.justLoggedIn && user?.role === 'admin'))
  // Tant que l'écran de bienvenue n'a pas commencé à se retirer, l'en-tête/les tuiles ne sont
  // pas encore montés : sans ça, leur cascade d'entrée jouerait pendant que l'écran de bienvenue
  // est encore affiché, et sa disparition (fondu + flou) révélerait une Home déjà figée/statique
  // plutôt qu'une vraie transition animée entre les deux écrans. `homeReady` bascule au tout
  // début du fondu de sortie (`onExitStart`, avant `onDone`) : les deux animations se chevauchent.
  const [homeReady, setHomeReady] = useState(() => !showWelcome)

  // Restriction de modules (31/07/2026, cf. models.py::User.allowed_pages) — une tuile dont
  // aucune page du module n'est autorisée disparaît ; sinon on route vers la première page
  // accessible du module plutôt que `m.to` en dur (qui peut être précisément la page interdite).
  const visibleModules = HOME_MODULES
    .map(m => ({ ...m, accessiblePaths: (MODULES[m.moduleKey]?.paths || [m.to]).filter(p => canAccessPage(user, p)) }))
    .filter(m => m.accessiblePaths.length > 0)

  useEffect(() => {
    if (location.state?.justLoggedIn) {
      navigate(location.pathname, { replace: true, state: {} })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-start pt-14 sm:pt-20 p-6 overflow-hidden" style={{ background: 'var(--bg-app)' }}>
      {showWelcome && (
        <WelcomeOverlay onExitStart={() => setHomeReady(true)} onDone={() => setShowWelcome(false)} />
      )}
      <div className="hero-grid" />
      <div className="home-glow home-glow--high" />

      {!homeReady ? null : (
      <>
      {/* En-tête */}
      <div className="relative z-10 flex flex-col items-center text-center mb-10 sm:mb-14">
        <CbrLogoTile size={56} rounded={18} className="home-logo mb-3" />
        <h1 className="home-enter text-4xl font-bold tracking-tight" style={{
          fontFamily: 'var(--font-mono)',
          backgroundImage: 'var(--brand-text-grad)', WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent',
          animationDelay: '90ms',
        }}>Allsafe</h1>
        <p className="home-enter text-sm mt-1.5" style={{ color: 'var(--text-secondary)', animationDelay: '150ms' }}>
          Plateforme cybersécurité
        </p>
        <p className="home-enter text-xs mt-2.5" style={{ color: 'var(--text-muted)', animationDelay: '210ms' }}>
          Sélectionnez un module pour commencer
        </p>
      </div>

      {/* Tuiles modules — 4 colonnes dès lg : les tuiles tiennent en 2 rangées (4+2)
          au lieu de 3 rangées, qui laissait la dernière tuile isolée et souvent
          coupée par la hauteur de viewport (cf. demande utilisateur, sans scroll). */}
      <div className="relative z-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full max-w-5xl">
        {visibleModules.map((m, i) => (
          <button
            key={m.to}
            onClick={() => navigate(m.accessiblePaths[0])}
            onMouseMove={handleMove}
            onMouseLeave={handleLeave}
            className="home-tile home-enter text-left p-4 rounded-2xl"
            style={{
              '--tile': m.color,
              animationDelay: `${TILE_BASE_DELAY + i * 55}ms`,
            }}
          >
            <div className="flex items-start justify-between mb-3">
              <div className="home-icon w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: `${m.color}22`, color: m.color }}>
                {m.icon}
              </div>
              <span style={{ color: m.color }}>{ARROW}</span>
            </div>
            <div className="flex items-center gap-2 mb-1">
              <p className="font-semibold text-sm" style={{ color: m.color }}>{m.label}</p>
              {m.soon && (
                <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                  Bientôt
                </span>
              )}
            </div>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>{m.desc}</p>
          </button>
        ))}
      </div>
      </>
      )}
    </div>
  )
}
