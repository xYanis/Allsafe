import { useNavigate } from 'react-router-dom'
import { useTheme } from '../contexts/ThemeContext.jsx'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }

function Switch({ checked, onChange, ariaLabel }) {
  return (
    <button
      onClick={onChange}
      aria-label={ariaLabel}
      style={{
        width: 44, height: 24, borderRadius: 12, padding: 2, border: 'none', cursor: 'pointer',
        background: checked ? 'var(--accent-blue)' : '#d0d7de', transition: 'background 0.2s',
        display: 'flex', alignItems: 'center',
      }}
    >
      <span style={{
        width: 20, height: 20, borderRadius: '50%', background: '#fff', display: 'block',
        transform: checked ? 'translateX(20px)' : 'translateX(0)', transition: 'transform 0.2s',
        boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </button>
  )
}

// Ligne « Administration » : mène à une page dédiée (réservée admin, cf. ProtectedRoute
// dans App.jsx), onglets Connexions IP / Base de données / Utilisateurs / Analystes.
function AdministrationRow() {
  const navigate = useNavigate()
  // #f85149 sur un fond clair tombe sous le seuil WCAG AA (~3:1) — repéré en tour UX
  // (03/08/2026). Rouge assombri en mode clair uniquement (même convention rouge
  // "danger" que le reste de l'app, juste recalibrée pour rester lisible sur blanc ;
  // #f85149 inchangé en mode sombre, où il reste conforme).
  const { isDark } = useTheme()
  const dangerColor = isDark ? '#f85149' : '#cf222e'
  const dangerBg     = isDark ? 'rgba(248,81,73,0.1)'  : 'rgba(207,34,46,0.08)'
  const dangerBorder = isDark ? 'rgba(248,81,73,0.2)'  : 'rgba(207,34,46,0.25)'
  return (
    <button onClick={() => navigate('/settings/administration')}
      style={CARD} className="w-full p-5 flex items-center gap-3 text-left transition-colors"
      onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.04)'}
      onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-card)'}
    >
      <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: dangerBg, border: `1px solid ${dangerBorder}` }}>
        <svg className="w-4 h-4" style={{ color: dangerColor }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Administration</p>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Connexions IP, base de données, comptes et analystes — accès réservé admin</p>
      </div>
      <svg className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
    </button>
  )
}

export default function Settings() {
  const { isDark, toggle } = useTheme()
  const { isAnonymous, toggle: toggleAnonymous } = usePresentation()
  const { user, logout } = useAuth()
  // Cf. AdministrationRow ci-dessus pour le pourquoi (contraste #f85149 sur fond clair).
  const dangerColor = isDark ? '#f85149' : '#cf222e'
  const dangerBg     = isDark ? 'rgba(248,81,73,0.1)'  : 'rgba(207,34,46,0.08)'
  const dangerBorder = isDark ? 'rgba(248,81,73,0.2)'  : 'rgba(207,34,46,0.25)'

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Paramètres</h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>Configuration de CyberVuln</p>
      </div>

      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>Présentation</h2>
        <div style={CARD} className="p-5 flex items-center justify-between">
          <div>
            <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Anonyme</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {isAnonymous
                ? 'Activé — noms d\'actifs, IP et analystes remplacés par des données fictives, parc complété par des actifs de démonstration'
                : 'Désactivé — données réelles affichées'}
            </p>
          </div>
          <Switch checked={isAnonymous} onChange={toggleAnonymous} ariaLabel="Basculer le mode Anonyme" />
        </div>
      </section>

      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>Apparence</h2>
        <div style={CARD} className="p-5 flex items-center justify-between">
          <div>
            <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Thème</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {isDark ? 'Mode sombre' : 'Mode clair'}
            </p>
          </div>
          <Switch checked={isDark} onChange={toggle} ariaLabel="Basculer le thème" />
        </div>
      </section>

      {user?.role === 'admin' && (
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>Sécurité</h2>
          <AdministrationRow />
        </section>
      )}

      {user && (
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>Compte</h2>
          <div style={CARD} className="p-5 flex items-center justify-between">
            <div>
              <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{user.full_name}</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{user.email}</p>
            </div>
            <button onClick={logout}
              className="text-sm px-4 py-2 rounded-lg font-medium transition-colors"
              style={{ background: dangerBg, color: dangerColor, border: `1px solid ${dangerBorder}` }}
              onMouseEnter={e => e.currentTarget.style.background = isDark ? 'rgba(248,81,73,0.18)' : 'rgba(207,34,46,0.14)'}
              onMouseLeave={e => e.currentTarget.style.background = dangerBg}
            >Se déconnecter</button>
          </div>
        </section>
      )}
    </div>
  )
}
