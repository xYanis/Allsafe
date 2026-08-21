import { useState, useEffect } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { securityEventsCount, incidentsPendingCount } from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'
import { canAccessPage } from '../utils/pageAccess.js'
import ErrorBoundary from './ErrorBoundary.jsx'
import { MODULES } from '../constants/modules.js'
import { CbrLogoTile } from './CbrMark.jsx'
import PageGuide from './PageGuide.jsx'

const ICONS = {
  dashboard: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>,
  vulns:     <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>,
  assets:    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" /></svg>,
  cve:       <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>,
  reports:   <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>,
  veille:    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  inventory: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" /></svg>,
  audits:    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
  bastion:   <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" /></svg>,
  agents:    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" /></svg>,
  durcissement: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 13.5V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m12-12V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m-6-9V3.75m0 3.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 9.75V10.5" /></svg>,
  documentation: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>,
  notes: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" /></svg>,
  admin:     <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.982 18.725A7.488 7.488 0 0012 15.75a7.488 7.488 0 00-5.982 2.975m11.964 0a9 9 0 10-11.964 0m11.964 0A8.966 8.966 0 0112 21a8.966 8.966 0 01-5.982-2.275M15 9.75a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  settings:  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  releaseNotes: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z" /></svg>,
  identity:  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 9h3.75M15 12h3.75M15 15h3.75M4.5 19.5h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5zm6-10.125a1.875 1.875 0 11-3.75 0 1.875 1.875 0 013.75 0zm1.294 6.336a6.721 6.721 0 01-3.17.789 6.721 6.721 0 01-3.168-.789 3.376 3.376 0 016.338 0z" /></svg>,
  leak:      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" /></svg>,
  incident:  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18a3.75 3.75 0 00.495-7.468 5.99 5.99 0 00-1.925 3.547 5.975 5.975 0 01-2.133-1.001A3.75 3.75 0 0012 18z" /></svg>,
  crisis:    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m9.303 3.376c.866 1.5-.217 3.374-1.948 3.374H4.645c-1.73 0-2.813-1.874-1.948-3.374L10.697 3.376c.866-1.5 3.032-1.5 3.898 0l7.303 12.75zM12 15.75h.007v.008H12v-.008z" /></svg>,
  chevronLeft:  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.75 19.5L8.25 12l7.5-7.5" /></svg>,
  chevronRight: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.25 4.5l7.5 7.5-7.5 7.5" /></svg>,
  menu:  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.75 6.75h16.5M3.75 12h16.5M3.75 17.25h16.5" /></svg>,
  close: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>,
}

const LOGO_ACCENT = 'var(--brand)'

// Chaque module de premier niveau (cf. Home.jsx) a désormais son propre
// sous-groupe dans la nav, même s'il n'a qu'un seul sous-item pour l'instant
// (Inventaire, Sécurité) — prêt à en accueillir d'autres plus tard sans redesign.
// Seul Paramètres reste un lien simple sans en-tête de groupe. Couleurs alignées
// sur les tuiles de la page d'accueil (Home.jsx).
const NAV_GROUPS = [
  {
    label: 'CyberVuln',
    color: MODULES.cybervuln.color,
    moduleKey: 'cybervuln',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: ICONS.dashboard },
      { to: '/vulnerabilities', label: 'Vulnérabilités', icon: ICONS.vulns },
      { to: '/cves', label: 'CVE', icon: ICONS.cve },
    ],
  },
  {
    label: 'Incidents',
    color: MODULES.incidents.color,
    moduleKey: 'incidents',
    items: [
      { to: '/incidents', label: 'Registre incidents', icon: ICONS.incident },
      { to: '/crises', label: 'Gestion de crise', icon: ICONS.crisis },
    ],
  },
  {
    label: 'CyberVeille',
    color: MODULES.cyberveille.color,
    moduleKey: 'cyberveille',
    items: [
      { to: '/veille', label: 'Veille technologique', icon: ICONS.veille },
      { to: '/fuite-de-donnees', label: 'Fuite de données', icon: ICONS.leak },
      { to: '/surveillance-identites', label: 'Surveillance Identités', icon: ICONS.identity },
    ],
  },
  {
    label: 'Inventaire',
    color: MODULES.inventaire.color,
    moduleKey: 'inventaire',
    items: [
      { to: '/assets', label: 'Actifs', icon: ICONS.assets },
      { to: '/inventaire', label: 'Inventaire Complet', icon: ICONS.inventory },
      { to: '/durcissement', label: 'Durcissement', icon: ICONS.durcissement },
      { to: '/agents', label: 'Agents', icon: ICONS.agents },
    ],
  },
  {
    label: 'Sécurité',
    color: MODULES.securite.color,
    moduleKey: 'securite',
    items: [
      { to: '/audits', label: 'Audits', icon: ICONS.audits },
      { to: '/bastion', label: 'Bastion', icon: ICONS.bastion },
    ],
  },
  {
    // Ex-« Documentation », renommé « Gouvernance » le 18/08/2026 (demande utilisateur) — la
    // sous-page "Documentation Entreprise" garde son nom, cohérent sous ce module (documents de
    // gouvernance NIS 2). Cf. constants/modules.js pour le détail du renommage.
    label: 'Gouvernance',
    color: MODULES.documentation.color,
    moduleKey: 'documentation',
    items: [
      { to: '/documentation', label: 'Documentation Entreprise', icon: ICONS.documentation },
      { to: '/notes', label: 'Notes', icon: ICONS.notes },
    ],
  },
  {
    label: 'Rapports',
    color: MODULES.rapports.color,
    moduleKey: 'rapports',
    items: [
      { to: '/reports', label: 'Rapport exécutif CVE', icon: ICONS.reports },
      { to: '/rapport-veille', label: 'Rapport Veille', icon: ICONS.reports },
      { to: '/rapport-surveillance', label: 'Rapport Surveillance', icon: ICONS.reports },
      { to: '/rapport-incidents', label: 'Rapport Incidents', icon: ICONS.reports },
    ],
  },
  {
    label: null,
    moduleKey: 'parametres',
    items: [
      { to: '/settings', label: 'Paramètres', icon: ICONS.settings, color: MODULES.parametres.color },
    ],
  },
  // Détaché de Paramètres (18/08/2026, demande explicite) — module à part entière, juste en
  // dessous de Paramètres. Même schéma "lien simple sans en-tête de groupe" que Paramètres
  // ci-dessus (un seul sous-item).
  {
    label: null,
    moduleKey: 'notesDeVersion',
    items: [
      { to: '/notes-de-version', label: 'Notes de version', icon: ICONS.releaseNotes, color: MODULES.notesDeVersion.color },
    ],
  },
]

// Badge de notification rouge (nombre). En mode réduit, se pose sur l'icône ;
// déplié, aligné à droite de l'item. Utilisé pour signaler des alertes de
// sécurité non acquittées sur l'item Paramètres (cf. Layout).
function NotifBadge({ count, floating }) {
  if (!count) return null
  const base = {
    background: '#f85149', color: '#fff', fontSize: 10, fontWeight: 700,
    minWidth: 16, height: 16, borderRadius: 8, padding: '0 5px',
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1,
  }
  const style = floating
    ? { ...base, position: 'absolute', top: -5, right: -7, boxShadow: '0 0 0 2px var(--bg-card)' }
    : { ...base, marginLeft: 'auto' }
  return <span style={style}>{count > 9 ? '9+' : count}</span>
}

function NavItem({ to, label, icon, collapsed, color, badge = 0 }) {
  return (
    <NavLink
      to={to}
      end
      title={collapsed && badge > 0 ? `${label} — ${badge} alerte${badge > 1 ? 's' : ''}` : (collapsed ? label : undefined)}
      className={({ isActive }) =>
        `nav-item ${collapsed ? 'nav-item-collapsed' : ''} flex items-center ${collapsed ? 'justify-center px-0' : 'gap-3 px-3'} py-2.5 text-sm rounded-lg mb-0.5 ${
          isActive ? 'active-nav' : 'inactive-nav'
        }`
      }
      style={({ isActive }) => isActive
        ? { '--nav': color, background: `${color}26`, color }
        : { '--nav': color, color }
      }
    >
      {({ isActive }) => (
        <>
          {/* Icône toujours teintée de la couleur du module — pas seulement à la
              sélection — pour servir de repère visuel constant dans la nav. */}
          <span className="flex-shrink-0 relative" style={{ color }}>
            {icon}
            {collapsed && <NotifBadge count={badge} floating />}
          </span>
          {!collapsed && label}
          {!collapsed && <NotifBadge count={badge} />}
        </>
      )}
    </NavLink>
  )
}

// En dessous de md (768px), la sidebar devient un tiroir plein écran (fixed +
// backdrop) plutôt qu'une colonne toujours visible qui mangerait la moitié
// d'un écran de téléphone. `collapsed` (préférence desktop persistée) et
// `isDesktop` (media query, redéterminé au resize) se combinent en
// `effectiveCollapsed` : le mode icône seule n'a de sens qu'en colonne fixe
// desktop — sur mobile le tiroir affiche toujours les libellés complets,
// même si l'utilisateur avait replié la sidebar sur un usage desktop
// antérieur dans le même navigateur.
export default function Layout() {
  const location = useLocation()
  const { user } = useAuth()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar_collapsed') === 'true')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [isDesktop, setIsDesktop] = useState(() => window.matchMedia('(min-width: 768px)').matches)
  // Restriction de modules (31/07/2026, cf. models.py::User.allowed_pages) — un groupe dont
  // aucune page n'est autorisée disparaît entièrement de la nav plutôt que de rester vide.
  const visibleGroups = NAV_GROUPS
    .map(group => ({ ...group, items: group.items.filter(item => canAccessPage(user, item.to)) }))
    .filter(group => group.items.length > 0)
  const hasIncidentsAccess = canAccessPage(user, '/incidents')

  // Badge d'alertes de sécurité (déception) sur l'item Paramètres : poll léger du
  // compteur (nombre seul, aucun détail — le détail reste derrière le mot de passe
  // dans Paramètres > Sécurité > Administration). Masqué en mode Présentation.
  const { isAnonymous } = usePresentation()
  const [securityCount, setSecurityCount] = useState(0)
  useEffect(() => {
    if (isAnonymous) { setSecurityCount(0); return }
    let alive = true
    const load = () => securityEventsCount()
      .then(r => { if (alive) setSecurityCount(r.data.unacknowledged || 0) })
      .catch(() => {})
    load()
    const t = setInterval(load, 30000)
    return () => { alive = false; clearInterval(t) }
  }, [isAnonymous])

  // Badge d'échéances NIS 2 sur l'item Incidents : dépassées + imminentes (< 24h),
  // même mécanique de poll léger que le badge Paramètres ci-dessus.
  const [nis2Count, setNis2Count] = useState(0)
  useEffect(() => {
    if (isAnonymous || !hasIncidentsAccess) { setNis2Count(0); return }
    let alive = true
    const load = () => incidentsPendingCount()
      .then(r => { if (alive) setNis2Count((r.data.overdue || 0) + (r.data.imminent || 0)) })
      .catch(() => {})
    load()
    const t = setInterval(load, 30000)
    return () => { alive = false; clearInterval(t) }
  }, [isAnonymous, hasIncidentsAccess])

  useEffect(() => {
    const mq = window.matchMedia('(min-width: 768px)')
    const handler = e => setIsDesktop(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  const effectiveCollapsed = collapsed && isDesktop

  function toggleCollapsed() {
    setCollapsed(c => {
      const next = !c
      localStorage.setItem('sidebar_collapsed', next ? 'true' : 'false')
      return next
    })
  }

  return (
    <div className="flex h-screen" style={{ background: 'var(--bg-app)' }}>
      {/* Fond assombri derrière le tiroir mobile — ferme au clic, jamais affiché en desktop */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar — colonne fixe en desktop, tiroir plein écran en dessous de md */}
      <aside
        className={`fixed md:static inset-y-0 left-0 z-50 ${effectiveCollapsed ? 'w-16' : 'w-60'} flex-shrink-0 flex flex-col transform ${mobileOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0`}
        style={{ background: 'var(--bg-card)', borderRight: '1px solid var(--border)', transition: 'width 0.15s ease, transform 0.2s ease' }}
      >
        <div className={effectiveCollapsed ? 'px-3 py-5' : 'px-5 py-5'} style={{ borderBottom: '1px solid var(--border)' }}>
          <div className={`flex items-center ${effectiveCollapsed ? 'justify-center' : 'justify-between'}`}>
            <Link to="/" className="flex items-center gap-2.5" title={effectiveCollapsed ? 'Allsafe' : undefined} onClick={() => setMobileOpen(false)}>
              <CbrLogoTile size={36} rounded={10} />
              {!effectiveCollapsed && <span className="font-bold text-base" style={{ color: LOGO_ACCENT, fontFamily: 'var(--font-mono)', letterSpacing: '0.02em' }}>Allsafe</span>}
            </Link>
            <div className="flex items-center gap-1">
              {!effectiveCollapsed && (
                <button
                  onClick={toggleCollapsed}
                  title="Réduire la sidebar"
                  className="hidden md:inline-flex p-1 rounded-md flex-shrink-0 transition-colors"
                  style={{ color: 'var(--text-muted)' }}
                  onMouseEnter={e => e.currentTarget.style.color = 'var(--text-secondary)'}
                  onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
                >
                  {ICONS.chevronLeft}
                </button>
              )}
              <button
                onClick={() => setMobileOpen(false)}
                title="Fermer le menu"
                className="md:hidden p-1 rounded-md flex-shrink-0"
                style={{ color: 'var(--text-muted)' }}
              >
                {ICONS.close}
              </button>
            </div>
          </div>
          {!effectiveCollapsed && <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>Plateforme cybersécurité</p>}
        </div>

        {effectiveCollapsed && (
          <div className="flex justify-center py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
            <button
              onClick={toggleCollapsed}
              title="Agrandir la sidebar"
              className="p-1 rounded-md transition-colors"
              style={{ color: 'var(--text-muted)' }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--text-secondary)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
            >
              {ICONS.chevronRight}
            </button>
          </div>
        )}

        <nav className="sidebar-scroll flex-1 py-3 px-2 overflow-y-auto" onClick={() => setMobileOpen(false)}>
          {visibleGroups.map((group, i) => (
            <div key={group.label || `group-${i}`} className={i > 0 ? 'mt-4 pt-4' : ''} style={i > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
              {group.label && !effectiveCollapsed && (
                <p className="px-3 mb-1.5 text-[11px] font-semibold uppercase tracking-wider" style={{ color: group.color }}>
                  {group.label}
                </p>
              )}
              {group.items.map(item => <NavItem key={item.to} {...item} color={item.color || group.color} collapsed={effectiveCollapsed}
                badge={item.to === '/settings' ? securityCount : item.to === '/incidents' ? nis2Count : 0} />)}
            </div>
          ))}
        </nav>

        <div className={effectiveCollapsed ? 'px-3 py-4' : 'px-5 py-4'} style={{ borderTop: '1px solid var(--border)' }}>
          <div className={`flex items-center gap-2 ${effectiveCollapsed ? 'justify-center' : ''}`} title={effectiveCollapsed ? 'Services opérationnels' : undefined}>
            <span className="w-2 h-2 rounded-full bg-green-400 inline-block flex-shrink-0"></span>
            {!effectiveCollapsed && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Services opérationnels</span>}
          </div>
        </div>
      </aside>

      {/* Colonne principale */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Barre mobile — hamburger, masquée en desktop où la sidebar est toujours visible */}
        <div className="md:hidden flex items-center justify-between px-4 py-3 flex-shrink-0" style={{ background: 'var(--bg-card)', borderBottom: '1px solid var(--border)' }}>
          <button onClick={() => setMobileOpen(true)} aria-label="Ouvrir le menu" className="p-1.5 rounded-md" style={{ color: 'var(--text-secondary)' }}>
            {ICONS.menu}
          </button>
          <Link to="/" className="flex items-center gap-2">
            <CbrLogoTile size={32} rounded={9} />
            <span className="font-bold text-sm" style={{ color: LOGO_ACCENT, fontFamily: 'var(--font-mono)', letterSpacing: '0.02em' }}>Allsafe</span>
          </Link>
          <div className="w-8 flex-shrink-0" />
        </div>

        <main className="main-scroll flex-1 overflow-y-auto">
          {/* Transition d'entrée légère à chaque changement de page : la clé sur
              le chemin fait rejouer l'animation. Court (180 ms) et discret — la
              nav est fréquente, on reste sous le seuil du « ça rame ». */}
          <div key={location.pathname} className="route-fade">
            <ErrorBoundary>
              <Outlet />
            </ErrorBoundary>
          </div>
        </main>
      </div>

      {/* Guide pas à pas flottant (bas-droite), un par page selon la route — cf.
          components/PageGuide.jsx + constants/pageGuides.js. Masquable globalement
          depuis Paramètres > Apparence. */}
      <PageGuide />
    </div>
  )
}
