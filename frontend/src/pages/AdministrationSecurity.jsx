import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import {
  getConnections, getUserConnections, securityEvents, ackSecurityEvent, ackAllSecurityEvents,
  users as fetchUsers, createUser, updateUser, deleteUser, revokeUserSessions,
  passwordResetRequests as fetchPasswordResetRequests, passwordResetRequestsCount,
  resolvePasswordResetRequest, dismissPasswordResetRequest,
  createAnalyst, updateAnalyst, deleteAnalyst,
  organizationRoles as fetchOrganizationRoles, createOrganizationRole, updateOrganizationRole, deleteOrganizationRole,
  services as fetchServices, createService, updateService, deleteService,
  windowsAppMappings as fetchWindowsAppMappings, createWindowsAppMapping, updateWindowsAppMapping, deleteWindowsAppMapping,
} from '../api/client.js'
import { anonymizeConnection, anonymizeUserConnection, anonymizeRoleHolder, anonymizeValidator } from '../utils/fakeData.js'
import PageLoader from '../components/PageLoader.jsx'
import DeclareIncidentButton from '../components/DeclareIncidentButton.jsx'
import UserFormModal from '../components/UserFormModal.jsx'
import ResolvePasswordResetModal from '../components/ResolvePasswordResetModal.jsx'
import AnalystFormModal from '../components/AnalystFormModal.jsx'
import OrganizationRoleFormModal from '../components/OrganizationRoleFormModal.jsx'
import ServiceFormModal from '../components/ServiceFormModal.jsx'
import ServiceOrgChartModal from '../components/ServiceOrgChartModal.jsx'
import WindowsAppMappingFormModal from '../components/WindowsAppMappingFormModal.jsx'
import { SERVICE_COLOR_PALETTE } from '../constants/serviceColors.js'
import ServiceIcon from '../components/ServiceIcon.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import PageHero from '../components/PageHero.jsx'
import { tintedCard } from '../utils/cardStyle.js'

const MODULE_COLOR = '#fb8f44' // orange Administration (demande utilisateur, 19/08/2026) — diverge
// volontairement du gris #8b949e de Paramètres : reprend l'orange déjà utilisé sur cette page (boutons
// « + Ajouter » d'Utilisateurs/Analystes/Services), pour thémer hero + nav + carte + filtres d'un seul point.
const CARD = tintedCard(MODULE_COLOR)
const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
const activeFilterSelectStyle = { background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }

// Icônes de la nav d'Administration — même famille (Heroicons outline, viewBox 24,
// strokeWidth cohérent) que ICONS dans Layout.jsx, dupliquées localement plutôt
// qu'importées : ce fichier n'a pas besoin du reste du set de la sidebar.
const TAB_ICON_PATHS = {
  database: 'M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75',
  connections: 'M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z',
  users: 'M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z',
  analysts: 'M15 9h3.75M15 12h3.75M15 15h3.75M4.5 19.5h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5zm6-10.125a1.875 1.875 0 11-3.75 0 1.875 1.875 0 013.75 0zm1.294 6.336a6.721 6.721 0 01-3.17.789 6.721 6.721 0 01-3.168-.789 3.376 3.376 0 016.338 0z',
  services: 'M2.25 21h19.5m-18-18v18m10.5-18v18m6-13.5V21M6.75 6.75h.75m-.75 3h.75m-.75 3h.75m3-6h.75m-.75 3h.75m-.75 3h.75M6.75 21v-3.375c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21m4.5 0v-3.375c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21',
  roles: 'M7.217 10.907a2.25 2.25 0 100 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186l9.566-5.314m-9.566 7.5l9.566 5.314m0 0a2.25 2.25 0 103.933 2.185 2.25 2.25 0 00-3.933-2.185zm0-12.814a2.25 2.25 0 103.933-2.185 2.25 2.25 0 00-3.933 2.185z',
  'windows-mappings': 'M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25',
}

function TabIcon({ name }) {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={TAB_ICON_PATHS[name]} />
    </svg>
  )
}

function fmtDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function Loader() {
  return (
    <div className="py-4">
      <PageLoader size="sm" />
    </div>
  )
}

// ─── Boilerplate CRUD partagé par les onglets à liste simple (Services/Rôles/Correspondances
// Windows) — même charpente partout : liste chargée au montage, modale de formulaire
// (null | 'new' | item édité), confirmation de suppression, message d'erreur d'action. Séparé
// en deux hooks : le chargement (générique tant qu'un seul endpoint suffit — ServicesTab, qui
// en croise deux avec les rôles, garde son propre `load` mais réutilise useCrudModals) et les
// modales de mutation (identiques partout, y compris pour ServicesTab).
function useLoadList(fetchFn, errorMessage) {
  const [list, setList] = useState(null)
  const [error, setError] = useState('')

  function load() {
    fetchFn().then(r => { setList(r.data.items || []); setError('') })
      .catch(() => { setList([]); setError(errorMessage) })
  }
  useEffect(() => { load() }, [])

  return { list, error, setError, load }
}

function useCrudModals({ createFn, updateFn, deleteFn, load, setError }) {
  const [formModal, setFormModal] = useState(null) // null | 'new' | item édité
  const [deleteTarget, setDeleteTarget] = useState(null)

  async function handleSave(payload) {
    if (formModal && formModal !== 'new') await updateFn(formModal.id, payload)
    else await createFn(payload)
    setFormModal(null)
    load()
  }

  async function confirmDelete() {
    try {
      await deleteFn(deleteTarget.id)
      setDeleteTarget(null)
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteTarget(null)
    }
  }

  return { formModal, setFormModal, deleteTarget, setDeleteTarget, handleSave, confirmDelete }
}

// ─── Onglet Connexion ───────────────────────────────────────────────────────────
// Fusionne deux journaux distincts en base (12/08/2026, demande utilisateur) — pas de
// fusion des modèles, juste de l'affichage : ConnectionLog (accès à l'app, anonyme, y
// compris avant authentification) et AuthAuditLog (connexion/déconnexion/échec par
// compte, cf. routers/connections.py). Triés ensemble par date décroissante.
const EVENT_BADGE = {
  LOGIN_SUCCESS:    { label: 'Connexion',          color: '#3fb950' },
  LOGIN_FAILED:     { label: 'Échec de connexion',  color: '#f85149' },
  LOGOUT:           { label: 'Déconnexion',         color: '#8b949e' },
  PASSWORD_CHANGED: { label: 'Mot de passe changé', color: '#58a6ff' },
  ACCESS:           { label: 'Accès',               color: '#8b949e' },
}

function shortUserAgent(ua) {
  return ua ? ua.replace(/\(.*?\)/g, '').trim().split(' ').slice(0, 3).join(' ') : '—'
}

function ConnectionsTab({ isAnonymous }) {
  const [entries, setEntries] = useState(null)
  const [loading, setLoading] = useState(true)
  // Bug réel corrigé (11/08/2026, même famille que l'incident ServicesTab du 31/07 —
  // cf. son commentaire plus bas) : un échec réseau était avalé silencieusement,
  // indiscernable de "aucune connexion enregistrée".
  const [error, setError] = useState('')

  // Filtres (12/08/2026, demande utilisateur) — appliqués côté client, la liste tient
  // déjà entièrement en mémoire (500 lignes max par source, cf. routers/connections.py).
  const [search, setSearch] = useState('')       // e-mail OU IP, sous-chaîne insensible à la casse
  const [typeFilter, setTypeFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  useEffect(() => {
    Promise.all([getConnections(), getUserConnections()])
      .then(([accessRes, loginRes]) => {
        const access = (accessRes.data || []).map(l => isAnonymous ? anonymizeConnection(l) : l)
          .map(l => ({ id: `access-${l.id}`, event_type: 'ACCESS', date: l.accessed_at, email: null, ip: l.ip, user_agent: l.user_agent }))
        const logins = (loginRes.data || []).map(l => isAnonymous ? anonymizeUserConnection(l) : l)
          .map(l => ({ id: `login-${l.id}`, event_type: l.event_type, date: l.created_at, email: l.email, ip: l.ip, user_agent: l.user_agent, details: l.details }))
        const merged = [...access, ...logins].sort((a, b) => new Date(b.date) - new Date(a.date))
        setEntries(merged)
        setError('')
      })
      .catch(() => { setEntries([]); setError('Impossible de charger le journal de connexions — le serveur a peut-être renvoyé une erreur.') })
      .finally(() => setLoading(false))
  }, [isAnonymous])

  if (loading) return <Loader />
  if (!entries) return null

  const q = search.trim().toLowerCase()
  const filtered = entries.filter(entry => {
    if (typeFilter && entry.event_type !== typeFilter) return false
    if (q && !(entry.email?.toLowerCase().includes(q) || entry.ip?.toLowerCase().includes(q))) return false
    if (dateFrom && new Date(entry.date) < new Date(dateFrom)) return false
    if (dateTo && new Date(entry.date) > new Date(dateTo)) return false
    return true
  })
  const filtersActive = q || typeFilter || dateFrom || dateTo

  return (
    <>
      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="E-mail ou IP…"
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={typeFilter ? activeFilterSelectStyle : filterSelectStyle}>
          <option value="">Tous types</option>
          {Object.entries(EVENT_BADGE).map(([key, b]) => <option key={key} value={key}>{b.label}</option>)}
        </select>
        <label className="text-xs flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
          Du
          <input type="datetime-local" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
            className="text-xs px-2 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
        </label>
        <label className="text-xs flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
          au
          <input type="datetime-local" value={dateTo} onChange={e => setDateTo(e.target.value)}
            className="text-xs px-2 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
        </label>
        {filtersActive && (
          <button onClick={() => { setSearch(''); setTypeFilter(''); setDateFrom(''); setDateTo('') }}
            className="text-xs px-2.5 py-1.5 rounded-lg font-medium" style={{ color: 'var(--text-muted)' }}>
            Réinitialiser
          </button>
        )}
      </div>

      <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
        {filtersActive
          ? `${filtered.length} résultat${filtered.length !== 1 ? 's' : ''} sur ${entries.length} entrée${entries.length !== 1 ? 's' : ''}`
          : `${entries.length} entrée${entries.length !== 1 ? 's' : ''} enregistrée${entries.length !== 1 ? 's' : ''}`}
      </p>
      {entries.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucune connexion enregistrée.</p>
      ) : filtered.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun résultat pour ces filtres.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['Date / Heure', 'Type', 'Utilisateur', 'Adresse IP', 'Navigateur'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(entry => {
                const badge = EVENT_BADGE[entry.event_type] || EVENT_BADGE.ACCESS
                const reason = entry.details?.reason
                return (
                  <tr key={entry.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.03)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{fmtDate(entry.date)}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${badge.color}22`, color: badge.color }}>
                        {badge.label}{reason === 'lockout' ? ' (verrou)' : reason === 'session_limit' ? ' (plafond)' : ''}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{entry.email || '—'}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.08)', color: '#58a6ff' }}>
                        {entry.ip || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs truncate max-w-xs" style={{ color: 'var(--text-muted)', maxWidth: 320 }} title={entry.user_agent}>
                      {shortUserAgent(entry.user_agent)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

// ─── Onglet Base de données (déception / administration) ───────────────────────
const EVENT_SOURCE = {
  honey_read:  { label: 'Lecture leurre',  color: '#f85149' },
  honey_write: { label: 'Écriture leurre', color: '#f85149' },
  decoy_role:  { label: 'Rôle leurre',     color: '#fb8f44' },
  ddl_attempt: { label: 'DDL bloquée',     color: '#a371f7' },
}

const OP_LABEL = { SELECT: 'lecture', INSERT: 'ajout', UPDATE: 'modification', DELETE: 'suppression' }

// Explication « grand public » d'une alerte : formulée pour qu'un non-technicien
// comprenne ce qui s'est passé, pourquoi c'est suspect, et quoi faire.
function explainEvent(e) {
  const who = e.db_user ? `le compte « ${e.db_user} »` : 'un compte de la base'
  const from = e.client_addr ? ` (adresse ${e.client_addr})` : ''
  const op = OP_LABEL[e.operation] || (e.operation || '').toLowerCase()
  switch (e.source) {
    case 'honey_read':
      return {
        title: 'Quelqu’un a fouillé une fausse table-piège',
        what: `${who}${from} a consulté « ${e.object_name} » — une fausse table qui imite des données sensibles (identifiants, mots de passe, clés d’API…). Ces pièges ne sont jamais utilisés par le logiciel Allsafe.`,
        why: `Un utilisateur ou un logiciel normal ne lit jamais cet objet. Cette lecture signifie que quelqu’un explore la base pour y trouver des secrets.`,
        reco: `À faire : identifier qui se cache derrière ce compte et cette adresse, puis couper l’accès si l’activité n’est pas légitime.`,
      }
    case 'honey_write':
      return {
        title: 'Quelqu’un a tenté de modifier un objet-piège',
        what: `${who}${from} a tenté une ${op} sur « ${e.object_name} », un objet-piège inutilisé par Allsafe. L’opération n’a eu aucun effet réel — elle a été absorbée par le piège.`,
        why: `Personne de légitime ne modifie cet objet. Une écriture ici trahit une manipulation volontaire de la base.`,
        reco: `À faire : traiter ce compte et cette adresse comme suspects et vérifier leurs autres actions.`,
      }
    case 'decoy_role':
      return {
        title: 'Connexion avec un compte-piège',
        what: `${who}${from} s’est connecté — c’est un compte-piège volontairement alléchant (admin, root, dba…) qu’aucun service d’Allsafe n’utilise.`,
        why: `Ces comptes n’existent que pour attirer un intrus. S’en servir prouve une tentative d’intrusion.`,
        reco: `À faire : bloquer cette adresse au niveau du pare-feu / réseau.`,
      }
    case 'ddl_attempt':
      return {
        title: 'Tentative de modifier la structure de la base — bloquée',
        blocked: true,
        what: `${who}${from} a tenté d’exécuter « ${e.object_name} » — une commande qui crée, modifie ou supprime des tables de la base. Allsafe l’a automatiquement bloquée avant tout effet.`,
        why: `Seul le compte d’administration a le droit de changer la structure de la base. Une telle commande venant d’un autre compte est une tentative d’altération (sabotage / destruction de données).`,
        reco: `À faire : vérifier d’urgence comment ce compte a pu lancer cette commande, et révoquer ses accès.`,
      }
    default:
      return { title: 'Activité anormale sur la base', what: '', why: '', reco: '' }
  }
}

// Modale de détail d'un événement de déception + bouton Acquitter.
function EventDetailModal({ event, onClose, onAck, acking }) {
  const src = EVENT_SOURCE[event.source] || { label: event.source, color: 'var(--text-muted)' }
  const rows = [
    ['Date / Heure', fmtDate(event.occurred_at)],
    ['Type', src.label],
    ['Objet leurre', event.object_name || '—'],
    ['Opération', event.operation || '—'],
    ['Rôle base de données', event.db_user],
    ['IP source', event.client_addr || '—'],
    ['Statut', event.acknowledged ? ('Acquitté' + (event.ack_by ? ` par ${event.ack_by}` : '')) : 'À investiguer'],
  ]
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-start justify-between gap-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${src.color}1a`, color: src.color, border: `1px solid ${src.color}55` }}>{src.label}</span>
              {!event.acknowledged && <span className="text-xs font-semibold" style={{ color: '#f85149' }}>À investiguer</span>}
            </div>
            <h2 className="text-base font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>{event.object_name}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-5">
          {/* Explication grand public */}
          {(() => {
            const x = explainEvent(event)
            return (
              <div>
                <p className="font-semibold text-sm mb-2" style={{ color: 'var(--text-primary)' }}>{x.title}</p>
                <div className="space-y-2.5 text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                  <p><span className="font-semibold" style={{ color: 'var(--text-primary)' }}>Ce qui s’est passé — </span>{x.what}</p>
                  <p><span className="font-semibold" style={{ color: 'var(--text-primary)' }}>Pourquoi c’est une alerte — </span>{x.why}</p>
                  {x.blocked && (
                    <p className="flex items-center gap-1.5 font-medium" style={{ color: '#3fb950' }}>
                      <span>✓</span> L’action a été automatiquement bloquée : la base n’a pas été modifiée.
                    </p>
                  )}
                  {x.reco && (
                    <p className="px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.25)', color: 'var(--text-secondary)' }}>
                      <span className="font-semibold" style={{ color: '#f85149' }}>{x.reco.split(':')[0].trim()} :</span>{x.reco.split(':').slice(1).join(':')}
                    </p>
                  )}
                </div>
              </div>
            )
          })()}

          {/* Détail technique */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-muted)' }}>Détail technique</p>
            {rows.map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4 text-sm py-1.5" style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                <span className="font-mono text-right break-all" style={{ color: 'var(--text-primary)' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="px-6 py-4 flex justify-end gap-2" style={{ borderTop: '1px solid var(--border)' }}>
          <button onClick={onClose} className="text-sm px-4 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>Fermer</button>
          {!event.acknowledged && (
            <button onClick={onAck} disabled={acking} className="text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-40" style={{ background: '#f85149', color: '#fff', border: 'none' }}>
              {acking ? '…' : 'Acquitter'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function DatabaseTab() {
  const { user: me } = useAuth()
  const [events, setEvents] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [acking, setAcking] = useState(false)
  const [detail, setDetail] = useState(null)   // événement ouvert dans la modale
  // Bug réel corrigé (11/08/2026, même famille que l'incident ServicesTab du 31/07) :
  // c'est la vue de DÉTECTION D'INTRUSION par leurres — un échec réseau avalé
  // silencieusement y affichait "0 alerte", le pire endroit possible pour ça.
  const [error, setError] = useState('')

  function load() {
    setLoading(true)
    securityEvents({ limit: 200 })
      .then(r => { setEvents(r.data.events || []); setError('') })
      .catch(() => { setEvents([]); setError('Impossible de charger les alertes de sécurité — le serveur a peut-être renvoyé une erreur.') })
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  // `ack_by` (11/08/2026, bug réel corrigé) : identifie qui a traité l'alerte, affiché
  // ensuite dans EventDetailModal — jusqu'ici toujours la chaîne "Administration" quel
  // que soit l'admin réellement connecté, perdant la piste d'audit entre plusieurs
  // admins (`useAuth()` déjà utilisé pour ça dans UsersTab du même fichier).
  async function ackAll() {
    setBusy(true)
    try { await ackAllSecurityEvents(me?.full_name || 'Administration'); load() }
    finally { setBusy(false) }
  }

  async function ackFromModal() {
    if (!detail) return
    setAcking(true)
    try { await ackSecurityEvent(detail.id, me?.full_name || 'Administration'); setDetail(null); load() }
    finally { setAcking(false) }
  }

  if (loading) return <Loader />
  if (!events) return null
  const unackEvents = events.filter(e => !e.acknowledged)

  return (
    <>
      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}
      <div className="mb-4 p-3 rounded-lg text-xs" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
        <p className="font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>🛡️ Déception base de données — active</p>
        Objets leurres (vues <span className="font-mono">api_keys</span>, <span className="font-mono">app_users</span>, <span className="font-mono">ssh_credentials_backup</span>, <span className="font-mono">admin_tokens</span> + rôles <span className="font-mono">admin/root/dba/backup/postgres_admin</span>) jamais utilisés par Allsafe : tout accès ci-dessous = activité anormale.
        L'app tourne en rôle à privilèges réduits (<span className="font-mono">cbr_app</span>, non superuser) qui ne peut pas effacer ce journal.
        Toute commande <b>DDL</b> (CREATE / ALTER / DROP…) par un rôle non autorisé (hors <span className="font-mono">cybervuln</span>) est <b>bloquée et journalisée</b> (event trigger).
      </div>

      {/* Alertes à traiter — au-dessus du journal, les non-acquittées listées et cliquables */}
      {unackEvents.length > 0 && (
        <div className="mb-5 rounded-lg overflow-hidden" style={{ border: '1px solid rgba(248,81,73,0.4)', background: 'rgba(248,81,73,0.06)' }}>
          <div className="px-4 py-2.5 flex items-center justify-between" style={{ borderBottom: '1px solid rgba(248,81,73,0.25)' }}>
            <p className="text-sm font-semibold" style={{ color: '#f85149' }}>
              🚨 {unackEvents.length} alerte{unackEvents.length > 1 ? 's' : ''} à traiter
            </p>
            <button onClick={ackAll} disabled={busy}
              className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-40"
              style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' }}>
              {busy ? '…' : 'Acquitter tout'}
            </button>
          </div>
          <ul>
            {unackEvents.map(e => {
              const src = EVENT_SOURCE[e.source] || { label: e.source, color: 'var(--text-muted)' }
              return (
                <li key={e.id}>
                  <button onClick={() => setDetail(e)}
                    className="w-full text-left px-4 py-2 text-xs flex flex-wrap items-center gap-x-2 gap-y-0.5 transition-colors"
                    style={{ borderTop: '1px solid rgba(248,81,73,0.15)', color: 'var(--text-secondary)' }}
                    onMouseEnter={ev => ev.currentTarget.style.background = 'rgba(248,81,73,0.08)'}
                    onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}>
                    <span className="font-mono" style={{ color: '#f85149' }}>{fmtDate(e.occurred_at)}</span>
                    <span className="font-medium px-1.5 py-0.5 rounded" style={{ background: `${src.color}1a`, color: src.color, border: `1px solid ${src.color}55` }}>{src.label}</span>
                    <span className="font-mono">{e.operation ? `${e.operation} ` : ''}sur <b>{e.object_name}</b> par « {e.db_user} »{e.client_addr ? ` depuis ${e.client_addr}` : ''}</span>
                    <span className="ml-auto" style={{ color: '#58a6ff' }}>Détail →</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      {/* Journal complet */}
      <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
        Journal complet — {events.length} événement{events.length !== 1 ? 's' : ''}
      </p>
      {events.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun accès aux objets leurres — rien à signaler.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['Date / Heure', 'Type', 'Objet', 'Opération', 'Rôle DB', 'IP source', 'Statut', ''].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map(e => {
                const src = EVENT_SOURCE[e.source] || { label: e.source, color: 'var(--text-muted)' }
                return (
                  <tr key={e.id} style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    // Rouge marqué + liseré gauche sur ce qui reste à acquitter.
                    background: e.acknowledged ? 'transparent' : 'rgba(248,81,73,0.1)',
                    boxShadow: e.acknowledged ? 'none' : 'inset 3px 0 0 #f85149',
                  }}>
                    <td className="px-4 py-2.5 text-xs font-mono whitespace-nowrap" style={{ color: e.acknowledged ? 'var(--text-secondary)' : '#f85149' }}>{fmtDate(e.occurred_at)}</td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${src.color}1a`, color: src.color, border: `1px solid ${src.color}55` }}>{src.label}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      {/* Objet cliquable → modale de détail */}
                      <button onClick={() => setDetail(e)} className="text-xs font-mono hover:underline" style={{ color: '#58a6ff' }} title="Voir le détail">
                        {e.object_name || '—'}
                      </button>
                    </td>
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{e.operation || '—'}</td>
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{e.db_user}</td>
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{e.client_addr || '—'}</td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {e.acknowledged
                        ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Acquitté</span>
                        : <span className="text-xs font-semibold" style={{ color: '#f85149' }}>À investiguer</span>}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <DeclareIncidentButton sourceType="security_event" sourceId={e.id} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <EventDetailModal event={detail} onClose={() => setDetail(null)} onAck={ackFromModal} acking={acking} />
      )}
    </>
  )
}

// ─── Onglet Utilisateurs ────────────────────────────────────────────────────────
// Anonymise un compte/une demande réels pour l'affichage (21/08/2026, retour utilisateur —
// "il manque beaucoup de fake data un peu partout") : `full_name`/`email` d'un vrai compte
// employé restaient en clair, seul ConnectionsTab était couvert sur cette page. Réutilise
// anonymizeRoleHolder (déjà utilisé pour Services/Rôles) — même pool de noms fictifs, cohérent
// dans toute l'app. Jamais utilisé pour construire un payload de mutation (modifier/supprimer
// continuent de lire l'objet réel, cf. displayUsers usage plus bas).
function anonymizeAccountLike(u) {
  if (!u) return u
  const fake = anonymizeRoleHolder({ id: u.id, name: u.full_name, email: u.email })
  return { ...u, full_name: fake.name, email: fake.email }
}

// Registre « Rôles » (organigramme) — même anonymizeRoleHolder que CrisisRoadmap.jsx/
// IncidentRoadmap.jsx, jamais branché sur cette page (Services/Rôles/ServiceOrgChartModal) avant
// ce correctif. Seedé sur le NOM (pas l'id du rôle) pour que la même personne réelle garde le
// même nom fictif partout où elle apparaît (titulaire d'un poste ici, "rapporte à" ailleurs) —
// contrairement à AnalystsTab/UsersTab (1 id = 1 compte), une même personne peut être référencée
// par plusieurs postes différents.
function anonymizeRole(r) {
  if (!r) return r
  const holder = anonymizeRoleHolder({ name: r.name, email: r.email })
  const reportsTo = r.reports_to_name ? anonymizeRoleHolder({ name: r.reports_to_name }).name : r.reports_to_name
  return { ...r, name: holder.name, email: holder.email, reports_to_name: reportsTo }
}

function UsersTab({ isAnonymous }) {
  const { user: me, refresh: refreshAuth } = useAuth()
  const [list, setList] = useState(null)
  const [formModal, setFormModal] = useState(null) // null | 'new' | user object
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [error, setError] = useState('')
  // Demandes « mot de passe oublié » (18/08/2026, cf. Login.jsx) — chargées séparément de
  // `list` : ce sont des demandes en attente, pas des comptes.
  const [resetRequests, setResetRequests] = useState(null)
  const [resolveTarget, setResolveTarget] = useState(null) // demande en cours de traitement

  function load() {
    fetchUsers().then(r => { setList(r.data.items || []); setError('') })
      .catch(() => { setList([]); setError('Impossible de charger les comptes — le serveur a peut-être renvoyé une erreur.') })
  }
  function loadResetRequests() {
    fetchPasswordResetRequests().then(r => setResetRequests(r.data.items || [])).catch(() => setResetRequests([]))
  }
  useEffect(() => { load(); loadResetRequests() }, [])

  async function handleResolveReset(newPassword) {
    await resolvePasswordResetRequest(resolveTarget.id, newPassword)
    setResolveTarget(null)
    loadResetRequests()
  }

  async function handleDismissReset(id) {
    await dismissPasswordResetRequest(id)
    loadResetRequests()
  }

  async function handleSave(payload) {
    const editingSelf = formModal && formModal !== 'new' && formModal.id === me?.id
    if (formModal && formModal !== 'new') await updateUser(formModal.id, payload)
    else await createUser(payload)
    setFormModal(null)
    load()
    // Le compte modifié peut être celui de l'admin connecté (ex: son propre nom/email) —
    // AuthContext garde une copie de /api/auth/me chargée une seule fois au démarrage,
    // sans ça Paramètres > Compte et le reste de l'app affichent des infos périmées
    // jusqu'au prochain rechargement complet de page.
    if (editingSelf) refreshAuth()
  }

  async function confirmDelete() {
    try {
      await deleteUser(deleteTarget.id)
      setDeleteTarget(null)
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteTarget(null)
    }
  }

  async function handleRevoke(id) {
    await revokeUserSessions(id)
  }

  if (!list) return <Loader />

  const displayList = isAnonymous ? list.map(anonymizeAccountLike) : list
  const displayResetRequests = isAnonymous ? (resetRequests || []).map(anonymizeAccountLike) : resetRequests

  return (
    <>
      {/* Demandes « mot de passe oublié » (18/08/2026, cf. Login.jsx) — au-dessus de la
          liste des comptes : ce sont des demandes en attente d'action, pas des comptes,
          elles méritent d'être vues avant de faire défiler la liste. */}
      {displayResetRequests?.length > 0 && (
        <div className="mb-4 rounded-xl p-3 space-y-2" style={{ background: 'rgba(210,153,34,0.08)', border: '1px solid rgba(210,153,34,0.25)' }}>
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: '#d29922' }}>
            {displayResetRequests.length} demande{displayResetRequests.length > 1 ? 's' : ''} de mot de passe oublié
          </p>
          {displayResetRequests.map(r => (
            <div key={r.id} className="flex items-start justify-between gap-3 text-sm rounded-lg px-3 py-2" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
              <div className="min-w-0">
                <p className="font-medium" style={{ color: 'var(--text-primary)' }}>{r.full_name} <span className="font-normal text-xs" style={{ color: 'var(--text-muted)' }}>({r.email})</span></p>
                {r.message && <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-secondary)' }}>« {r.message} »</p>}
              </div>
              <div className="flex gap-1.5 flex-shrink-0">
                <button onClick={() => handleDismissReset(r.id)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                >Rejeter</button>
                <button onClick={() => setResolveTarget(r)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922', border: '1px solid rgba(210,153,34,0.4)' }}
                >Traiter</button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="flex justify-end mb-3">
        <button onClick={() => setFormModal('new')}
          className="text-xs px-3 py-1.5 rounded-lg font-medium"
          style={{ background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.4)' }}
        >+ Ajouter un compte</button>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {displayList.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun compte.</p>
      ) : (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {displayList.map(u => {
            // Édition : toujours l'objet RÉEL (jamais la copie anonymisée `u`), sinon un
            // "Enregistrer" sans changement écraserait le vrai nom/email par le nom fictif.
            const realUser = isAnonymous ? list.find(ru => ru.id === u.id) : u
            return (
            <div key={u.id} className="py-3 flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-[220px]">
                <div className="flex items-center gap-2 mb-1">
                  <p className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{u.full_name}</p>
                  <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
                    style={{ background: u.role === 'admin' ? 'rgba(251,143,68,0.15)' : 'var(--bg-secondary)', color: u.role === 'admin' ? '#fb8f44' : 'var(--text-muted)' }}>
                    {u.role === 'admin' ? 'Administrateur' : 'Analyste'}
                  </span>
                  {!u.is_active && (
                    <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded" style={{ background: 'rgba(248,81,73,0.12)', color: '#f85149' }}>Désactivé</span>
                  )}
                  {u.role === 'analyst' && Array.isArray(u.allowed_pages) && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--bg-secondary)', color: 'var(--text-faint)' }}
                      title="Accès restreint à certains modules">
                      Accès restreint ({u.allowed_pages.length})
                    </span>
                  )}
                  {u.must_change_password && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--bg-secondary)', color: 'var(--text-faint)' }}>Changement mdp requis</span>
                  )}
                </div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{u.email}</p>
              </div>
              <div className="flex gap-1.5 flex-shrink-0">
                <button onClick={() => handleRevoke(u.id)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                  title="Invalider toutes les sessions actives de ce compte"
                >Déconnecter partout</button>
                <button onClick={() => setFormModal(realUser)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                >Modifier</button>
                <button onClick={() => setDeleteTarget(u)} disabled={u.id === me?.id}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium disabled:opacity-40"
                  style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}
                >Supprimer</button>
              </div>
            </div>
            )
          })}
        </div>
      )}

      {formModal && (
        <UserFormModal initial={formModal === 'new' ? null : formModal} onConfirm={handleSave} onClose={() => setFormModal(null)} />
      )}
      {deleteTarget && (
        <ConfirmModal
          title="Supprimer ce compte ?"
          message={<>Supprimer définitivement le compte de « <strong>{deleteTarget.full_name}</strong> » ? Il perdra immédiatement tout accès. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}
      {resolveTarget && (
        <ResolvePasswordResetModal request={resolveTarget} onConfirm={handleResolveReset} onClose={() => setResolveTarget(null)} />
      )}
    </>
  )
}

// ─── Onglet Analystes ───────────────────────────────────────────────────────────
// Registre de noms utilisés partout comme menu déroulant d'attribution (validé par,
// déclaré par, jalon envoyé par...) — distinct des comptes de connexion ci-dessus
// (onglet Utilisateurs). Gestion réservée admin (30/07/2026, déplacé depuis Paramètres
// où n'importe quel compte pouvait auparavant l'éditer).
function AnalystsTab({ isAnonymous }) {
  const { analysts, refresh } = useAnalysts()
  const [formModal, setFormModal] = useState(null) // null | 'new' | analyst object
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [error, setError] = useState('')

  async function handleSave(payload) {
    if (formModal && formModal !== 'new') await updateAnalyst(formModal.id, payload)
    else await createAnalyst(payload)
    setFormModal(null)
    refresh()
  }

  async function confirmDelete() {
    try {
      await deleteAnalyst(deleteTarget.id)
      setDeleteTarget(null)
      refresh()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la suppression.')
      setDeleteTarget(null)
    }
  }

  return (
    <>
      <div className="flex justify-end mb-3">
        <button onClick={() => setFormModal('new')}
          className="text-xs px-3 py-1.5 rounded-lg font-medium"
          style={{ background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.4)' }}
        >+ Ajouter un analyste</button>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {analysts.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun analyste — ajoutez-en un ci-dessus.</p>
      ) : (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {/* Noms réels masqués à l'affichage (21/08/2026, retour utilisateur) via
              anonymizeValidator — édition toujours sur l'objet réel `a` (jamais le nom masqué),
              sinon "Enregistrer" sans changement écraserait le vrai nom par le nom fictif. */}
          {analysts.map(a => (
            <div key={a.id} className="py-3 flex items-center justify-between gap-3">
              <p className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{isAnonymous ? anonymizeValidator(a.name) : a.name}</p>
              <div className="flex gap-1.5 flex-shrink-0">
                <button onClick={() => setFormModal(a)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                >Modifier</button>
                <button onClick={() => setDeleteTarget(a)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}
                >Supprimer</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {formModal && (
        <AnalystFormModal
          initial={formModal === 'new' ? null : formModal}
          onConfirm={handleSave}
          onClose={() => setFormModal(null)}
        />
      )}
      {deleteTarget && (
        <ConfirmModal
          title="Supprimer cet analyste ?"
          message={<>Supprimer définitivement « <strong>{isAnonymous ? anonymizeValidator(deleteTarget.name) : deleteTarget.name}</strong> » du registre ? Il ne sera plus proposé dans les menus déroulants d'attribution. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}
    </>
  )
}

// ─── Onglet Services ─────────────────────────────────────────────────────────────
// Services/départements (31/07/2026, cf. models.py::Service) — RH, DSI, Juridique, Direction...
// liste ouverte, ajoutable sans code. Regroupent les postes du registre Rôles
// (OrganizationRole.service_id) avec un code couleur pour les distinguer visuellement. Chaque
// carte liste directement ses postes rattachés (31/07/2026) — le rattachement se fait toujours
// côté formulaire Rôle (le service est optionnel sur un poste, pas l'inverse), cette vue-ci
// n'est qu'un miroir en lecture pour ne pas devoir naviguer vers l'onglet Rôles pour vérifier.
function ServicesTab({ isAnonymous }) {
  const [svcs, setSvcs] = useState(null)
  const [roles, setRoles] = useState([])
  const [chartTarget, setChartTarget] = useState(null) // service dont l'organigramme est ouvert
  const [error, setError] = useState('')

  function load() {
    Promise.all([fetchServices(), fetchOrganizationRoles()])
      .then(([svcRes, roleRes]) => {
        setSvcs(svcRes.data.items || [])
        setRoles(roleRes.data.items || [])
        setError('')
      })
      .catch(() => {
        // Incident réel 31/07/2026 : une colonne manquante côté DB faisait planter
        // ces deux endpoints, ce catch affichait juste "aucun service" sans le dire
        // — l'utilisateur a cru avoir perdu ses données. Rien n'était perdu, juste
        // inaccessible tant que l'erreur restait invisible.
        setSvcs([]); setRoles([])
        setError('Impossible de charger les services/rôles — le serveur a peut-être renvoyé une erreur.')
      })
  }
  useEffect(() => { load() }, [])

  const { formModal, setFormModal, deleteTarget, setDeleteTarget, handleSave, confirmDelete } =
    useCrudModals({ createFn: createService, updateFn: updateService, deleteFn: deleteService, load, setError })

  if (svcs === null) return <Loader />

  const displayRoles = isAnonymous ? roles.map(anonymizeRole) : roles

  return (
    <>
      <p className="text-sm mb-3" style={{ color: 'var(--text-muted)' }}>
        Services/départements (RH, DSI, Juridique, Direction...) — regroupent les postes du
        registre Rôles avec un code couleur pour les distinguer. Le rattachement se fait depuis
        l'onglet Rôles (poste → service) ; il est repris ici pour information.
      </p>
      <div className="flex justify-end mb-3">
        <button onClick={() => setFormModal('new')}
          className="text-xs px-3 py-1.5 rounded-lg font-medium"
          style={{ background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.4)' }}
        >+ Ajouter un service</button>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {svcs.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun service — ajoutez-en un ci-dessus.</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {svcs.map(s => {
            const attached = displayRoles.filter(r => r.service_id === s.id)
            return (
              <div key={s.id} className="rounded-2xl p-4" style={{ background: 'var(--bg-secondary)', border: `1px solid ${s.color}59` }}>
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ background: `${s.color}22`, color: s.color }}>
                    <ServiceIcon icon={s.icon} size={16} />
                  </div>
                  <p className="font-medium text-sm flex-1 min-w-0 truncate" style={{ color: s.color }}>{s.name}</p>
                  <button onClick={() => setFormModal(s)} className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>✎</button>
                  <button onClick={() => setDeleteTarget(s)} className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>✕</button>
                </div>

                {attached.length === 0 ? (
                  <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucun poste rattaché.</p>
                ) : (
                  <>
                    <ul className="space-y-1.5 mb-3">
                      {attached.map(r => (
                        <li key={r.id} className="flex items-baseline gap-1.5 text-xs">
                          <span className="font-semibold uppercase tracking-wide flex-shrink-0" style={{ color: s.color }}>{r.position}</span>
                          <span className="truncate" style={{ color: 'var(--text-muted)' }}>{r.name}</span>
                        </li>
                      ))}
                    </ul>
                    <button onClick={() => setChartTarget(s)}
                      className="text-xs px-2.5 py-1 rounded-lg font-medium w-full"
                      style={{ background: `${s.color}14`, color: s.color, border: `1px solid ${s.color}40` }}
                    >Voir l'organigramme</button>
                  </>
                )}
              </div>
            )
          })}
        </div>
      )}

      {formModal && (
        <ServiceFormModal
          initial={formModal === 'new' ? null : formModal}
          onConfirm={handleSave}
          onClose={() => setFormModal(null)}
        />
      )}
      {deleteTarget && (
        <ConfirmModal
          title="Supprimer ce service ?"
          message={<>Supprimer définitivement « <strong>{deleteTarget.name}</strong> » ? Les postes qui y étaient rattachés ne seront pas supprimés, seulement détachés. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}
      {chartTarget && (
        <ServiceOrgChartModal service={chartTarget} roles={displayRoles} onClose={() => setChartTarget(null)} />
      )}
    </>
  )
}

// ─── Onglet Rôles ────────────────────────────────────────────────────────────────
// Organigramme simple (31/07/2026, cf. models.py::OrganizationRole) : quel poste (RSSI, DPO,
// Direction générale...) est tenu par quelle personne — utilisé par la Gestion de crise
// (CrisisRoadmap.jsx) et les Incidents (IncidentRoadmap.jsx) pour savoir à qui se référer selon
// le poste. Distinct du registre Analystes ci-dessus (noms utilisés dans les dropdowns
// d'attribution). Gestion réservée admin, lecture ouverte à tout connecté.
function hashPosition(str) {
  let h = 0
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0
  return h
}
// Couleur du Service rattaché si renseignée (Administration > Services) ; à défaut, repli sur
// un hash du poste dans la même palette — variété visuelle sans forcer à rattacher un service.
function roleColor(role) {
  if (role.service_color) return role.service_color
  return SERVICE_COLOR_PALETTE[hashPosition(role.position || '') % SERVICE_COLOR_PALETTE.length]
}
function initials(name) {
  const parts = (name || '').trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  return (parts[0][0] + (parts[1]?.[0] || '')).toUpperCase()
}

function OrganizationRolesTab({ isAnonymous }) {
  const { list: roles, error, setError, load } = useLoadList(
    fetchOrganizationRoles, 'Impossible de charger les rôles — le serveur a peut-être renvoyé une erreur.'
  )
  const { formModal, setFormModal, deleteTarget, setDeleteTarget, handleSave, confirmDelete } =
    useCrudModals({ createFn: createOrganizationRole, updateFn: updateOrganizationRole, deleteFn: deleteOrganizationRole, load, setError })

  if (roles === null) return <Loader />

  // Édition/suppression restent sur l'objet réel (`setFormModal(r)`/`setDeleteTarget(r)` plus
  // bas utilisent `r` de `roles`, jamais `displayRoles`) — seul l'affichage est masqué.
  const displayRoles = isAnonymous ? roles.map(anonymizeRole) : roles

  return (
    <>
      <p className="text-sm mb-3" style={{ color: 'var(--text-muted)' }}>
        Organigramme simple — quel poste (RSSI, DPO, Direction générale...) est tenu par quelle
        personne. Affiché dans la Gestion de crise et les Incidents pour savoir à qui se référer.
      </p>
      <div className="flex justify-end mb-3">
        <button onClick={() => setFormModal('new')}
          className="text-xs px-3 py-1.5 rounded-lg font-medium"
          style={{ background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.4)' }}
        >+ Ajouter un rôle</button>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {roles.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun rôle — ajoutez-en un ci-dessus.</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {displayRoles.map(r => {
            const color = roleColor(r)
            const realRole = isAnonymous ? roles.find(rr => rr.id === r.id) : r
            return (
              <div key={r.id} className="rounded-2xl p-4"
                style={{ background: 'var(--bg-secondary)', border: `1px solid ${r.service_color ? `${color}59` : 'var(--border)'}` }}>
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 font-semibold text-sm"
                    style={{ background: `${color}22`, color }}>
                    {r.service_id ? <ServiceIcon icon={r.service_icon} size={18} /> : initials(r.name)}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <p className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded inline-block"
                        style={{ background: `${color}1f`, color }}>{r.position}</p>
                      {r.service_name && (
                        <span className="text-[10px]" style={{ color: 'var(--text-faint)' }}>· {r.service_name}</span>
                      )}
                    </div>
                    <p className="font-medium text-sm mt-0.5 truncate" style={{ color: 'var(--text-primary)' }}>{r.name}</p>
                  </div>
                </div>
                {r.email && (
                  <a href={`mailto:${r.email}`} className="text-xs hover:underline block truncate"
                    style={{ color: 'var(--text-muted)' }}>✉ {r.email}</a>
                )}
                {r.reports_to_name && (
                  <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-faint)' }}>
                    ↳ rapporte à {r.reports_to_position} — {r.reports_to_name}
                  </p>
                )}
                <div className="flex gap-1.5 mt-3">
                  <button onClick={() => setFormModal(realRole)}
                    className="text-xs px-2.5 py-1 rounded-lg transition-colors font-medium flex-1"
                    style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                  >Modifier</button>
                  <button onClick={() => setDeleteTarget(r)}
                    className="text-xs px-2.5 py-1 rounded-lg transition-colors font-medium flex-1"
                    style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}
                  >Supprimer</button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {formModal && (
        <OrganizationRoleFormModal
          initial={formModal === 'new' ? null : formModal}
          onConfirm={handleSave}
          onClose={() => setFormModal(null)}
        />
      )}
      {deleteTarget && (
        <ConfirmModal
          title="Supprimer ce rôle ?"
          message={<>Supprimer définitivement « <strong>{deleteTarget.position}</strong> — {deleteTarget.name} » du registre ? Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}
    </>
  )
}

// ─── Onglet Correspondances Windows ─────────────────────────────────────────────
// Table réglable en base (cf. models.py::WindowsAppMapping) qui alimente
// services/cpe_matcher.py côté Windows : un nom d'application Windows (texte libre
// de registre) n'a pas de convention exploitable comme les paquets Debian/RPM, d'où
// une correspondance déclarée ici plutôt qu'un heuristique deviné.
function WindowsAppMappingsTab() {
  const { list, error, setError, load } = useLoadList(
    fetchWindowsAppMappings, 'Impossible de charger les correspondances — le serveur a peut-être renvoyé une erreur.'
  )
  const { formModal, setFormModal, deleteTarget, setDeleteTarget, handleSave, confirmDelete } =
    useCrudModals({ createFn: createWindowsAppMapping, updateFn: updateWindowsAppMapping, deleteFn: deleteWindowsAppMapping, load, setError })

  if (list === null) return <Loader />

  return (
    <>
      <p className="text-sm mb-3" style={{ color: 'var(--text-muted)' }}>
        Correspondances entre un nom d'application Windows et un produit CPE — alimente le badge
        vulnérabilité sur les applications installées côté Windows. À ajouter au fil des applications
        réellement rencontrées sur le parc.
      </p>
      <div className="flex justify-end mb-3">
        <button onClick={() => setFormModal('new')}
          className="text-xs px-3 py-1.5 rounded-lg font-medium"
          style={{ background: 'rgba(251,143,68,0.15)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.4)' }}
        >+ Ajouter une correspondance</button>
      </div>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl mb-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      {list.length === 0 ? (
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucune correspondance — ajoutez-en une ci-dessus.</p>
      ) : (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {list.map(m => (
            <div key={m.id} className="py-3 flex items-center justify-between gap-3">
              <div>
                <p className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>
                  « {m.pattern} » → <span style={{ color: 'var(--text-secondary)' }}>{m.cpe_product}</span>
                </p>
                {m.cpe_vendor && (
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Vendeur : {m.cpe_vendor}</p>
                )}
              </div>
              <div className="flex gap-1.5 flex-shrink-0">
                <button onClick={() => setFormModal(m)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                >Modifier</button>
                <button onClick={() => setDeleteTarget(m)}
                  className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                  style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}
                >Supprimer</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {formModal && (
        <WindowsAppMappingFormModal
          initial={formModal === 'new' ? null : formModal}
          onConfirm={handleSave}
          onClose={() => setFormModal(null)}
        />
      )}
      {deleteTarget && (
        <ConfirmModal
          title="Supprimer cette correspondance ?"
          message={<>Supprimer définitivement « <strong>{deleteTarget.pattern}</strong> » → <strong>{deleteTarget.cpe_product}</strong> ? Les applications Windows correspondantes ne seront plus croisées avec les CVE. Cette action est irréversible.</>}
          confirmLabel="Supprimer"
          onConfirm={confirmDelete}
          onClose={() => setDeleteTarget(null)}
        />
      )}
    </>
  )
}

// ─── Page Administration (réservée au rôle admin, cf. ProtectedRoute dans App.jsx) ──
export default function AdministrationSecurity() {
  const navigate = useNavigate()
  const { isAnonymous } = usePresentation()
  const [tab, setTab] = useState('database')
  // Repli icônes seules (demande utilisateur, 14/08/2026) — même idée que la sidebar
  // principale (Layout.jsx) mais état local, pas persisté : cette nav est secondaire,
  // pas la navigation globale de l'app.
  const [navCollapsed, setNavCollapsed] = useState(false)
  // Badge sur l'onglet Utilisateurs (18/08/2026) — demandes « mot de passe oublié » en
  // attente (cf. Login.jsx/UsersTab ci-dessus), visible sans avoir à ouvrir l'onglet.
  const [pendingResets, setPendingResets] = useState(0)
  useEffect(() => {
    passwordResetRequestsCount().then(r => setPendingResets(r.data.pending || 0)).catch(() => {})
  }, [])

  const TABS = [
    { key: 'database',    label: 'Base de données',  desc: 'Déception & journal' },
    { key: 'connections', label: 'Connexions IP',     desc: 'Historique d\'accès' },
    { key: 'users',       label: 'Utilisateurs',      desc: 'Comptes de connexion' },
    { key: 'analysts',    label: 'Analystes',         desc: 'Registre de validation' },
    { key: 'services',    label: 'Services',          desc: 'RH, DSI, Direction...' },
    { key: 'roles',       label: 'Rôles',             desc: 'Organigramme' },
    { key: 'windows-mappings', label: 'Correspondances Windows', desc: 'Apps → CPE' },
  ]

  return (
    <div className="p-6 space-y-5">
      <button onClick={() => navigate('/settings')}
        className="text-xs -mb-1 inline-flex items-center gap-1 hover:underline" style={{ color: 'var(--text-muted)' }}>
        ← Retour aux paramètres
      </button>
      <PageHero
        icon="M17.982 18.725A7.488 7.488 0 0012 15.75a7.488 7.488 0 00-5.982 2.975m11.964 0a9 9 0 10-11.964 0m11.964 0A8.966 8.966 0 0112 21a8.966 8.966 0 01-5.982-2.275M15 9.75a3 3 0 11-6 0 3 3 0 016 0z"
        title="Administration" color={MODULE_COLOR}
        subtitle="Journal de connexion, administration de la base et comptes utilisateurs — réservé aux administrateurs"
      />

      <div className="flex flex-col lg:flex-row gap-5 items-start">
        <nav className={`w-full ${navCollapsed ? 'lg:w-16' : 'lg:w-64'} flex-shrink-0 flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible pb-1 transition-[width] duration-200`}>
          <button onClick={() => setNavCollapsed(c => !c)} title={navCollapsed ? 'Déplier le menu' : 'Réduire le menu'}
            className="hidden lg:flex items-center gap-2 px-3 py-2 rounded-lg mb-1 flex-shrink-0 transition-colors"
            style={{ color: 'var(--text-muted)' }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <svg className="w-4 h-4 flex-shrink-0 transition-transform duration-200" style={{ transform: navCollapsed ? 'rotate(180deg)' : 'none' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.75 19.5L8.25 12l7.5-7.5" />
            </svg>
            {!navCollapsed && <span className="text-xs font-medium">Réduire</span>}
          </button>
          {TABS.map(t => {
            const active = tab === t.key
            return (
              <button key={t.key} onClick={() => setTab(t.key)} title={navCollapsed ? t.label : undefined}
                className="flex-shrink-0 w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors"
                style={{
                  background: active ? `color-mix(in srgb, ${MODULE_COLOR} 12%, transparent)` : 'transparent',
                  boxShadow: active ? `inset 3px 0 0 0 ${MODULE_COLOR}` : 'none',
                  justifyContent: navCollapsed ? 'center' : 'flex-start',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg-secondary)' }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
              >
                <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{
                  background: active ? `color-mix(in srgb, ${MODULE_COLOR} 20%, transparent)` : 'var(--bg-secondary)',
                  color: active ? MODULE_COLOR : 'var(--text-muted)',
                }}>
                  <TabIcon name={t.key} />
                </span>
                {!navCollapsed && (
                  <span className="min-w-0 flex-1 flex items-center justify-between gap-2">
                    <span className="min-w-0">
                      <span className="block text-sm font-medium truncate" style={{ color: active ? MODULE_COLOR : 'var(--text-primary)' }}>{t.label}</span>
                      <span className="hidden lg:block text-xs truncate" style={{ color: 'var(--text-muted)' }}>{t.desc}</span>
                    </span>
                    {t.key === 'users' && pendingResets > 0 && (
                      <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full flex-shrink-0" style={{ background: 'rgba(210,153,34,0.2)', color: '#d29922' }}>
                        {pendingResets}
                      </span>
                    )}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        <div style={CARD} className="flex-1 min-w-0 p-6">
          {tab === 'connections' ? (
            <ConnectionsTab isAnonymous={isAnonymous} />
          ) : tab === 'users' ? (
            <UsersTab isAnonymous={isAnonymous} />
          ) : tab === 'analysts' ? (
            <AnalystsTab isAnonymous={isAnonymous} />
          ) : tab === 'services' ? (
            <ServicesTab isAnonymous={isAnonymous} />
          ) : tab === 'roles' ? (
            <OrganizationRolesTab isAnonymous={isAnonymous} />
          ) : tab === 'windows-mappings' ? (
            <WindowsAppMappingsTab />
          ) : (
            <DatabaseTab />
          )}
        </div>
      </div>
    </div>
  )
}
