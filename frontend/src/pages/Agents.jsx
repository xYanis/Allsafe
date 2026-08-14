import { useEffect, useState, useCallback, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext.jsx'
import {
  listAgents, createEnrollmentToken, listEnrollmentTokens, deleteEnrollmentToken,
  revokeAgent, deleteAgent, requestAgentScan, assets as fetchAssets,
} from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import OsLogo from '../components/OsLogo.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.inventaire.color

const STATUS_STYLES = {
  enrolled: { background: 'rgba(63,185,80,0.12)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
  revoked:  { background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' },
}

function StatusBadge({ value }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.enrolled
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>
    {value === 'revoked' ? 'Révoqué' : 'Enrôlé'}
  </span>
}

function VersionBadge({ version, outdated }) {
  if (!version) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <span className="inline-flex items-center gap-1.5">
      <span style={{ color: 'var(--text-secondary)' }}>{version}</span>
      {outdated && (
        <span title="Une version plus récente de l'agent est disponible"
          style={{ background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)', borderRadius: 6, padding: '1px 6px', fontSize: 10, fontWeight: 600 }}>
          Mise à jour dispo
        </span>
      )}
    </span>
  )
}

// Distribution précise (ex. "Debian 12", "Windows Server 2019") — distincte de la colonne
// "OS" (juste windows/linux, déclaré par l'agent lui-même) : vient de l'actif rattaché
// (Asset.os/os_version, alimenté par le premier scan). OsLogo.jsx sait déjà distinguer
// Debian/Ubuntu d'un Linux générique à partir de ce texte (même composant que Assets.jsx/
// Inventaire.jsx) — absente tant qu'aucun scan n'a encore eu lieu sur l'actif.
function DistroBadge({ os, version }) {
  if (!os) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <span className="inline-flex items-center gap-1.5" style={{ color: 'var(--text-secondary)' }}>
      <OsLogo os={os} size={16} />
      {os}{version ? ` ${version}` : ''}
    </span>
  )
}

function formatDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Rapport de coupure (13/08/2026, boucle persistante — agent/src/daemon.rs::DaemonState) —
// icône discrète, affichée seulement si la coupure est récente (< 7 jours) : au-delà, plus
// vraiment exploitable pour l'analyste, autant ne pas encombrer la colonne indéfiniment
// (le champ reste en base, juste plus affiché ici).
const GAP_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

function GapBadge({ startedAt, failedAttempts }) {
  if (!startedAt) return null
  const started = new Date(startedAt)
  if (Date.now() - started.getTime() > GAP_MAX_AGE_MS) return null
  const title = `Hors ligne depuis le ${formatDateTime(startedAt)} (${failedAttempts ?? '?'} tentative${failedAttempts > 1 ? 's' : ''} échouée${failedAttempts > 1 ? 's' : ''})`
  return (
    <span title={title} className="inline-flex" style={{ color: '#d29922' }}>
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
    </span>
  )
}

const inputStyle = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }
const labelStyle = { color: 'var(--text-muted)' }

// Sélecteur d'actif avec recherche (13/08/2026, demande explicite) — remplace le <select>
// natif du formulaire de jeton : liste pénible à parcourir au clic passé quelques dizaines
// d'actifs, et le menu natif du navigateur s'ouvrait vers le haut de façon imprévisible en
// bas de modale. Positionnement en `position: fixed` mesuré via `getBoundingClientRect`
// (même idiome que ValidateDropdown.jsx) plutôt que `absolute` : échappe au `overflow`/
// empilement de la modale, aligné pile sous (ou au-dessus si pas la place) le champ plutôt
// que dans un coin — bascule automatique selon l'espace disponible.
function AssetSearchSelect({ assetList, value, onChange, emptyLabel }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [menuStyle, setMenuStyle] = useState({})
  const wrapRef = useRef(null)
  const menuRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = e => {
      if (
        wrapRef.current && !wrapRef.current.contains(e.target) &&
        menuRef.current && !menuRef.current.contains(e.target)
      ) setOpen(false)
    }
    const onKeyDown = e => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', handler)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', handler)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  function openMenu() {
    if (wrapRef.current) {
      const r = wrapRef.current.getBoundingClientRect()
      const spaceBelow = window.innerHeight - r.bottom
      const menuH = 260
      setMenuStyle(spaceBelow < menuH
        ? { position: 'fixed', bottom: window.innerHeight - r.top + 4, left: r.left, width: r.width, zIndex: 9999 }
        : { position: 'fixed', top: r.bottom + 4, left: r.left, width: r.width, zIndex: 9999 })
    }
    setSearch('')
    setOpen(true)
  }

  function select(id) {
    onChange(id)
    setOpen(false)
  }

  const filtered = search.trim()
    ? assetList.filter(a => a.name.toLowerCase().includes(search.trim().toLowerCase()))
    : assetList
  const selectedName = value ? (assetList.find(a => a.id === value)?.name ?? '') : ''

  return (
    <div ref={wrapRef} style={{ position: 'relative' }}>
      <button type="button" onClick={openMenu}
        className="w-full text-sm rounded-lg px-3 py-2 outline-none text-left flex items-center justify-between gap-2"
        style={inputStyle}>
        <span style={{ color: value ? 'var(--text-primary)' : 'var(--text-muted)' }} className="truncate">
          {value ? selectedName : emptyLabel}
        </span>
        <svg className="w-3.5 h-3.5 opacity-60 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div ref={menuRef}
          className="rounded-xl overflow-hidden flex flex-col"
          style={{ ...menuStyle, maxHeight: 260, background: 'var(--bg-card)', border: '1px solid var(--border)', boxShadow: '0 8px 24px rgba(0,0,0,0.4)' }}>
          <div className="px-2 pt-2 pb-1.5 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
            <input
              autoFocus
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Rechercher un actif…"
              className="w-full text-xs px-2.5 py-1.5 rounded-lg outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            />
          </div>
          <div style={{ overflowY: 'auto' }}>
            <button type="button" onClick={() => select('')}
              className="w-full text-left text-xs px-3 py-2 transition-colors"
              style={{ color: 'var(--text-muted)' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              {emptyLabel}
            </button>
            {filtered.length === 0 && (
              <p className="px-3 py-2.5 text-xs" style={{ color: 'var(--text-muted)' }}>Aucun actif trouvé.</p>
            )}
            {filtered.map(a => (
              <button type="button" key={a.id} onClick={() => select(a.id)}
                className="w-full text-left text-sm px-3 py-1.5 transition-colors truncate"
                style={{ color: value === a.id ? '#58a6ff' : 'var(--text-secondary)' }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                {a.name}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Modale de génération de jeton — le jeton en clair n'est retourné qu'une seule fois par
// l'API (cf. routers/agents.py::POST /enrollment-tokens), jamais reloggé/re-consultable
// après fermeture : affichage "à copier maintenant" façon coffre-fort, pas de champ éditable.
function TokenModal({ assetList, onClose, onCreated }) {
  const [assetId, setAssetId] = useState('')
  const [label, setLabel] = useState('')
  // Enrôlement à l'échelle (13/08/2026) — un jeton lié à un actif précis reste forcément
  // usage unique côté backend (data.max_uses != 1 refusé si asset_id posé, cf. routers/
  // agents.py) : bascule "réutilisable" désactivée tant qu'un actif est sélectionné.
  const [bulk, setBulk] = useState(false)
  const [maxUses, setMaxUses] = useState(10)
  const [expiresHours, setExpiresHours] = useState(48)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [copied, setCopied] = useState(false)

  async function handleSubmit() {
    if (saving) return
    setSaving(true)
    setError('')
    try {
      const { data } = await createEnrollmentToken({
        asset_id: bulk ? null : (assetId || null),
        label: label.trim() || null,
        max_uses: bulk ? maxUses : 1,
        expires_in_hours: expiresHours,
      })
      setResult(data)
      onCreated()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la génération du jeton.')
    } finally {
      setSaving(false)
    }
  }

  function copyToken() {
    navigator.clipboard?.writeText(result.token)
    setCopied(true)
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={result ? undefined : onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>
            {result ? 'Jeton généré' : "Nouveau jeton d'enrôlement"}
          </h2>
          {!result && (
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          )}
        </div>

        {!result ? (
          <>
            <div className="p-6 space-y-3">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={labelStyle}>Portée</label>
                <div className="flex gap-2">
                  <button type="button" onClick={() => setBulk(false)}
                    className="flex-1 text-xs px-3 py-2 rounded-lg font-medium"
                    style={!bulk ? { background: MODULE_COLOR, color: MODULES.inventaire.dark } : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                    Usage unique
                  </button>
                  <button type="button" onClick={() => { setBulk(true); setAssetId('') }}
                    className="flex-1 text-xs px-3 py-2 rounded-lg font-medium"
                    style={bulk ? { background: MODULE_COLOR, color: MODULES.inventaire.dark } : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                    Réutilisable (parc)
                  </button>
                </div>
              </div>
              {!bulk ? (
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={labelStyle}>
                    Actif à lier (optionnel)
                  </label>
                  <AssetSearchSelect assetList={assetList} value={assetId} onChange={setAssetId}
                    emptyLabel="Aucun — l'agent créera un nouvel actif à l'enrôlement" />
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Lier un actif bascule sa méthode de collecte sur "Agent" au premier check-in.
                  </p>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={labelStyle}>
                    Nombre de postes max
                  </label>
                  <input type="number" min="2" value={maxUses} onChange={e => setMaxUses(Math.max(2, parseInt(e.target.value) || 2))}
                    className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle} />
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Un jeton partageable entre plusieurs postes — chacun crée son propre actif à
                    l'enrôlement (pas de lien à un actif précis, cf. usage unique).
                  </p>
                </div>
              )}
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={labelStyle}>
                  Expire dans (heures)
                </label>
                <input type="number" min="1" value={expiresHours} onChange={e => setExpiresHours(Math.max(1, parseInt(e.target.value) || 1))}
                  className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle} />
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={labelStyle}>Label (optionnel)</label>
                <input value={label} onChange={e => setLabel(e.target.value)} placeholder="ex : Poste RH-042"
                  className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle} />
              </div>
              {error && (
                <div className="text-sm px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                  {error}
                </div>
              )}
            </div>
            <div className="px-6 py-4 flex items-center justify-end gap-2" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={onClose} disabled={saving}
                className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                Annuler
              </button>
              <button onClick={handleSubmit} disabled={saving}
                className="text-xs px-4 py-2 rounded-lg font-medium disabled:opacity-50"
                style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}>
                {saving ? 'Génération…' : 'Générer'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="p-6 space-y-3">
              <div className="text-sm px-3 py-2 rounded-lg" style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' }}>
                ⚠ Copiez ce jeton maintenant — il ne sera plus jamais affiché.
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs px-3 py-2.5 rounded-lg break-all" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                  {result.token}
                </code>
                <button onClick={copyToken}
                  className="text-xs px-3 py-2.5 rounded-lg font-medium flex-shrink-0"
                  style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}>
                  {copied ? 'Copié ✓' : 'Copier'}
                </button>
              </div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Sur le poste : <code>allsafe-agent enroll --token &lt;JETON&gt; --server &lt;URL&gt;</code>
              </p>
            </div>
            <div className="px-6 py-4 flex items-center justify-end" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={onClose}
                className="text-xs px-4 py-2 rounded-lg font-medium"
                style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}>
                Fermer
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois,
// par-dessus le guard hasLoadedOnce existant (state local, protège seulement les reloads
// internes — revoke/scan — pas le remontage). Permet de réafficher instantanément la
// dernière liste connue au remontage pendant qu'un rafraîchissement silencieux la met à jour.
let agentsCache = null

export default function Agents() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [agentList, setAgentList] = useState(() => agentsCache?.agentList ?? [])
  const [tokens, setTokens] = useState(() => agentsCache?.tokens ?? [])
  const [assetList, setAssetList] = useState([])
  const [loading, setLoading] = useState(() => agentsCache == null)
  const [hasLoadedOnce, setHasLoadedOnce] = useState(() => agentsCache != null)
  const [tokenModal, setTokenModal] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState(null)
  const [deleteAgentTarget, setDeleteAgentTarget] = useState(null)
  const [deleteTokenTarget, setDeleteTokenTarget] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      listAgents(),
      isAdmin ? listEnrollmentTokens() : Promise.resolve({ data: [] }),
    ])
      .then(([a, t]) => {
        const agents = a.data?.items || []
        const toks = t.data?.items || []
        setAgentList(agents); setTokens(toks); setError('')
        agentsCache = { agentList: agents, tokens: toks }
      })
      .catch(() => setError('Impossible de charger les agents — le serveur a peut-être renvoyé une erreur.'))
      .finally(() => { setLoading(false); setHasLoadedOnce(true) })
  }, [isAdmin])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!isAdmin) return
    fetchAssets().then(r => setAssetList([...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name)))).catch(() => {})
  }, [isAdmin])

  async function handleRevoke() {
    await revokeAgent(revokeTarget.id)
    setRevokeTarget(null)
    load()
  }

  async function handleDeleteAgent() {
    await deleteAgent(deleteAgentTarget.id)
    setDeleteAgentTarget(null)
    load()
  }

  async function handleRequestScan(agent) {
    await requestAgentScan(agent.id)
    load()
  }

  async function handleDeleteToken() {
    await deleteEnrollmentToken(deleteTokenTarget.id)
    setDeleteTokenTarget(null)
    load()
  }

  const pendingTokens = tokens.filter(t => t.use_count < t.max_uses && new Date(t.expires_at) > new Date())
  const assetNameById = new Map(assetList.map(a => [a.id, a.name]))

  if (loading && !hasLoadedOnce) {
    return <PageLoader />
  }

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25"
        title="Agents"
        color="#39c5cf"
        subtitle="Collecte alternative pour les postes, en complément du compte de service AD/SSH — lecture seule."
      >
        {isAdmin && (
          <button onClick={() => setTokenModal(true)}
            className="px-4 py-2 text-sm font-medium rounded-lg"
            style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}>
            + Jeton d'enrôlement
          </button>
        )}
      </PageHero>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Hôte', 'OS', 'Distribution', 'Actif lié', 'Version', 'Dernier contact', 'Statut', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {!loading && agentList.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucun agent enrôlé</p>
                    <p className="text-xs">Générez un jeton d'enrôlement pour poser l'agent sur un poste</p>
                  </td>
                </tr>
              )}
              {agentList.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)' }}>{a.hostname}</td>
                  <td className="px-4 py-3">
                    <OsLogo os={a.os} size={18} />
                  </td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap"><DistroBadge os={a.asset_os} version={a.asset_os_version} /></td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{a.asset_name || '—'}</td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap"><VersionBadge version={a.agent_version} outdated={a.outdated} /></td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    <span className="inline-flex items-center gap-1.5">
                      {formatDateTime(a.last_seen_at)}
                      <GapBadge startedAt={a.last_gap_started_at} failedAttempts={a.last_gap_failed_attempts} />
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap"><StatusBadge value={a.status} /></td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    {isAdmin && a.status === 'enrolled' && (
                      a.pending_scan_requested_at ? (
                        <span className="text-xs px-2.5 py-1.5 rounded-lg font-medium mr-1.5" title="Récupéré au prochain sondage de l'agent (jusqu'à 60s), puis au check-in qui suit"
                          style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }}>
                          Scan demandé
                        </span>
                      ) : (
                        <button onClick={() => handleRequestScan(a)}
                          className="text-xs px-2.5 py-1.5 rounded-lg font-medium mr-1.5"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                          Scanner maintenant
                        </button>
                      )
                    )}
                    {isAdmin && a.status === 'enrolled' && (
                      <button onClick={() => setRevokeTarget(a)}
                        className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
                        style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                        Révoquer
                      </button>
                    )}
                    {isAdmin && a.status === 'revoked' && (
                      <button onClick={() => setDeleteAgentTarget(a)}
                        className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
                        style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                        Supprimer
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {isAdmin && pendingTokens.length > 0 && (
        <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
          <div className="px-5 py-3.5" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Jetons en attente</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Label', 'Actif lié', 'Utilisations', 'Créé par', 'Expire le', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pendingTokens.map(t => (
                  <tr key={t.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{t.label || '—'}</td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{assetNameById.get(t.asset_id) || '—'}</td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>{t.use_count} / {t.max_uses}</td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{t.created_by}</td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{formatDateTime(t.expires_at)}</td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button onClick={() => setDeleteTokenTarget(t)}
                        className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
                        style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                        Révoquer
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tokenModal && (
        <TokenModal assetList={assetList} onClose={() => setTokenModal(false)} onCreated={load} />
      )}

      {revokeTarget && (
        <ConfirmModal
          title="Révoquer l'agent"
          message={<>Révoquer l'agent <strong>{revokeTarget.hostname}</strong> ? Il ne pourra plus pousser de check-in tant qu'il n'aura pas été ré-enrôlé.</>}
          confirmLabel="Révoquer" busyLabel="Révocation…" color="#f85149"
          onConfirm={handleRevoke} onClose={() => setRevokeTarget(null)} />
      )}

      {deleteAgentTarget && (
        <ConfirmModal
          title="Supprimer l'agent"
          message={<>Supprimer définitivement l'agent <strong>{deleteAgentTarget.hostname}</strong> ? Cette entrée disparaîtra de la liste — action irréversible.</>}
          confirmLabel="Supprimer" busyLabel="Suppression…" color="#f85149"
          onConfirm={handleDeleteAgent} onClose={() => setDeleteAgentTarget(null)} />
      )}

      {deleteTokenTarget && (
        <ConfirmModal
          title="Révoquer le jeton"
          message="Ce jeton ne pourra plus être utilisé pour enrôler un agent."
          confirmLabel="Révoquer" busyLabel="Révocation…" color="#f85149"
          onConfirm={handleDeleteToken} onClose={() => setDeleteTokenTarget(null)} />
      )}
    </div>
  )
}
