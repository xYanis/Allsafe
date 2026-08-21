import { useEffect, useState, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import {
  listAgents, createEnrollmentToken, listEnrollmentTokens, deleteEnrollmentToken,
  revokeAgent, deleteAgent, assets as fetchAssets, agentLatestVersion, requestAgentScan,
} from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import OsLogo from '../components/OsLogo.jsx'
import { StatusBadge, VersionBadge, TokenStateBadge, DistroBadge, formatDateTime, contactFreshness, FRESHNESS_COLOR } from '../components/AgentBadges.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'

const MODULE_COLOR = MODULES.inventaire.color

const inputStyle = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }
const labelStyle = { color: 'var(--text-muted)' }

// Sélecteur d'actif avec recherche (13/08/2026, demande explicite) — remplace le <select>
// natif du formulaire de jeton : liste pénible à parcourir au clic passé quelques dizaines
// d'actifs, et le menu natif du navigateur s'ouvrait vers le haut de façon imprévisible en
// bas de modale. Positionnement en `position: fixed` mesuré via `getBoundingClientRect`
// (même idiome que ValidateDropdown.jsx) plutôt que `absolute` : échappe au `overflow`/
// empilement de la modale, aligné pile sous (ou au-dessus si pas la place) le champ plutôt
// que dans un coin — bascule automatique selon l'espace disponible.
// Téléchargement des paquets construits (18/08/2026, demande explicite) — 3 formats, mêmes
// routes publiques déjà utilisées par agent/deploy/update-agent.*/le poste lui-même
// (GET /agents/latest/*, cf. routers/agents.py) : pas de nouvel endpoint pour le .msi/.deb,
// seul le .exe autonome (zippé avec WebView2Loader.dll, indispensable à côté de lui) est
// nouveau. Simple <a> natif (routes publiques, pas de session à porter) plutôt qu'un
// téléchargement piloté en JS — le navigateur gère nativement Content-Disposition.
// Versionnement séparé par plateforme (19/08/2026, demande explicite) — .exe/.msi
// partagent forcément la même version (même binaire Windows compilé une fois, le .msi
// l'embarque tel quel) mais divergent de .deb, souvent modifié indépendamment.
const DOWNLOAD_OPTIONS = [
  { href: '/api/agents/latest/windows-exe', os: 'windows', dateKey: 'built_at_windows', versionKey: 'version_windows', label: 'Windows — .exe autonome', desc: 'Poste critique, assistant graphique (installation/réparation/mise à jour)' },
  { href: '/api/agents/latest/windows', os: 'windows', dateKey: 'built_at_windows', versionKey: 'version_windows', label: 'Windows — .msi (GPO)', desc: 'Déploiement de parc via GPO/script, jeton pré-rempli possible' },
  { href: '/api/agents/latest/linux', os: 'linux', dateKey: 'built_at_linux', versionKey: 'version_linux', label: 'Linux — .deb', desc: 'apt install ./allsafe-agent*.deb' },
]

// Version + date de build affichées par option (19/08/2026, demande explicite) — un
// utilisateur a téléchargé un paquet obsolète resservi par le cache disque du navigateur
// (le nom de fichier seul ne suffisait pas à s'en rendre compte, cf. STATUS.md). Vient de
// `GET /agents/latest/version` (déjà interrogée pour le badge de version du titre).
function DownloadDropdown({ color, versionInfo }) {
  const [open, setOpen] = useState(false)
  const [menuStyle, setMenuStyle] = useState({})
  const btnRef = useRef(null)
  const menuRef = useRef(null)

  useEffect(() => {
    if (!open) return
    function handler(e) {
      if (
        btnRef.current && !btnRef.current.contains(e.target) &&
        menuRef.current && !menuRef.current.contains(e.target)
      ) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  // `position: fixed` mesuré (pas `absolute`) — cf. AssetSearchSelect ci-dessus : le menu
  // était rendu à l'intérieur de PageHero, dont le conteneur racine a `overflow-hidden`
  // (trame de points/lueur d'ambiance), ce qui coupait le menu au lieu de le montrer
  // (retour utilisateur, "caché dans la tuile d'agent").
  function openMenu() {
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      setMenuStyle({ position: 'fixed', top: r.bottom + 6, right: window.innerWidth - r.right, zIndex: 9999 })
    }
    setOpen(o => !o)
  }

  return (
    <>
      <button ref={btnRef} onClick={openMenu}
        className="px-4 py-2 text-sm font-medium rounded-lg flex items-center gap-1.5"
        style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
        Télécharger l'agent
        <svg className="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={open ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7'} />
        </svg>
      </button>
      {open && (
        <div ref={menuRef} className="rounded-xl overflow-hidden"
          style={{ ...menuStyle, width: 310, background: 'var(--bg-card)', border: '1px solid var(--border)', boxShadow: '0 8px 24px rgba(0,0,0,0.35)' }}>
          {DOWNLOAD_OPTIONS.map(o => (
            <a key={o.href} href={o.href} onClick={() => setOpen(false)}
              className="flex items-start gap-2.5 px-3.5 py-2.5 transition-colors"
              style={{ borderBottom: '1px solid var(--border)' }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <span className="flex-shrink-0 mt-0.5"><OsLogo os={o.os} size={18} /></span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium" style={{ color }}>{o.label}</p>
                  {versionInfo?.[o.versionKey] && (
                    <span className="flex-shrink-0 text-[11px] font-bold px-1.5 py-0.5 rounded"
                      style={{ color, background: 'rgba(57,197,207,0.15)' }}>
                      v{versionInfo[o.versionKey]}
                    </span>
                  )}
                </span>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{o.desc}</p>
                {versionInfo?.[o.versionKey] && (
                  <p className="text-xs mt-1 font-semibold" style={{ color: 'var(--text-secondary)' }}>
                    Construit le {formatDateTime(versionInfo[o.dateKey])}
                  </p>
                )}
              </span>
            </a>
          ))}
        </div>
      )}
    </>
  )
}

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
  // Version courante de l'agent (18/08/2026, demande explicite ; versionnement séparé par
  // plateforme le 19/08/2026) — affichée à côté du titre de page, même source que le champ
  // `outdated` de chaque ligne (CURRENT_AGENT_VERSION_WINDOWS/_LINUX, cf. routers/agents.py),
  // déjà exposée publiquement pour la distribution des paquets (GET /agents/latest/version,
  // utilisé aussi par l'agent lui-même pour se mettre à jour). Objet complet
  // (version_windows/version_linux + built_at_windows/linux) — pas de version "unique",
  // .exe/.msi et .deb évoluent indépendamment.
  const [latestVersionInfo, setLatestVersionInfo] = useState(null)
  useEffect(() => { agentLatestVersion().then(r => setLatestVersionInfo(r.data)).catch(() => {}) }, [])

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

  // Poll léger pendant un scan à la demande (19/08/2026, demande explicite) — le scan se
  // termine quand l'agent, au prochain sondage court côté lui (`GET /pending`, jusqu'à 60s),
  // le détecte et pousse un check-in : rien côté serveur ne prévient la page quand c'est fait,
  // il faut redemander la liste pour le voir. Silencieux (pas de `setLoading`, sinon le
  // PageLoader plein écran clignoterait à chaque tick) ; ne tourne QUE tant qu'au moins un
  // agent a un scan en attente — pas de polling permanent inutile le reste du temps.
  const hasPendingScan = agentList.some(a => a.pending_scan_requested_at)
  useEffect(() => {
    if (!hasPendingScan) return
    const id = setInterval(() => {
      listAgents().then(r => {
        const agents = r.data?.items || []
        setAgentList(agents)
        agentsCache = { ...agentsCache, agentList: agents }
      }).catch(() => {})
    }, 5000)
    return () => clearInterval(id)
  }, [hasPendingScan])

  async function handleRequestScan(agentId) {
    await requestAgentScan(agentId)
    load()
  }
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
        title={<>Agents{(latestVersionInfo?.version_windows || latestVersionInfo?.version_linux) && (
          <Link to="/agents/notes-de-version" title="Voir les notes de version de l'agent"
            className="text-xs font-semibold px-2 py-0.5 rounded-full hover:underline"
            style={{ color: '#39c5cf', background: 'rgba(57,197,207,0.12)', border: '1px solid rgba(57,197,207,0.3)' }}>
            Win v{latestVersionInfo.version_windows} · Linux v{latestVersionInfo.version_linux}
          </Link>
        )}<Link to="/agents/historique" title="Historique global des agents, y compris révoqués et supprimés"
            className="text-xs font-semibold px-2 py-0.5 rounded-full hover:underline ml-1.5 align-middle"
            style={{ color: '#39c5cf', background: 'rgba(57,197,207,0.12)', border: '1px solid rgba(57,197,207,0.3)' }}>
            Historique
          </Link></>}
        color="#39c5cf"
        subtitle="Collecte alternative pour les postes, en complément du compte de service AD/SSH — lecture seule."
      >
        <div className="flex items-center gap-2">
          <DownloadDropdown color={MODULE_COLOR} versionInfo={latestVersionInfo} />
          {isAdmin && (
            <button onClick={() => setTokenModal(true)}
              className="px-4 py-2 text-sm font-medium rounded-lg"
              style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}>
              + Jeton d'enrôlement
            </button>
          )}
        </div>
      </PageHero>

      {error && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
          {error}
        </div>
      )}

      <div className="rounded-2xl overflow-hidden" style={tintedCard(MODULE_COLOR)}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Hôte', 'OS', 'Distribution', 'Actif lié', 'Version', 'Dernier contact', 'Statut', 'État', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {!loading && agentList.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucun agent enrôlé</p>
                    <p className="text-xs">Générez un jeton d'enrôlement pour poser l'agent sur un poste</p>
                  </td>
                </tr>
              )}
              {agentList.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-primary)' }}>
                    <span className="inline-flex items-center gap-2">
                      {a.hostname}
                      {a.pending_scan_requested_at && (
                        <span title="Scan en cours…"><PageLoader size="sm" label="" color={MODULE_COLOR} /></span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <OsLogo os={a.os} size={18} />
                  </td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap"><DistroBadge os={a.asset_os} version={a.asset_os_version} /></td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{a.asset_name || '—'}</td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap"><VersionBadge version={a.agent_version} outdated={a.outdated} /></td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap">
                    <Link to={`/agents/${a.id}`} className="inline-flex items-center gap-1.5 hover:underline"
                      title="Voir l'historique des contacts de cet agent"
                      style={{ color: FRESHNESS_COLOR[contactFreshness(a.last_seen_at)] }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: 'currentColor' }} />
                      {formatDateTime(a.last_seen_at)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap"><StatusBadge value={a.status} /></td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap"><TokenStateBadge status={a.token_status} /></td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    {isAdmin && a.status === 'enrolled' && !a.pending_scan_requested_at && (
                      <button onClick={() => handleRequestScan(a.id)}
                        className="text-xs px-2.5 py-1.5 rounded-lg font-medium mr-1.5"
                        style={{ background: 'var(--bg-secondary)', color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}33` }}>
                        Scanner maintenant
                      </button>
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
        <div className="rounded-2xl overflow-hidden" style={tintedCard(MODULE_COLOR)}>
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
