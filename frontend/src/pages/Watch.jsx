import { useEffect, useState, useCallback, useRef } from 'react'
import {
  watchItems, updateWatch, watchStats, syncWatch, watchSyncStatus, watchLeakSources,
  watchSources, createWatchSource, deleteWatchSource, assetNames as fetchAssetNames,
} from '../api/client.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import AddSourceModal from '../components/AddSourceModal.jsx'
import AssetDropdown from '../components/AssetDropdown.jsx'
import MarkdownNote from '../components/MarkdownNote.jsx'
import WatchProfileModal from '../components/WatchProfileModal.jsx'
import PageLoader from '../components/PageLoader.jsx'
import DeclareIncidentButton from '../components/DeclareIncidentButton.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import PageHero from '../components/PageHero.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_WATCH_ITEMS, isFakeId, anonymizeWatchItem, anonymizeAsset } from '../utils/fakeData.js'

const WATCH_ACCENT = '#58a6ff'

const CARD = tintedCard(WATCH_ACCENT)

// ─── Constantes ───────────────────────────────────────────────────────────────

// Sources dédiées "fuite de données" — désormais leur propre onglet informatif
// (cf. FuiteDeDonnees.jsx), retirées de Veille technologique (sélecteur ET
// résultats, via exclude_source dans loadItems/loadKpis). Liste de secours
// utilisée avant la résolution de GET /api/watch/leak-sources (qui inclut en
// plus les sources personnalisées ajoutées via l'onglet Fuite de données) —
// tenir synchronisée avec BUILTIN_LEAK_SOURCES côté backend
// (services/watch_fetcher.py) en cas d'ajout/retrait d'une source native.
export const BUILTIN_LEAK_SOURCES = ['zataz', 'fuitesinfos', 'ransomware-live', 'databreaches-net', 'hibp']

const SOURCES = [
  { value: 'cert-fr-avis',        label: 'CERT-FR Avis' },
  { value: 'cert-fr-alerte',      label: 'CERT-FR Alertes' },
  { value: 'cert-fr-bulletin',    label: 'CERT-FR Bulletins' },
  { value: 'anssi',               label: 'ANSSI' },
  { value: 'cnil',                label: 'CNIL' },
  { value: 'cybermalveillance',   label: 'Cybermalveillance' },
  { value: 'it-connect',          label: 'IT Connect' },
  { value: 'global-security-mag', label: 'Global Security Mag' },
  { value: 'sekoia',              label: 'Sekoia Blog' },
  { value: 'harfanglab',          label: 'HarfangLab Blog' },
  { value: 'synacktiv',           label: 'Synacktiv Blog' },
  { value: 'intrinsec',           label: 'Intrinsec Blog' },
  { value: 'nolimitsecu',         label: 'No Limit Secu' },
]

const SEVERITIES = [
  { value: 'critical',      label: 'Critique',   color: 'rgba(248,81,73,0.12)',  text: '#f85149', border: 'rgba(248,81,73,0.3)'  },
  { value: 'important',     label: 'Important',  color: 'rgba(251,143,68,0.12)', text: '#fb8f44', border: 'rgba(251,143,68,0.3)' },
  { value: 'informational', label: 'Informatif', color: 'rgba(88,166,255,0.12)', text: '#58a6ff', border: 'rgba(88,166,255,0.3)' },
]

const THEMES = [
  'Admin', 'APT', 'Cyber', 'Données', 'Hardware', 'IA',
  'Ransomware', 'Réglementation', 'Réseau', 'Software', 'Vulnérabilité',
]

const SEV_STYLES = {
  critical:      { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  important:     { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  informational: { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
}
const SEV_LABELS = { critical: 'Critique', important: 'Important', informational: 'Informatif' }

const STATUS_STYLES = {
  new:            { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  in_review:      { background: 'rgba(88,166,255,0.12)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  treated:        { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  // Violet et non gris : "Non concerné" était strictement identique à "Nouveau"
  // (même gris), donc indistinguable — dans le tableau comme dans les filtres.
  // Le violet est déjà la couleur de "Faux positif" côté vulnérabilités, même
  // idée sémantique (« ça ne nous concerne pas »), cf. docs/FRONTEND.md.
  not_applicable: { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
}

// Version renforcée des couleurs de statut, pour l'**état sélectionné** des puces
// de filtre : les badges du tableau vivent sur fond neutre et se contentent d'un
// fond à 12% d'opacité, illisible dès qu'il sert à signaler « ce filtre est
// actif ». Fond plus dense, bordure pleine et texte plus clair pour "Nouveau",
// dont le gris ne ressortait pas du tout.
const STATUS_FILTER_STYLES = {
  new:            { background: 'rgba(139,148,158,0.35)', color: '#e6edf3', border: '1px solid #8b949e' },
  in_review:      { background: 'rgba(88,166,255,0.28)',  color: '#79c0ff', border: '1px solid #58a6ff' },
  treated:        { background: 'rgba(63,185,80,0.28)',   color: '#56d364', border: '1px solid #3fb950' },
  not_applicable: { background: 'rgba(163,113,247,0.28)', color: '#c297ff', border: '1px solid #a371f7' },
}
const STATUS_LABELS = { new: 'Nouveau', in_review: 'En cours', treated: 'Traité', not_applicable: 'Non concerné' }

// ─── Sous-composants ──────────────────────────────────────────────────────────

function SevBadge({ value }) {
  const s = SEV_STYLES[value] || SEV_STYLES.informational
  return (
    <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {SEV_LABELS[value] ?? value}
    </span>
  )
}

// `onClick` rend le badge cliquable dans le tableau — ouvrir le détail depuis
// le statut est le geste naturel quand on cherche « pourquoi cet élément est
// dans cet état ». Reste un simple <span> ailleurs (modale), sans faux affordage.
function StatusBadge({ value, onClick }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.new
  return (
    <span onClick={onClick}
      title={onClick ? 'Voir le détail' : undefined}
      className={onClick ? 'transition-opacity hover:opacity-70' : undefined}
      style={{
        ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600,
        display: 'inline-block', cursor: onClick ? 'pointer' : undefined,
      }}>
      {STATUS_LABELS[value] ?? value}
    </span>
  )
}

function ThemeTag({ value, small }) {
  return (
    <span style={{
      background: 'rgba(88,166,255,0.08)', color: '#58a6ff',
      border: '1px solid rgba(88,166,255,0.2)',
      borderRadius: 5, padding: small ? '1px 6px' : '2px 7px',
      fontSize: small ? 10 : 11, fontWeight: 500, display: 'inline-block',
    }}>
      {value}
    </span>
  )
}

function Btn({ children, onClick, variant = 'primary', disabled, small }) {
  // `primary` teinté à la couleur du module CyberVeille (11/08/2026, tour visuel — cohérence
  // sidebar → page) plutôt que l'accent-blue générique — sans risque de collision sémantique
  // ici (contrairement à CyberVuln, dont le rouge sert aussi de code "sévérité").
  const variants = {
    primary:   { background: WATCH_ACCENT, color: MODULES.cyberveille.dark, border: 'none' },
    success:   { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)'   },
    secondary: { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
  }
  return (
    <button onClick={onClick} disabled={disabled}
      className={`${small ? 'text-xs px-2.5 py-1.5' : 'text-sm px-4 py-2'} rounded-lg font-medium transition-colors disabled:opacity-40`}
      style={variants[variant] || variants.secondary}
    >
      {children}
    </button>
  )
}

// Icônes des KPI — même famille (Heroicons outline) que le reste de l'app.
const KPI_ICON_PATHS = {
  warning: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  clock:   'M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z',
  check:   'M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
}

// `accent` porte l'identité propre de chaque KPI (une couleur par carte, pas un
// gris uniforme) — `highlight` reste la seule alerte rouge prioritaire (état
// "critique non traité", cf. logique existante), qui écrase l'accent quand vraie.
// Gabarit très resserré (px-3/py-2, valeur text-base) + rangée forcée à
// l'horizontale côté conteneur (flex nowrap, cf. appel ci-dessous) : les
// versions précédentes (grid, plus grand padding) restaient hautes et
// pouvaient retomber à une tuile par ligne sur un écran étroit.
function KpiCard({ label, value, sub, highlight, icon, accent = 'var(--text-muted)' }) {
  const tint = highlight ? '#f85149' : accent
  return (
    <div style={{
      ...CARD,
      boxShadow: `inset 3px 0 0 0 ${highlight ? '#f85149' : `color-mix(in srgb, ${accent} 50%, transparent)`}`,
      ...(highlight ? { border: '1px solid rgba(248,81,73,0.4)', background: 'rgba(248,81,73,0.05)' } : {}),
    }} className="lift-card group px-3 py-2 min-w-0">
      <div className="flex items-center gap-1.5 mb-1">
        {icon && (
          <span className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 transition-transform duration-200 group-hover:scale-110" style={{
            background: `color-mix(in srgb, ${tint} 16%, transparent)`,
            color: tint,
          }}>
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icon} />
            </svg>
          </span>
        )}
        <p className="text-[10px] font-semibold uppercase tracking-wide truncate" style={{ color: tint }}>{label}</p>
      </div>
      <p className="text-base font-bold truncate" style={{ color: highlight ? '#f85149' : 'var(--text-primary)' }}>{value ?? '—'}</p>
      {sub && <p className="text-[11px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>{sub}</p>}
    </div>
  )
}

// Dropdown multi-select pour les sources — panneau horizontal 3 colonnes.
// Regroupement par valeur explicite (pas par tranche d'index) : robuste si
// SOURCES est modifiée plus tard (ex: retrait des sources "fuite de données").
const OFFICIAL_SOURCES = ['cert-fr-avis', 'cert-fr-alerte', 'cert-fr-bulletin', 'anssi', 'cnil', 'cybermalveillance']
const EDITOR_SOURCES = ['sekoia', 'harfanglab', 'synacktiv', 'intrinsec', 'nolimitsecu']
const SOURCE_GROUPS = [
  { label: 'Officielles',      sources: SOURCES.filter(s => OFFICIAL_SOURCES.includes(s.value)) },
  { label: 'Médias & trackers', sources: SOURCES.filter(s => !OFFICIAL_SOURCES.includes(s.value) && !EDITOR_SOURCES.includes(s.value)) },
  { label: 'Éditeurs sécu',    sources: SOURCES.filter(s => EDITOR_SOURCES.includes(s.value)) },
]

function SourceDropdown({ selected, onChange, customSources, onDeleteCustom, onAddNew }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function toggle(val) {
    onChange(selected.includes(val) ? selected.filter(s => s !== val) : [...selected, val])
  }

  const allLabeled = [...SOURCES, ...customSources.map(s => ({ value: s.slug, label: s.name }))]
  const label = selected.length === 0
    ? 'Toutes les sources'
    : selected.length === 1
      ? (allLabeled.find(s => s.value === selected[0])?.label ?? selected[0])
      : `${selected.length} sources`

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 text-sm px-3 py-1.5 rounded-lg"
        style={{
          background: selected.length > 0 ? 'rgba(88,166,255,0.1)' : 'var(--bg-secondary)',
          color: selected.length > 0 ? '#58a6ff' : 'var(--text-secondary)',
          border: selected.length > 0 ? '1px solid rgba(88,166,255,0.3)' : '1px solid var(--border)',
        }}
      >
        {label}
        <svg className="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={open ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7'} />
        </svg>
      </button>

      {open && (
        <div
          className="absolute z-50 mt-1 rounded-xl"
          style={{
            top: '100%', left: 0,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          }}
        >
          {/* Panneau horizontal : 3 colonnes fixes + 1 colonne "Personnalisées" */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0 }}>
            {SOURCE_GROUPS.map((group) => (
              <div key={group.label} style={{ borderRight: '1px solid var(--border)', minWidth: 170 }}>
                <p className="px-4 pt-3 pb-1.5 text-xs font-bold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {group.label}
                </p>
                {group.sources.map(src => (
                  <label key={src.value}
                    className="flex items-center gap-2.5 px-4 py-1.5 cursor-pointer text-sm"
                    style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <input
                      type="checkbox"
                      checked={selected.includes(src.value)}
                      onChange={() => toggle(src.value)}
                      className="w-3.5 h-3.5 accent-blue-500 flex-shrink-0"
                    />
                    {src.label}
                  </label>
                ))}
              </div>
            ))}
            <div style={{ minWidth: 190 }}>
              <p className="px-4 pt-3 pb-1.5 text-xs font-bold uppercase tracking-wider"
                style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                Personnalisées
              </p>
              {customSources.length === 0 && (
                <p className="px-4 py-1.5 text-xs" style={{ color: 'var(--text-faint)' }}>Aucune source ajoutée</p>
              )}
              {customSources.map(src => (
                <div key={src.id}
                  className="flex items-center gap-1.5 px-4 py-1.5 text-sm"
                  style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <label className="flex items-center gap-2.5 cursor-pointer flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={selected.includes(src.slug)}
                      onChange={() => toggle(src.slug)}
                      className="w-3.5 h-3.5 accent-blue-500 flex-shrink-0"
                    />
                    <span className="truncate">{src.name}</span>
                  </label>
                  <button onClick={() => onDeleteCustom(src)} title="Retirer cette source"
                    className="text-xs w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ color: 'var(--text-muted)' }}
                  >×</button>
                </div>
              ))}
              <div className="px-4 py-2">
                <button onClick={onAddNew} className="text-xs font-medium" style={{ color: WATCH_ACCENT }}>
                  + Ajouter une source
                </button>
              </div>
            </div>
          </div>
          {selected.length > 0 && (
            <div className="px-4 py-2.5" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={() => onChange([])} className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Tout décocher ({selected.length} sélectionnée{selected.length > 1 ? 's' : ''})
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Chip cliquable pour filtres multi-sélection
function FilterChip({ label, active, onClick, activeStyle }) {
  return (
    <button
      onClick={onClick}
      className="text-xs px-2.5 py-1 rounded-lg font-medium transition-colors"
      style={active
        ? { ...(activeStyle || { background: 'rgba(88,166,255,0.15)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }) }
        : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
      }
    >
      {label}
    </button>
  )
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function Watch() {
  const { names: ANALYSTS } = useAnalysts()
  const [data, setData]     = useState({ items: [], total: 0 })
  const [kpis, setKpis]     = useState(null)
  const [page, setPage]     = useState(1)
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [modal, setModal]   = useState(null)
  // Ligne mise en avant après un clic sur "Traiter"/"Consulter" — reste
  // surlignée le temps de retrouver l'item après avoir ouvert le lien source
  // dans un nouvel onglet, jusqu'au prochain clic sur un autre item (demande
  // utilisateur, 29/07/2026). Volontairement en mémoire seulement (pas
  // persisté) : un repère de session de travail, pas un état métier.
  const [activeItemId, setActiveItemId] = useState(null)
  const [form, setForm]     = useState({ status: '', severity: '', reviewed_by: '', decision: '', linked_cve_id: '', asset_ids: [] })
  // Parc, pour le sélecteur "Actifs concernés" de la modale de traitement.
  const [assetList, setAssetList] = useState([])
  const [saving, setSaving] = useState(false)
  const [msg, setMsg]       = useState({ text: '', type: 'info' })
  const [lastSyncedAt, setLastSyncedAt] = useState(null)
  const perPage = 50

  // Filtres multi-sélection — Critique + Nouveau présélectionnés par défaut :
  // c'est ce qui est réellement urgent à l'arrivée sur la page, pas besoin de
  // le resélectionner à chaque visite (demande utilisateur, 29/07/2026).
  const [selSources,    setSelSources]    = useState([])
  const [selSeverities, setSelSeverities] = useState(['critical'])
  const [selThemes,     setSelThemes]     = useState([])
  const [selStatuses,   setSelStatuses]   = useState(['new'])
  const [slaOnly,       setSlaOnly]       = useState(false)
  const [profileOnly,   setProfileOnly]   = useState(false)
  const [showProfile,   setShowProfile]   = useState(false)
  const [profileCount,  setProfileCount]  = useState(0)   // nb de termes configurés
  const { isAnonymous } = usePresentation()

  // Sources "fuite de données" à exclure (natives + personnalisées) — résolu
  // dynamiquement pour qu'une source ajoutée via Fuite de données disparaisse
  // aussi automatiquement d'ici, sans redéploiement.
  const [leakSources, setLeakSources] = useState(BUILTIN_LEAK_SOURCES)
  useEffect(() => { watchLeakSources().then(r => setLeakSources(r.data.sources)).catch(() => {}) }, [])

  // Parc chargé une fois : alimente le sélecteur "Actifs concernés" de la
  // modale de traitement (l'analyste rattache une alerte aux machines visées).
  useEffect(() => {
    fetchAssetNames()
      .then(r => setAssetList([...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name))))
      .catch(() => {})
  }, [])

  useEffect(() => {
    watchSyncStatus().then(r => setLastSyncedAt(r.data.last_synced_at)).catch(() => {})
  }, [])

  // Sources RSS/Atom personnalisées ajoutées depuis cette page (category
  // "general" — distinctes de celles ajoutées depuis Fuite de données, cf.
  // AddSourceModal / GET /watch/sources?category=general).
  const [customSources, setCustomSources] = useState([])
  const [showAddSource, setShowAddSource] = useState(false)

  const reloadCustomSources = useCallback(() => {
    watchSources({ category: 'general' }).then(r => setCustomSources(r.data.custom)).catch(() => {})
  }, [])
  useEffect(() => { reloadCustomSources() }, [reloadCustomSources])

  async function handleAddSource(payload) {
    await createWatchSource(payload)
    setShowAddSource(false)
    flash(`Source « ${payload.name} » ajoutée — synchronisation…`, 'success')
    reloadCustomSources()
    await handleSync()
  }

  const [pendingDeleteSource, setPendingDeleteSource] = useState(null)

  function handleDeleteSource(source) {
    setPendingDeleteSource(source)
  }

  async function confirmDeleteSource() {
    const source = pendingDeleteSource
    await deleteWatchSource(source.id)
    setSelSources(s => s.filter(v => v !== source.slug))
    reloadCustomSources()
    setPendingDeleteSource(null)
  }

  const hasFilters = selSources.length > 0 || selSeverities.length > 0 || selThemes.length > 0
    || selStatuses.length > 0 || slaOnly || profileOnly

  function resetFilters() {
    setSelSources([]); setSelSeverities([]); setSelThemes([]); setSelStatuses([])
    setSlaOnly(false); setProfileOnly(false); setPage(1)
  }

  function toggleStatus(val) {
    setSelStatuses(s => s.includes(val) ? s.filter(x => x !== val) : [...s, val])
    setPage(1)
  }

  function toggleSev(val) {
    setSelSeverities(s => s.includes(val) ? s.filter(x => x !== val) : [...s, val])
    setPage(1)
  }

  function toggleTheme(val) {
    setSelThemes(s => s.includes(val) ? s.filter(x => x !== val) : [...s, val])
    setPage(1)
  }

  const loadItems = useCallback(() => {
    setLoading(true)
    const params = { page, per_page: perPage, exclude_source: leakSources.join(',') }
    if (selSources.length)    params.source   = selSources.join(',')
    if (selSeverities.length) params.severity = selSeverities.join(',')
    if (selThemes.length)     params.themes   = selThemes.join(',')
    if (selStatuses.length)   params.status   = selStatuses.join(',')
    if (slaOnly)              params.sla_only = true
    if (profileOnly)          params.profile_only = true
    watchItems(params)
      .then(r => { setData(r.data); setProfileCount((r.data.profile_terms || []).length) })
      .finally(() => setLoading(false))
  }, [page, selSources, selSeverities, selThemes, selStatuses, slaOnly, profileOnly, leakSources])

  const loadKpis = useCallback(() => {
    watchStats(30, { exclude_source: leakSources.join(',') }).then(r => setKpis(r.data)).catch(() => {})
  }, [leakSources])

  useEffect(() => { loadItems() }, [loadItems])
  useEffect(() => { loadKpis() },  [loadKpis])

  function flash(text, type = 'info') {
    setMsg({ text, type })
    setTimeout(() => setMsg({ text: '', type: 'info' }), 4000)
  }

  function openModal(item) {
    setModal(item)
    setForm({
      asset_ids:     item.asset_ids || [],
      status:        item.status,
      severity:      item.severity,
      reviewed_by:   item.reviewed_by || '',
      decision:      item.decision || '',
      linked_cve_id: item.linked_cve_id || '',
    })
  }

  async function handleSync() {
    setSyncing(true)
    try {
      const r = await syncWatch()
      flash(`Sync terminée — ${r.data.inserted} nouveaux items, ${r.data.skipped} doublons ignorés`, 'success')
      if (r.data.synced_at) setLastSyncedAt(r.data.synced_at)
      loadItems(); loadKpis()
    } catch { flash('Erreur lors de la synchronisation.', 'error') }
    finally { setSyncing(false) }
  }

  async function handleSave() {
    if (!modal) return
    setSaving(true)
    try {
      const payload = {}
      if (form.status        !== modal.status)                    payload.status        = form.status
      if (form.severity      !== modal.severity)                  payload.severity      = form.severity
      if (form.reviewed_by   !== (modal.reviewed_by   || ''))     payload.reviewed_by   = form.reviewed_by   || null
      if (form.decision      !== (modal.decision      || ''))     payload.decision      = form.decision      || null
      if (form.linked_cve_id !== (modal.linked_cve_id || ''))     payload.linked_cve_id = form.linked_cve_id || null
      // Comparaison sur le contenu trié : l'ordre de sélection n'est pas une
      // modification, et un tableau neuf est toujours !== de l'ancien.
      const before = [...(modal.asset_ids || [])].sort().join(',')
      const after  = [...(form.asset_ids  || [])].sort().join(',')
      if (before !== after) payload.asset_ids = form.asset_ids

      if (Object.keys(payload).length === 0) { setModal(null); return }

      // Item de démonstration (mode Présentation) : pas d'appel API (n'existe pas en
      // base) — mutation directe du jeu fictif, il n'est jamais persisté nulle part.
      if (isFakeId(modal.id)) {
        const fake = FAKE_WATCH_ITEMS.find(w => w.id === modal.id)
        if (fake) {
          Object.assign(fake, payload)
          if (payload.status && payload.status !== 'new' && !fake.reviewed_at) fake.reviewed_at = new Date().toISOString()
        }
        flash('Item mis à jour', 'success')
        setModal(null)
        return
      }

      // Traiter une ligne regroupée = traiter tous ses membres (même actu, sources
      // multiples) : la même décision est appliquée à chacun pour que la base reste
      // cohérente et que le groupe ne réapparaisse pas comme « à traiter ».
      const ids = modal.group_item_ids?.length > 1 ? modal.group_item_ids : [modal.id]
      for (const id of ids) await updateWatch(id, payload)
      flash(ids.length > 1 ? `Groupe mis à jour — ${ids.length} sources` : 'Item mis à jour', 'success')
      setModal(null)
      loadItems()   // recharge pour refléter l'état fusionné du groupe
      loadKpis()
    } catch { flash('Erreur lors de la mise à jour.', 'error') }
    finally { setSaving(false) }
  }

  const totalPages        = Math.ceil(data.total / perPage)
  const criticalUntreated = kpis?.critical_untreated ?? null

  // Fake data ajoutée seulement en page 1, sans filtre source/thème/SLA/profil actif —
  // filtrée côté client sur sévérité/statut (les deux chips par défaut) pour rester
  // cohérente avec la sélection, sans dupliquer tout le filtrage serveur pour si peu.
  const noExtraFilter = selSources.length === 0 && selThemes.length === 0 && !slaOnly && !profileOnly
  const fakeWatchItems = FAKE_WATCH_ITEMS.filter(w =>
    (selSeverities.length === 0 || selSeverities.includes(w.severity)) &&
    (selStatuses.length === 0 || selStatuses.includes(w.status)))
  // Vraies lignes anonymisées (21/08/2026, retour utilisateur) avant l'ajout des fake data —
  // restaient jusqu'ici en clair (titre/résumé/décision/analyste), seules des lignes
  // FAKE_WATCH_ITEMS s'y ajoutaient.
  const anonymizedItems = isAnonymous ? data.items.map(w => anonymizeWatchItem(w, assetList)) : data.items
  const displayItems = isAnonymous && noExtraFilter && page === 1 ? [...anonymizedItems, ...fakeWatchItems] : anonymizedItems
  const displayAssetList = isAnonymous ? assetList.map(anonymizeAsset) : assetList

  // Couleur de ligne : la mise en avant "item en cours" prime sur les signaux
  // ambiants (SLA dépassé, correspondance profil) — c'est un repère explicite
  // posé par l'analyste, pas une alerte automatique.
  function rowBg(item, hover) {
    if (activeItemId === item.id) return hover ? 'rgba(210,153,34,0.18)' : 'rgba(210,153,34,0.12)'
    if (item.sla_exceeded) return hover ? 'rgba(248,81,73,0.08)' : 'rgba(248,81,73,0.04)'
    if (item.profile_matches?.length > 0) return hover ? 'rgba(88,166,255,0.1)' : 'rgba(88,166,255,0.05)'
    return hover ? 'rgba(88,166,255,0.03)' : 'transparent'
  }

  const msgColors = {
    info:    { background: 'rgba(88,166,255,0.1)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' },
    success: { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.2)' },
    error:   { background: 'rgba(248,81,73,0.1)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' },
  }

  return (
    <div className="p-6 space-y-5">

      {/* En-tête */}
      <PageHero
        icon="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z M15 12a3 3 0 11-6 0 3 3 0 016 0z"
        title="Veille technologique" color={WATCH_ACCENT}
        subtitle="Registre de veille auditable — conforme NIS 2"
      >
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-2">
            <Btn variant="primary" onClick={handleSync} disabled={syncing}>
              {syncing ? 'Sync…' : 'Synchroniser'}
            </Btn>
            {/* Profil de veille : cible la veille sur les OS/logiciels réellement
                présents dans le parc. Marque et trie — ne filtre jamais la collecte. */}
            <button onClick={() => setShowProfile(true)}
              title="Profil de veille — cibler sur les OS et logiciels de mon parc"
              className="p-2 rounded-lg transition-colors"
              style={{ background: 'var(--bg-secondary)', color: profileCount ? '#58a6ff' : 'var(--text-muted)', border: `1px solid ${profileCount ? 'rgba(88,166,255,0.4)' : 'var(--border)'}` }}>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>
          </div>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {lastSyncedAt
              ? `Dernière sync : ${new Date(lastSyncedAt).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`
              : 'Jamais synchronisé'}
          </span>
        </div>
      </PageHero>

      {/* Message flash */}
      {msg.text && (
        <div className="text-sm px-4 py-3 rounded-xl" style={msgColors[msg.type]}>{msg.text}</div>
      )}

      {/* KPIs — rangée forcée à l'horizontale (flex nowrap, pas un grid qui peut
          retomber à une tuile par ligne sur un écran étroit) ; défile plutôt que de
          s'empiler verticalement si la place manque vraiment. */}
      <div className="stagger flex flex-nowrap gap-2 overflow-x-auto pb-1">
        <div className="flex-1 min-w-[140px]"><KpiCard label="Critiques non traités" value={criticalUntreated} sub={`dont ${kpis?.by_status?.new ?? 0} nouveaux`} highlight={criticalUntreated > 0} icon={KPI_ICON_PATHS.warning} accent="#f85149" /></div>
        <div className="flex-1 min-w-[140px]"><KpiCard label="SLA critique dépassé (>48h)" value={kpis?.sla_exceeded}  sub="items critiques sans traitement"  highlight={(kpis?.sla_exceeded ?? 0) > 0} icon={KPI_ICON_PATHS.clock} accent="#d29922" /></div>
        <div className="flex-1 min-w-[140px]"><KpiCard label="Taux traitement (30j)"  value={kpis ? `${kpis.treatment_rate_pct}%` : null} sub={`${kpis?.period_treated ?? 0} / ${kpis?.period_total ?? 0} traités`} icon={KPI_ICON_PATHS.check} accent="#3fb950" /></div>
        <div className="flex-1 min-w-[140px]"><KpiCard label="Délai moyen traitement" value={kpis?.avg_treatment_delay_hours != null ? `${kpis.avg_treatment_delay_hours}h` : '—'} sub="sur les 30 derniers jours" icon={KPI_ICON_PATHS.clock} accent="#58a6ff" /></div>
      </div>

      {/* Filtres */}
      <div style={CARD} className="px-5 py-4 space-y-3">

        {/* Ligne 1 : sources + SLA + reset */}
        <div className="flex flex-wrap gap-3 items-center">
          <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Sources</span>
          <SourceDropdown
            selected={selSources} onChange={s => { setSelSources(s); setPage(1) }}
            customSources={customSources} onDeleteCustom={handleDeleteSource}
            onAddNew={() => setShowAddSource(true)}
          />

          <label className="flex items-center gap-2 cursor-pointer select-none ml-2">
            <input type="checkbox" checked={slaOnly} onChange={e => { setSlaOnly(e.target.checked); setPage(1) }} className="w-3.5 h-3.5 accent-red-500" />
            <span className="text-xs font-medium" style={{ color: slaOnly ? '#f85149' : 'var(--text-secondary)' }}>SLA critique dépassé</span>
          </label>

          {/* N'a de sens qu'une fois le profil configuré — sans termes, la case
              ne filtrerait rien et laisserait croire à un bug. */}
          {profileCount > 0 && (
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input type="checkbox" checked={profileOnly}
                onChange={e => { setProfileOnly(e.target.checked); setPage(1) }}
                className="w-3.5 h-3.5 accent-blue-500" />
              <span className="text-xs font-medium" style={{ color: profileOnly ? '#58a6ff' : 'var(--text-secondary)' }}>
                Concerne mon parc
              </span>
            </label>
          )}

          {hasFilters && (
            <button onClick={resetFilters} className="text-xs px-2.5 py-1.5 rounded-lg ml-auto"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
              Réinitialiser tout
            </button>
          )}
        </div>

        {/* Ligne 2 : sévérité */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-semibold uppercase tracking-wide w-24 flex-shrink-0" style={{ color: 'var(--text-muted)' }}>Sévérité</span>
          {SEVERITIES.map(s => (
            <FilterChip
              key={s.value} label={s.label}
              active={selSeverities.includes(s.value)}
              onClick={() => toggleSev(s.value)}
              activeStyle={{ background: s.color, color: s.text, border: `1px solid ${s.border}` }}
            />
          ))}
        </div>

        {/* Ligne 3 : traitement — suivi de l'avancement (« qu'est-ce qui me reste
            à traiter ? », « qu'ai-je déjà qualifié ? »). Couleurs reprises de
            STATUS_STYLES pour que la puce et le badge du tableau se répondent. */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-semibold uppercase tracking-wide w-24 flex-shrink-0" style={{ color: 'var(--text-muted)' }}>Traitement</span>
          {['new', 'in_review', 'treated', 'not_applicable'].map(v => (
            <FilterChip
              key={v} label={STATUS_LABELS[v]}
              active={selStatuses.includes(v)}
              onClick={() => toggleStatus(v)}
              activeStyle={STATUS_FILTER_STYLES[v]}
            />
          ))}
          {/* Raccourci du suivi quotidien : tout ce qui n'est pas encore qualifié,
              en un clic plutôt qu'en cochant deux puces. */}
          <button
            onClick={() => {
              const reste = ['new', 'in_review']
              const dejaActif = reste.every(v => selStatuses.includes(v)) && selStatuses.length === 2
              setSelStatuses(dejaActif ? [] : reste)
              setPage(1)
            }}
            className="text-xs px-2.5 py-1 rounded-lg font-medium transition-colors ml-2"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px dashed var(--border)' }}
            title="Nouveau + En cours — ce qu'il reste à qualifier"
          >
            Reste à traiter
          </button>
        </div>

        {/* Ligne 4 : thèmes */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-semibold uppercase tracking-wide w-24 flex-shrink-0" style={{ color: 'var(--text-muted)' }}>Thèmes</span>
          {THEMES.map(t => (
            <FilterChip key={t} label={t} active={selThemes.includes(t)} onClick={() => toggleTheme(t)} />
          ))}
        </div>
      </div>

      {showAddSource && (
        <AddSourceModal category="general" accent={WATCH_ACCENT} onConfirm={handleAddSource} onClose={() => setShowAddSource(false)} />
      )}

      {pendingDeleteSource && (
        <ConfirmModal
          title="Retirer cette source ?"
          message={<>Retirer la source « <strong>{pendingDeleteSource.name}</strong> » ? Les items déjà importés restent visibles.</>}
          confirmLabel="Retirer"
          busyLabel="Retrait…"
          onConfirm={confirmDeleteSource}
          onClose={() => setPendingDeleteSource(null)}
        />
      )}

      {showProfile && (
        <WatchProfileModal
          onClose={() => setShowProfile(false)}
          onSaved={n => {
            setProfileCount(n)
            if (n === 0) setProfileOnly(false)   // plus de termes : le filtre n'a plus d'objet
            setPage(1)
            loadItems()
            flash(`Profil de veille enregistré — ${n} terme${n > 1 ? 's' : ''}`, 'success')
          }}
        />
      )}

      {/* Tableau */}
      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['Reçu le', 'Source', 'Titre', 'Thèmes', 'Sévérité', 'CVEs', 'Statut', 'Analyste', 'Traité le', ''].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="stagger-rows">
              {loading && (
                <tr><td colSpan={10} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && displayItems.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-4 py-16 text-center" style={{ color: 'var(--text-muted)' }}>
                    <p className="text-sm font-medium mb-1">Aucun item de veille</p>
                    <p className="text-xs">Cliquez sur "Synchroniser" pour lancer la première collecte</p>
                  </td>
                </tr>
              )}
              {!loading && displayItems.map(item => (
                <tr key={item.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    // Priorité visuelle : la ligne marquée "en cours" (dernier clic sur
                    // Traiter/Consulter) prime sur les signaux ambiants — SLA dépassé
                    // (fond rouge + ⚠) et correspondance profil (fond bleu + liseré).
                    // Le petit badge ★ (colonne Thèmes) reste discret au milieu des
                    // tags ; la ligne entière teintée, elle, se repère en balayant
                    // la liste sans avoir à lire chaque badge un par un.
                    background: rowBg(item, false),
                    borderLeft: activeItemId === item.id
                      ? '3px solid rgba(210,153,34,0.7)'
                      : item.profile_matches?.length > 0 && !item.sla_exceeded
                        ? '3px solid rgba(88,166,255,0.4)' : '3px solid transparent',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = rowBg(item, true)}
                  onMouseLeave={e => e.currentTarget.style.background = rowBg(item, false)}
                >
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {item.received_at ? new Date(item.received_at).toLocaleDateString('fr-FR') : '—'}
                    {item.sla_exceeded && <span className="ml-1.5 font-bold" style={{ color: '#f85149' }}>⚠</span>}
                  </td>
                  <td className="px-4 py-3">
                    {/* Sources du groupe (même actu multi-sources) — une seule si
                        pas de doublon. Le nombre de badges signale le regroupement. */}
                    <div className="flex flex-wrap gap-1" style={{ maxWidth: 190 }}>
                      {(item.group_sources || [{ source: item.source, source_label: item.source_label }])
                        .slice(0, 3).map((s, i) => (
                          <span key={s.source || i} className="text-xs font-medium px-2 py-0.5 rounded whitespace-nowrap"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                            {s.source_label || s.source}
                          </span>
                        ))}
                      {(item.group_sources?.length || 1) > 3 && (
                        <span className="text-xs self-center" style={{ color: 'var(--text-muted)' }}>
                          +{item.group_sources.length - 3}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3" style={{ maxWidth: 280 }}>
                    <a href={item.url?.startsWith('urn:') ? undefined : item.url}
                      target="_blank" rel="noopener noreferrer"
                      className="text-sm font-medium hover:underline"
                      style={{ color: 'var(--text-primary)', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                      {item.title}
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {/* Marquage profil : l'élément mentionne un OS/logiciel du
                          parc. Informatif — rien n'est masqué pour autant. */}
                      {item.profile_matches?.length > 0 && (
                        <span title={`Correspond à votre profil de veille : ${item.profile_matches.join(', ')}`}
                          className="whitespace-nowrap"
                          style={{
                            background: 'rgba(88,166,255,0.15)', color: '#58a6ff',
                            border: '1px solid rgba(88,166,255,0.4)', borderRadius: 5,
                            padding: '1px 6px', fontSize: 10, fontWeight: 600, display: 'inline-block',
                          }}>
                          ★ {item.profile_matches.slice(0, 2).join(', ')}
                          {item.profile_matches.length > 2 ? ` +${item.profile_matches.length - 2}` : ''}
                        </span>
                      )}
                      {(item.themes || []).slice(0, 3).map(t => <ThemeTag key={t} value={t} small />)}
                      {(item.themes || []).length > 3 && (
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>+{item.themes.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap"><SevBadge value={item.severity} /></td>
                  <td className="px-4 py-3">
                    {item.cve_ids_found?.length > 0
                      ? <span className="text-xs font-mono font-semibold" style={{ color: '#58a6ff' }}>
                          {item.cve_ids_found.slice(0, 2).join(', ')}{item.cve_ids_found.length > 2 ? ` +${item.cve_ids_found.length - 2}` : ''}
                        </span>
                      : <span style={{ color: 'var(--text-muted)' }}>—</span>
                    }
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <StatusBadge value={item.status} onClick={() => openModal(item)} />
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {item.reviewed_by || <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap">
                    {item.reviewed_at
                      ? <span style={{ color: '#3fb950' }}>
                          {new Date(item.reviewed_at).toLocaleDateString('fr-FR')}
                          {item.delay_hours != null ? <span style={{ color: 'var(--text-muted)' }}> ({item.delay_hours}h)</span> : ''}
                        </span>
                      : <span style={{ color: 'var(--text-muted)' }}>—</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1.5 flex-wrap">
                      {/* Un élément déjà qualifié n'est plus « à traiter » : libellé et
                          couleur changent pour que l'analyste voie d'un coup d'œil ce
                          qui lui reste à faire, sans lire la colonne Statut. */}
                      {item.status === 'new' || item.status === 'in_review'
                        ? <Btn small variant="secondary" onClick={() => { setActiveItemId(item.id); openModal(item) }}>Traiter</Btn>
                        : <Btn small variant="success" onClick={() => { setActiveItemId(item.id); openModal(item) }}>Consulter</Btn>}
                      {(item.severity === 'critical' || item.severity === 'important') && (
                        <DeclareIncidentButton sourceType="watch_item" sourceId={item.id} />
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="px-5 py-3.5 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{data.total} résultats</span>
            <div className="flex items-center gap-2">
              <Btn small variant="secondary" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Préc.</Btn>
              <span className="text-xs px-2" style={{ color: 'var(--text-muted)' }}>Page {page} / {totalPages}</span>
              <Btn small variant="secondary" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Suiv. →</Btn>
            </div>
          </div>
        )}
      </div>

      {/* Modal traitement */}
      {modal && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in"
          onClick={() => setModal(null)}>
          <div className="max-w-2xl w-full max-h-[90vh] flex flex-col rounded-2xl animate-modal-in"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
            onClick={e => e.stopPropagation()}>

            {/* Header */}
            <div className="px-6 py-4 flex items-start justify-between gap-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <SevBadge value={modal.severity} />
                  {(modal.group_sources || [{ source: modal.source, source_label: modal.source_label }]).map((s, i) => (
                    <span key={s.source || i} className="text-xs px-2 py-0.5 rounded"
                      style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                      {s.source_label || s.source}
                    </span>
                  ))}
                  {(modal.themes || []).map(t => <ThemeTag key={t} value={t} small />)}
                </div>
                <h2 className="text-base font-semibold leading-tight" style={{ color: 'var(--text-primary)' }}>{modal.title}</h2>
                {/* Liens : une entrée par source du groupe (même actu republiée). */}
                <div className="flex flex-wrap gap-x-3 gap-y-1 mt-1">
                  {(modal.group_sources || [{ source: modal.source, source_label: modal.source_label, url: modal.url }])
                    .filter(s => s.url && !s.url.startsWith('urn:'))
                    .map((s, i) => (
                      <a key={s.source || i} href={s.url} target="_blank" rel="noopener noreferrer"
                        className="text-xs inline-block hover:underline" style={{ color: '#58a6ff' }}>
                        Ouvrir {(modal.group_sources?.length || 1) > 1 ? (s.source_label || s.source) : 'la source'} →
                      </a>
                    ))}
                </div>
                {modal.group_size > 1 && (
                  <p className="text-xs mt-1.5" style={{ color: 'var(--text-muted)' }}>
                    Regroupe {modal.group_size} items de même titre — les traiter appliquera la décision à tous.
                  </p>
                )}
              </div>
              <button onClick={() => setModal(null)} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Corps */}
            <div className="overflow-y-auto flex-1 p-6 space-y-5">
              {modal.summary && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Résumé</p>
                  <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                    {modal.summary.length > 600 ? modal.summary.slice(0, 600) + '…' : modal.summary}
                  </p>
                </div>
              )}

              {modal.cve_ids_found?.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>CVEs détectées automatiquement</p>
                  <div className="flex flex-wrap gap-1.5">
                    {modal.cve_ids_found.map(cve => (
                      <span key={cve} className="font-mono text-xs px-2 py-0.5 rounded"
                        style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' }}>
                        {cve}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ borderTop: '1px solid var(--border)' }} />

              {/* Workflow */}
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Sévérité</p>
                <div className="flex gap-2 mb-4 flex-wrap">
                  {['critical', 'important', 'informational'].map(value => (
                    <button key={value} onClick={() => setForm(f => ({ ...f, severity: value }))}
                      className="text-sm px-3 py-1.5 rounded-lg font-medium transition-all"
                      style={form.severity === value
                        ? SEV_STYLES[value]
                        : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
                      }>
                      {SEV_LABELS[value]}
                    </button>
                  ))}
                </div>

                <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--text-muted)' }}>Traitement</p>

                <div className="flex gap-2 mb-4 flex-wrap">
                  {[
                    { value: 'in_review',      label: 'Prendre en charge' },
                    { value: 'treated',        label: 'Traité'            },
                    { value: 'not_applicable', label: 'Non concerné'      },
                  ].map(({ value, label }) => (
                    <button key={value} onClick={() => setForm(f => ({ ...f, status: value }))}
                      className="text-sm px-3 py-1.5 rounded-lg font-medium transition-all"
                      style={form.status === value
                        ? { background: 'var(--accent-blue)', color: '#fff', border: 'none' }
                        : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
                      }>
                      {label}
                    </button>
                  ))}
                </div>

                <div className="mb-3">
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-muted)' }}>Analyste</label>
                  <select value={form.reviewed_by} onChange={e => setForm(f => ({ ...f, reviewed_by: e.target.value }))}
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', width: '100%' }}>
                    <option value="">— Sélectionner —</option>
                    {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
                  </select>
                </div>

                <div className="mb-3">
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-muted)' }}>
                    CVE liée
                    {modal.cve_ids_found?.length > 0 && (
                      <span className="ml-2 font-normal" style={{ color: 'var(--text-muted)' }}>
                        (auto-détectée : {modal.cve_ids_found[0]})
                      </span>
                    )}
                  </label>
                  <input type="text" value={form.linked_cve_id}
                    onChange={e => setForm(f => ({ ...f, linked_cve_id: e.target.value }))}
                    placeholder="CVE-2025-XXXXX"
                    className="w-full text-sm rounded-lg px-3 py-2 font-mono"
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>

                <div className="mb-3">
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-muted)' }}>
                    Actifs concernés
                    <span className="ml-2 font-normal" style={{ color: 'var(--text-faint)' }}>(facultatif)</span>
                  </label>
                  <AssetDropdown
                    assetList={displayAssetList}
                    selected={form.asset_ids}
                    onChange={ids => setForm(f => ({ ...f, asset_ids: ids }))}
                  />
                </div>

                {/* Décision déjà enregistrée : affichée rendue en Markdown avant le
                    champ de saisie. Le texte reste modifiable juste en dessous —
                    on consulte et on corrige au même endroit, sans second écran. */}
                {modal.decision && (
                  <div className="mb-3 p-3 rounded-lg" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                    <p className="text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-muted)' }}>
                      Décision enregistrée
                      {modal.reviewed_by ? ` — ${modal.reviewed_by}` : ''}
                      {modal.reviewed_at ? ` · ${new Date(modal.reviewed_at).toLocaleDateString('fr-FR')}` : ''}
                    </p>
                    <MarkdownNote text={modal.decision} className="text-xs" />
                  </div>
                )}

                <div>
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-muted)' }}>
                    {modal.decision ? 'Modifier la décision / action' : 'Décision / Action'}
                  </label>
                  <textarea rows={3} value={form.decision}
                    onChange={e => setForm(f => ({ ...f, decision: e.target.value }))}
                    placeholder="Décrire l'action décidée ou la raison de non-applicabilité…"
                    className="w-full text-sm rounded-lg px-3 py-2 resize-none"
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--text-faint)' }}>
                    Markdown pris en charge (gras, listes, code…) — rendu à l'affichage.
                  </p>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-4 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Reçu le {modal.received_at ? new Date(modal.received_at).toLocaleDateString('fr-FR') : '—'}
                {modal.published_at && ` · Publié le ${new Date(modal.published_at).toLocaleDateString('fr-FR')}`}
              </div>
              <div className="flex gap-2">
                <Btn variant="secondary" onClick={() => setModal(null)}>Annuler</Btn>
                <Btn variant="primary" onClick={handleSave} disabled={saving}>
                  {saving ? 'Enregistrement…' : 'Enregistrer'}
                </Btn>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
