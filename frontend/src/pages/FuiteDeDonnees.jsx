import { useEffect, useState, useCallback, useRef } from 'react'
import {
  watchItems, syncWatch, watchSyncStatus, watchLeakSources, watchSources,
  createWatchSource, deleteWatchSource,
} from '../api/client.js'
import { BUILTIN_LEAK_SOURCES } from './Watch.jsx'
import FlagIcon from '../components/FlagIcon.jsx'
import AddSourceModal from '../components/AddSourceModal.jsx'
import { COUNTRIES } from '../utils/countries.js'
import { hexToRgba } from '../utils/color.js'
import PageLoader from '../components/PageLoader.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import PageHero from '../components/PageHero.jsx'

// Onglet 100% informatif — aucun rapport avec le registre auditable NIS 2 de
// Veille technologique (pas de statut/analyste/décision/SLA). Restreint aux
// sources dédiées à l'identification de fuites de bases de données (ZATAZ,
// fuitesinfos.fr, Ransomware.live, DataBreaches.net, Have I Been Pwned, +
// sources personnalisées ajoutées ici même) — les autres sources (CERT-FR,
// éditeurs sécu...) ne remontent jamais ici, même si un de leurs articles
// mentionne occasionnellement une fuite de données.
const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }
const ACCENT = '#a371f7'

// Icônes des KPI/pagination — même famille (Heroicons outline) que le reste de l'app.
const ICON_PATHS = {
  leak:    'M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z',
  sources: 'M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z',
  clock:   'M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z',
  chevronLeft:  'M15.75 19.5L8.25 12l7.5-7.5',
  chevronRight: 'M8.25 4.5l7.5 7.5-7.5 7.5',
}

function Icon({ d, className = 'w-4 h-4' }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={d} />
    </svg>
  )
}

// Tuile de stat — même gabarit resserré que KpiCard (Watch.jsx, cf. son commentaire pour
// le pourquoi de la largeur plafonnée) ; pas d'extraction partagée pour ce petit composant
// présentationnel dupliqué une 3e fois (cf. Dashboard.jsx/Watch.jsx) — dépasse le cadre
// d'une passe purement visuelle. `accent` distinct par tuile plutôt qu'un seul violet
// répété trois fois — plus de vie, chaque stat garde une identité propre au coup d'œil.
function StatTile({ label, value, sub, icon, accent = ACCENT }) {
  return (
    <div style={{ ...CARD, boxShadow: `inset 3px 0 0 0 color-mix(in srgb, ${accent} 50%, transparent)` }} className="lift-card group px-3 py-2 min-w-0">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 transition-transform duration-200 group-hover:scale-110" style={{ background: hexToRgba(accent, 0.16), color: accent }}>
          <Icon d={icon} className="w-3 h-3" />
        </span>
        <p className="text-[10px] font-semibold uppercase tracking-wide truncate" style={{ color: accent }}>{label}</p>
      </div>
      <p className="text-base font-bold truncate" style={{ color: 'var(--text-primary)' }}>{value ?? '—'}</p>
      {sub && <p className="text-[11px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>{sub}</p>}
    </div>
  )
}

const SOURCE_LABELS = {
  zataz: 'ZATAZ',
  fuitesinfos: 'fuitesinfos.fr',
  'ransomware-live': 'Ransomware.live',
  'databreaches-net': 'DataBreaches.net',
  hibp: 'Have I Been Pwned',
}

// Une couleur distincte par source — pas de teinte unique partagée comme
// avant, pour distinguer les cartes en un coup d'œil dans la grille.
const SOURCE_COLORS = {
  zataz: '#f0883e',
  fuitesinfos: '#58a6ff',
  'ransomware-live': '#f85149',
  'databreaches-net': '#d29922',
  hibp: '#bc8cff',
}

// Palette de repli pour les sources personnalisées (nombre arbitraire, pas de
// couleur pré-assignée possible) — dérivée du slug pour rester stable d'un
// chargement à l'autre.
const CUSTOM_PALETTE = ['#39c5cf', '#db61a2', '#7ee787', '#ffa657', '#79c0ff', '#e3b341']
function colorForSlug(slug) {
  let h = 0
  for (const c of slug) h = (h * 31 + c.charCodeAt(0)) >>> 0
  return CUSTOM_PALETTE[h % CUSTOM_PALETTE.length]
}

// Seule ransomware.live fournit un champ "victime" structuré — le titre est
// composé côté backend en "victime — groupe (activité)" (cf. watch_fetcher.py
// _fetch_ransomware_live). On l'éclate ici pour isoler le nom de l'entreprise
// du contexte (groupe/activité). Les autres sources (RSS dédiés + flux
// personnalisés) n'ont pas de champ entreprise séparé du titre — le titre EST
// déjà l'intitulé de l'entité concernée dans la plupart des cas pour ces flux
// dédiés "fuite", donc on l'utilise tel quel comme nom affiché.
function parseCompany(item) {
  if (item.source !== 'ransomware-live') return { company: item.title, context: '' }
  const m = item.title.match(/^(.*?) — (.*?)(?: \((.*)\))?$/)
  if (!m) return { company: item.title, context: '' }
  const [, victim, group, activity] = m
  return { company: victim, context: [group, activity].filter(Boolean).join(' · ') }
}

function Chip({ label, active, color, onClick }) {
  return (
    <button
      onClick={onClick}
      className="text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
      style={active
        ? { background: hexToRgba(color, 0.15), color, border: `1px solid ${hexToRgba(color, 0.35)}` }
        : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
      }
    >
      {label}
    </button>
  )
}

function truncate(text, max = 140) {
  if (!text) return ''
  return text.length > max ? text.slice(0, max).trimEnd() + '…' : text
}

function CountryDropdown({ selected, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function toggle(code) {
    onChange(selected.includes(code) ? selected.filter(c => c !== code) : [...selected, code])
  }

  const isCustom = selected.length > 0 && !(selected.length === 1 && selected[0] === 'FR')

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
        style={isCustom
          ? { background: hexToRgba(ACCENT, 0.15), color: ACCENT, border: `1px solid ${hexToRgba(ACCENT, 0.35)}` }
          : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
        }
      >
        {isCustom ? `Pays (${selected.length}) ▾` : 'Choisir des pays… ▾'}
      </button>
      {open && (
        <div style={CARD} className="absolute z-20 mt-1 w-56 max-h-72 overflow-y-auto p-2 shadow-xl">
          {COUNTRIES.map(c => (
            <label key={c.code}
              className="flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer text-xs"
              style={{ color: 'var(--text-primary)' }}
            >
              <input type="checkbox" checked={selected.includes(c.code)} onChange={() => toggle(c.code)} />
              <FlagIcon code={c.code} size={16} />
              <span>{c.label}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

export default function FuiteDeDonnees() {
  const [data, setData] = useState({ items: [], total: 0 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [selSource, setSelSource] = useState('') // '' = toutes les sources dédiées
  const [selCountries, setSelCountries] = useState(['FR']) // [] = monde entier
  const [msg, setMsg] = useState('')
  const [leakSources, setLeakSources] = useState(BUILTIN_LEAK_SOURCES) // natives + personnalisées
  const [customSources, setCustomSources] = useState([])
  const [showAddModal, setShowAddModal] = useState(false)
  const [lastSyncedAt, setLastSyncedAt] = useState(null)
  const perPage = 30

  const reloadSources = useCallback(() => {
    watchLeakSources().then(r => setLeakSources(r.data.sources)).catch(() => {})
    watchSources({ category: 'leak' }).then(r => setCustomSources(r.data.custom)).catch(() => {})
  }, [])

  useEffect(() => { reloadSources() }, [reloadSources])

  useEffect(() => {
    watchSyncStatus().then(r => setLastSyncedAt(r.data.last_synced_at)).catch(() => {})
  }, [])

  const loadItems = useCallback(() => {
    setLoading(true)
    const params = { page, per_page: perPage, source: selSource || leakSources.join(',') }
    if (selCountries.length) params.country = selCountries.join(',')
    watchItems(params).then(r => setData(r.data)).finally(() => setLoading(false))
  }, [page, selSource, selCountries, leakSources])

  useEffect(() => { loadItems() }, [loadItems])

  async function handleSync() {
    setSyncing(true)
    try {
      const r = await syncWatch()
      setMsg(`Sync terminée — ${r.data.inserted} nouveaux items`)
      if (r.data.synced_at) setLastSyncedAt(r.data.synced_at)
      loadItems()
    } catch {
      setMsg('Erreur lors de la synchronisation.')
    } finally {
      setSyncing(false)
      setTimeout(() => setMsg(''), 4000)
    }
  }

  async function handleAddSource(payload) {
    await createWatchSource(payload)
    setShowAddModal(false)
    setMsg(`Source « ${payload.name} » ajoutée — synchronisation…`)
    reloadSources()
    await handleSync()
  }

  const [pendingDeleteSource, setPendingDeleteSource] = useState(null)

  function handleDeleteSource(source) {
    setPendingDeleteSource(source)
  }

  async function confirmDeleteSource() {
    const source = pendingDeleteSource
    await deleteWatchSource(source.id)
    if (selSource === source.slug) setSelSource('')
    reloadSources()
    setPendingDeleteSource(null)
  }

  const totalPages = Math.ceil(data.total / perPage)

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
        title="Fuite de données" color={ACCENT}
        subtitle="Sources dédiées à l'identification de fuites de bases de données"
      >
        <div className="flex flex-col items-end gap-1">
          <button onClick={handleSync} disabled={syncing}
            className="px-3 py-2 text-xs font-medium rounded-lg transition-colors disabled:opacity-60"
            style={{ background: ACCENT, color: '#fff' }}
          >
            {syncing ? 'Sync…' : 'Synchroniser'}
          </button>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {lastSyncedAt
              ? `Dernière sync : ${new Date(lastSyncedAt).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`
              : 'Jamais synchronisé'}
          </span>
        </div>
      </PageHero>

      {msg && (
        <div className="text-sm px-4 py-3 rounded-xl" style={{ background: hexToRgba(ACCENT, 0.1), color: ACCENT, border: `1px solid ${hexToRgba(ACCENT, 0.2)}` }}>
          {msg}
        </div>
      )}

      <div className="stagger flex flex-nowrap gap-2 overflow-x-auto pb-1">
        <div className="flex-1 min-w-[140px]"><StatTile label="Fuites détectées" value={data.total} icon={ICON_PATHS.leak} accent={ACCENT} /></div>
        <div className="flex-1 min-w-[140px]"><StatTile label="Sources suivies" value={leakSources.length} sub={`dont ${customSources.length} personnalisée${customSources.length > 1 ? 's' : ''}`} icon={ICON_PATHS.sources} accent="#39c5cf" /></div>
        <div className="flex-1 min-w-[140px]"><StatTile label="Dernière synchronisation" value={lastSyncedAt ? new Date(lastSyncedAt).toLocaleDateString('fr-FR') : '—'}
          sub={lastSyncedAt ? new Date(lastSyncedAt).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : 'Jamais synchronisé'} icon={ICON_PATHS.clock} accent="#58a6ff" /></div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Chip label="Toutes sources" active={!selSource} color={ACCENT} onClick={() => { setSelSource(''); setPage(1) }} />
        {BUILTIN_LEAK_SOURCES.map(v => (
          <Chip key={v} label={SOURCE_LABELS[v] || v} active={selSource === v} color={SOURCE_COLORS[v] || ACCENT}
            onClick={() => { setSelSource(v); setPage(1) }} />
        ))}
        {customSources.map(s => (
          <span key={s.id} className="inline-flex items-center">
            <Chip label={s.name} active={selSource === s.slug} color={colorForSlug(s.slug)}
              onClick={() => { setSelSource(s.slug); setPage(1) }} />
            <button onClick={() => handleDeleteSource(s)} title="Retirer cette source"
              className="text-xs -ml-1.5 w-4 h-4 rounded-full flex items-center justify-center"
              style={{ color: 'var(--text-muted)' }}
            >×</button>
          </span>
        ))}
        <button onClick={() => setShowAddModal(true)}
          className="text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
          style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px dashed var(--border)' }}
        >+ Ajouter une source</button>
      </div>

      {showAddModal && (
        <AddSourceModal category="leak" accent={ACCENT} onConfirm={handleAddSource} onClose={() => setShowAddModal(false)} />
      )}

      {pendingDeleteSource && (
        <ConfirmModal
          title="Retirer cette source ?"
          message={<>Retirer la source « <strong>{pendingDeleteSource.name}</strong> » ? Les fuites déjà importées restent visibles.</>}
          confirmLabel="Retirer"
          busyLabel="Retrait…"
          onConfirm={confirmDeleteSource}
          onClose={() => setPendingDeleteSource(null)}
        />
      )}

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Pays :</span>
        <Chip
          label={<span className="inline-flex items-center gap-1.5"><FlagIcon code="FR" size={14} /> France</span>}
          active={selCountries.length === 1 && selCountries[0] === 'FR'} color={ACCENT}
          onClick={() => { setSelCountries(['FR']); setPage(1) }} />
        <Chip label="🌍 Monde entier" active={selCountries.length === 0} color={ACCENT}
          onClick={() => { setSelCountries([]); setPage(1) }} />
        <CountryDropdown selected={selCountries} onChange={v => { setSelCountries(v); setPage(1) }} />
      </div>

      <div className="stagger grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, min(380px, 1fr)))' }}>
        {loading && (
          <div style={CARD} className="col-span-full px-5 py-10 text-center">
            <PageLoader size="sm" />
          </div>
        )}
        {!loading && data.items.length === 0 && (
          <div style={CARD} className="col-span-full px-5 py-10 text-center text-sm">
            <span style={{ color: 'var(--text-muted)' }}>Aucune fuite recensée pour ce filtre</span>
          </div>
        )}
        {!loading && data.items.map(item => {
          const color = SOURCE_COLORS[item.source] || colorForSlug(item.source)
          const { company, context } = parseCompany(item)
          return (
            <a key={item.id} href={item.url || '#'} target="_blank" rel="noopener noreferrer"
              style={{ ...CARD, boxShadow: `inset 3px 0 0 0 ${hexToRgba(color, 0.55)}` }} className="lift-card flex flex-col px-4 py-4 transition-colors"
              onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-card)'}
            >
              <div className="flex items-start justify-between gap-2 mb-1">
                <div className="flex items-baseline gap-2 min-w-0">
                  <span className="text-xs px-2 py-0.5 rounded-md font-medium flex-shrink-0" style={{ background: hexToRgba(color, 0.1), color, border: `1px solid ${hexToRgba(color, 0.2)}` }}>
                    {item.source_label}
                  </span>
                  <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{company}</p>
                </div>
                <FlagIcon code={item.country} />
              </div>
              {context && (
                <p className="text-xs mb-1.5" style={{ color: 'var(--text-muted)' }}>{context}</p>
              )}
              {item.summary && (
                <p className="text-xs leading-relaxed mb-2" style={{ color: 'var(--text-muted)' }}>{truncate(item.summary)}</p>
              )}
              <span className="text-xs mt-auto pt-1" style={{ color: 'var(--text-muted)' }}>
                {item.received_at ? new Date(item.received_at).toLocaleDateString('fr-FR') : '—'}
              </span>
            </a>
          )
        })}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-2">
          <button onClick={() => setPage(p => p - 1)} disabled={page === 1}
            className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg disabled:opacity-40 transition-colors"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
          ><Icon d={ICON_PATHS.chevronLeft} className="w-3.5 h-3.5" /> Préc.</button>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Page {page} / {totalPages}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={page === totalPages}
            className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg disabled:opacity-40 transition-colors"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
          >Suiv. <Icon d={ICON_PATHS.chevronRight} className="w-3.5 h-3.5" /></button>
        </div>
      )}
    </div>
  )
}
