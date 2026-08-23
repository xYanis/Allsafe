import { useEffect, useState, useCallback, useRef } from 'react'
import {
  Tooltip, ResponsiveContainer, BarChart, Bar, AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import {
  watchItems, syncWatch, watchSyncStatus, watchLeakSources, watchSources,
  createWatchSource, deleteWatchSource, watchLeakDashboard,
} from '../api/client.js'
import { BUILTIN_LEAK_SOURCES } from './Watch.jsx'
import FlagIcon from '../components/FlagIcon.jsx'
import AddSourceModal from '../components/AddSourceModal.jsx'
import { COUNTRIES, COUNTRY_LABELS } from '../utils/countries.js'
import { hexToRgba } from '../utils/color.js'
import PageLoader from '../components/PageLoader.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import PageHero from '../components/PageHero.jsx'
import { tintedCard } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { SYNTHETIC_LEAK_ITEMS } from '../utils/syntheticData.js'
import { SOURCE_COLORS, colorForSlug } from '../utils/watchVisuals.js'
import WatchThumbnail from '../components/WatchThumbnail.jsx'
import ViewToggle from '../components/ViewToggle.jsx'
import { MODULES } from '../constants/modules.js'
import SevBadge from '../components/SevBadge.jsx'

// Onglet 100% informatif — aucun rapport avec le registre auditable NIS 2 de
// Veille technologique (pas de statut/analyste/décision/SLA). Restreint aux
// sources dédiées à l'identification de fuites de bases de données (ZATAZ,
// fuitesinfos.fr, Ransomware.live, DataBreaches.net, Have I Been Pwned, +
// sources personnalisées ajoutées ici même) — les autres sources (CERT-FR,
// éditeurs sécu...) ne remontent jamais ici, même si un de leurs articles
// mentionne occasionnellement une fuite de données.
// Bleu CyberVeille (23/08/2026, retour utilisateur — "pourquoi la page fuite de données est
// en violet") : #a371f7 était la couleur Rapports, sans rapport avec ce module — Fuite de
// données appartient à CyberVeille (Watch.jsx/SurveillanceIdentites.jsx, même bleu), incohérence
// jamais documentée comme un choix délibéré (contrairement à l'orange d'Administration).
// Résolu par thème (23/08/2026, suite du même retour — "le fond bleu" restait fixe sur
// Neutre/Cyberpunk) : `MODULES.cyberveille.color`, pas un hex à nouveau codé en dur ici —
// même erreur que celle qu'on vient de corriger, à un cran d'abstraction près.
const ACCENT = MODULES.cyberveille.color
const CARD = tintedCard(ACCENT)
// Même objet que Dashboard.jsx::TOOLTIP_STYLE (seul autre consommateur de recharts dans l'app)
// — pas d'extraction partagée pour une seule constante, cf. commentaire StatTile plus bas.
const TOOLTIP_STYLE = { backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }

// Complète les périodes sans aucune fuite (absentes de la réponse API, qui ne renvoie que des
// GROUP BY non vides) avec un compte à 0 — sans ça, un graphique de tendance saute d'une
// semaine à l'autre de façon trompeuse dès qu'une période est restée calme.
function fillPeriods(rows, count, unit) {
  const byKey = new Map((rows || []).map(r => [r.period.slice(0, 10), r.count]))
  const now = new Date()
  const out = []
  for (let i = count - 1; i >= 0; i--) {
    const d = new Date(now)
    if (unit === 'week') {
      // Lundi de la semaine i périodes en arrière (date_trunc('week', ...) est aussi ISO,
      // lundi premier jour) — getDay() dimanche=0, donc l'offset se calcule en mod 7.
      const day = (d.getDay() + 6) % 7
      d.setDate(d.getDate() - day - i * 7)
    } else {
      d.setMonth(d.getMonth() - i, 1)
    }
    const key = d.toISOString().slice(0, 10)
    out.push({
      period: key,
      count: byKey.get(key) || 0,
      label: unit === 'week'
        ? d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' })
        : d.toLocaleDateString('fr-FR', { month: 'short', year: '2-digit' }),
    })
  }
  return out
}

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
  // `height: 100%` (23/08/2026, retour utilisateur — même bug que KpiCard/Dashboard.jsx) :
  // le conteneur flex parent (`flex flex-nowrap`, cf. usage plus bas) étire déjà chaque
  // wrapper `.flex-1` à la hauteur de la ligne (`align-items: stretch`, défaut flexbox) —
  // sans ce `height: 100%`, cette carte ne prenait que la hauteur de SON PROPRE contenu, donc
  // "Fuites détectées" (2 lignes, pas de `sub`) restait plus courte que ses deux voisines (3
  // lignes, avec `sub`).
  return (
    <div style={{ ...CARD, boxShadow: `inset 3px 0 0 0 color-mix(in srgb, ${accent} 50%, transparent)`, height: '100%' }} className="lift-card group px-3 py-2 min-w-0">
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

// SOURCE_COLORS/colorForSlug déplacés dans utils/watchVisuals.js (23/08/2026, partagés
// avec Watch.jsx pour les vignettes WatchThumbnail).

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

// Confirmé/revendiqué (23/08/2026, demande explicite) — `null`/`undefined` = notion non
// applicable à cette source (seul HIBP peuple `is_verified`, cf. models.py::WatchItem), pas
// affiché du tout plutôt qu'un badge "non concerné" qui alourdirait toutes les autres cartes.
function VerifiedBadge({ value }) {
  if (value === null || value === undefined) return null
  const s = value
    ? { background: 'rgba(63,185,80,0.12)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' }
    : { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' }
  return (
    <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {value ? 'Confirmé' : 'Non vérifié'}
    </span>
  )
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
  // Bascule Tableau/Cartes (23/08/2026, demande explicite — "la même bascule que sur veille
  // technologique") — la page reste en cartes par défaut (comportement d'origine), tableau en
  // option pour un survol plus dense. Persisté séparément de Watch.jsx (clé distincte) : rien
  // n'impose aux deux pages de partager la même préférence d'affichage.
  const [viewMode, setViewMode] = useState(() => localStorage.getItem('leak-view-mode') || 'cards')
  useEffect(() => { localStorage.setItem('leak-view-mode', viewMode) }, [viewMode])
  const perPage = 30
  const { isAnonymous } = usePresentation()

  // Dashboard mondial (23/08/2026, demande explicite) — dépend de `selSource`/`leakSources`
  // (même périmètre de sources que la liste ci-dessous) mais PAS de `selCountries` : le
  // classement par pays doit rester une vue d'ensemble, pas se réduire au(x) pays déjà
  // sélectionné(s) dans le filtre de la liste (sinon "classement des pays" filtré sur la
  // France elle-même n'aurait plus de sens).
  const [dashboard, setDashboard] = useState(null)
  const [trendUnit, setTrendUnit] = useState('week') // 'week' | 'month'
  // Plage du classement pays (23/08/2026, demande explicite) — seul ce bloc-là prend une
  // fenêtre de temps, cf. docstring backend watch_dashboard : total/tendance/source restent
  // sur tout l'historique, non demandé pour eux.
  const [countryRange, setCountryRange] = useState('all') // 'day'|'week'|'month'|'year'|'all'

  useEffect(() => {
    watchLeakDashboard(selSource || leakSources.join(','), countryRange).then(r => setDashboard(r.data)).catch(() => {})
  }, [selSource, leakSources, countryRange])

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
  // Synthetic data ajoutée seulement en page 1 sans filtre de source — filtrée par pays côté
  // client (mêmes critères que le paramètre serveur) pour rester cohérente avec les chips.
  const syntheticMatches = !selSource && (selCountries.length === 0 || selCountries.includes('FR'))
  const displayItems = isAnonymous && syntheticMatches && page === 1 ? [...data.items, ...SYNTHETIC_LEAK_ITEMS] : data.items

  // Dashboard : périodes complétées à 0 (cf. fillPeriods plus haut), top 8 pays (au-delà,
  // la barre la plus courte devient illisible dans la hauteur disponible — le reste, moins
  // touché, n'a pas besoin d'être lu au pixel près sur cette vue d'ensemble).
  const trendData = dashboard ? fillPeriods(dashboard[trendUnit === 'week' ? 'trend_weekly' : 'trend_monthly'], 12, trendUnit) : []
  const topCountries = dashboard ? dashboard.by_country.slice(0, 8).map(c => ({ ...c, name: c.country })) : []
  const bySourceCount = Object.fromEntries((dashboard?.by_source || []).map(s => [s.source, s.count]))

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
        <div className="flex-1 min-w-[140px]"><StatTile label="Fuites détectées" value={data.total + (isAnonymous && syntheticMatches && page === 1 ? SYNTHETIC_LEAK_ITEMS.length : 0)} icon={ICON_PATHS.leak} accent={ACCENT} /></div>
        <div className="flex-1 min-w-[140px]"><StatTile label="Sources suivies" value={leakSources.length} sub={`dont ${customSources.length} personnalisée${customSources.length > 1 ? 's' : ''}`} icon={ICON_PATHS.sources} accent="#39c5cf" /></div>
        <div className="flex-1 min-w-[140px]"><StatTile label="Dernière synchronisation" value={lastSyncedAt ? new Date(lastSyncedAt).toLocaleDateString('fr-FR') : '—'}
          sub={lastSyncedAt ? new Date(lastSyncedAt).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : 'Jamais synchronisé'} icon={ICON_PATHS.clock} accent="#58a6ff" /></div>
      </div>

      {/* Dashboard mondial (23/08/2026, demande explicite) — tendance + classement des pays.
          `selCountries` volontairement absent des dépendances (cf. commentaire sur `dashboard`
          plus haut) : cette vue reste une vue d'ensemble, jamais réduite au filtre pays actif
          de la liste en dessous. */}
      {dashboard && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <div style={CARD} className="lg:col-span-2 p-4">
            <div className="flex items-start justify-between gap-3 mb-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Tendance mondiale</p>
                <p className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{dashboard.total.toLocaleString('fr-FR')} fuites au total</p>
              </div>
              <div className="inline-flex rounded-lg overflow-hidden flex-shrink-0" style={{ border: '1px solid var(--border)' }}>
                {[['week', 'Semaine'], ['month', 'Mois']].map(([u, label]) => (
                  <button key={u} onClick={() => setTrendUnit(u)}
                    className="text-xs px-2.5 py-1.5 font-medium transition-colors"
                    style={{ background: trendUnit === u ? ACCENT : 'var(--bg-secondary)', color: trendUnit === u ? '#fff' : 'var(--text-muted)' }}
                  >{label}</button>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={trendData} margin={{ left: -20, right: 8, top: 8, bottom: 0 }}>
                <defs>
                  <linearGradient id="leakTrendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
                    <stop offset="100%" stopColor={ACCENT} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} width={28} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: 'var(--text-primary)' }} formatter={v => [v, 'Fuites']} />
                <Area type="monotone" dataKey="count" stroke={ACCENT} strokeWidth={2} fill="url(#leakTrendFill)" dot={false} activeDot={{ r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div style={CARD} className="p-4">
            <div className="flex items-center justify-between gap-2 mb-3">
              <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Pays les plus touchés</p>
              <select value={countryRange} onChange={e => setCountryRange(e.target.value)}
                className="text-[11px] px-1.5 py-1 rounded-md outline-none flex-shrink-0"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              >
                <option value="day">Jour</option>
                <option value="week">Semaine</option>
                <option value="month">Mois</option>
                <option value="year">Année</option>
                <option value="all">Tout</option>
              </select>
            </div>
            {topCountries.length === 0 ? (
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucune donnée de pays.</p>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={topCountries} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                  <XAxis type="number" hide allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={36} tick={{ fontSize: 11, fill: 'var(--text-secondary)' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: hexToRgba(ACCENT, 0.06) }}
                    labelFormatter={code => COUNTRY_LABELS[code] || code} formatter={v => [v, 'Fuites']} />
                  <Bar dataKey="count" fill={ACCENT} radius={[0, 4, 4, 0]} barSize={10} label={{ position: 'right', fontSize: 10, fill: 'var(--text-muted)' }} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Chip label="Toutes sources" active={!selSource} color={ACCENT} onClick={() => { setSelSource(''); setPage(1) }} />
        {/* Compte par source (23/08/2026, demande explicite — "répartition par source") en
            plus du filtre déjà existant : pas de graphique dédié pour ça, juste le nombre
            entre parenthèses sur un contrôle qui existait déjà — la répartition se lit d'un
            coup d'œil sans occuper une carte de plus. */}
        {BUILTIN_LEAK_SOURCES.map(v => (
          <Chip key={v} label={`${SOURCE_LABELS[v] || v}${bySourceCount[v] ? ` (${bySourceCount[v]})` : ''}`} active={selSource === v} color={SOURCE_COLORS[v] || ACCENT}
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
        <div className="ml-auto"><ViewToggle mode={viewMode} onChange={setViewMode} /></div>
      </div>

      {viewMode === 'table' ? (
        <div style={CARD} className="overflow-hidden">
          <div className="overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Reçu le', 'Source', 'Pays', 'Entreprise', 'Sévérité', 'Contexte'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="stagger-rows">
                {loading && (
                  <tr><td colSpan={6} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
                )}
                {!loading && displayItems.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-16 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucune fuite recensée pour ce filtre</td></tr>
                )}
                {!loading && displayItems.map(item => {
                  const color = SOURCE_COLORS[item.source] || colorForSlug(item.source)
                  const { company, context } = parseCompany(item)
                  return (
                    <tr key={item.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td className="px-4 py-2.5 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {item.received_at ? new Date(item.received_at).toLocaleDateString('fr-FR') : '—'}
                      </td>
                      <td className="px-4 py-2.5">
                        <a href={item.url || '#'} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 hover:underline">
                          <WatchThumbnail item={item} size={24} rounded={6} />
                          <span className="text-xs font-medium px-2 py-0.5 rounded-md whitespace-nowrap" style={{ background: hexToRgba(color, 0.1), color, border: `1px solid ${hexToRgba(color, 0.2)}` }}>
                            {item.source_label}
                          </span>
                        </a>
                      </td>
                      <td className="px-4 py-2.5"><FlagIcon code={item.country} /></td>
                      <td className="px-4 py-2.5">
                        <a href={item.url || '#'} target="_blank" rel="noopener noreferrer" className="text-sm font-semibold hover:underline" style={{ color: 'var(--text-primary)' }}>{company}</a>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <SevBadge value={item.severity} />
                          <VerifiedBadge value={item.is_verified} />
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-muted)', maxWidth: 340 }}>
                        {context || (item.summary ? truncate(item.summary) : '—')}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
      <div className="stagger grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, min(380px, 1fr)))' }}>
        {loading && (
          <div style={CARD} className="col-span-full px-5 py-10 text-center">
            <PageLoader size="sm" />
          </div>
        )}
        {!loading && displayItems.length === 0 && (
          <div style={CARD} className="col-span-full px-5 py-10 text-center text-sm">
            <span style={{ color: 'var(--text-muted)' }}>Aucune fuite recensée pour ce filtre</span>
          </div>
        )}
        {!loading && displayItems.map(item => {
          const color = SOURCE_COLORS[item.source] || colorForSlug(item.source)
          const { company, context } = parseCompany(item)
          return (
            <a key={item.id} href={item.url || '#'} target="_blank" rel="noopener noreferrer"
              style={{ ...CARD, boxShadow: `inset 3px 0 0 0 ${hexToRgba(color, 0.55)}` }} className="lift-card flex flex-col px-4 py-4 transition-colors"
              onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-card)'}
            >
              <div className="flex items-start gap-3">
                <WatchThumbnail item={item} size={40} />
                <div className="min-w-0 flex-1 flex flex-col">
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
                  <div className="flex items-center justify-between gap-2 mt-auto pt-1">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                      {item.received_at ? new Date(item.received_at).toLocaleDateString('fr-FR') : '—'}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <VerifiedBadge value={item.is_verified} />
                      <SevBadge value={item.severity} />
                    </div>
                  </div>
                </div>
              </div>
            </a>
          )
        })}
      </div>
      )}

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
