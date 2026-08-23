import { Fragment, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  assets as fetchAssets, runWebHardeningCheck, scanPolicies,
  agentSecurityEvents, ackAgentSecurityEvent, ackAllAgentSecurityEvents, listAgents,
} from '../api/client.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'
import { SYNTHETIC_ASSETS, anonymizeAsset, isSyntheticId } from '../utils/syntheticData.js'
import { assetCategory, categoryStyle } from '../utils/assetCategory.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import OsLogo from '../components/OsLogo.jsx'
import CategoryIcon from '../components/CategoryIcon.jsx'
import ComplianceChecklist, { complianceSummary } from '../components/ComplianceChecklist.jsx'
import DeclareIncidentButton from '../components/DeclareIncidentButton.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'
import { useHorizontalWheelScroll } from '../hooks/useHorizontalWheelScroll.js'

// Durcissement (12/08/2026, ex-section "Durcissement / conformité" de la modale de scan
// d'Assets.jsx, demande utilisateur — "sortir la modal pour en faire un module à part") : vue
// dédiée sur tout le parc, plus adaptée pour repérer les non-conformités que noyée dans une
// modale par-actif. Aucun nouvel endpoint : `GET /assets` porte déjà `last_scan_result` (serveurs/
// postes, compte de service ou agent) et `network_compliance` (équipements réseau Meraki/PRTG) en
// entier pour chaque actif — la page recalcule juste le résumé côté client.
//
// 13/08/2026 : la modale de détail (DetailModal) a été retirée — demande utilisateur, pas
// pratique pour lire une liste de checks (hauteur/largeur contraintes). Remplacée par un
// dépliage inline de la ligne, même esprit que les sections repliables de
// ComplianceChecklist.jsx — une seule ligne dépliée à la fois.
const MODULE_HOVER = `${MODULES.inventaire.color}0a`
const CARD = tintedCard(MODULES.inventaire.color)

// ─── Évènements détectés par les agents (19/08/2026, cf. docs/AGENT_DETECTION.md) ──────────
// Lecture des journaux d'audit natifs de l'OS + diff d'état entre deux check-ins — l'agent
// constate, il n'exécute et n'écrit jamais rien sur le poste (même principe de non-intervention
// que le reste d'Allsafe). Journal séparé du honeypot DB (jamais fusionnés, cf. doc § Modèle de
// données) : réservé admin comme AdministrationSecurity.jsx > onglet Base de données, même
// schéma d'acquittement (GET/POST /agents/security-events*).
const AGENT_EVENT_CATEGORY = {
  account_created:      { label: 'Compte créé',                color: '#d29922' },
  privilege_escalation: { label: 'Élévation de privilèges',    color: '#f85149' },
  account_reactivated:  { label: 'Compte réactivé',             color: '#d29922' },
  persistence:          { label: 'Nouvelle persistance',       color: '#fb8f44' },
  suspicious_process:   { label: 'Processus suspect',          color: '#f85149' },
  audit_tampering:      { label: "Altération de l'audit",      color: '#f85149' },
  buffer_overflow:      { label: 'Évènements perdus (buffer)', color: '#8b949e' },
}
const AGENT_EVENT_SEVERITY = {
  critical: { label: 'Critique',      color: '#f85149' },
  warning:  { label: 'Avertissement', color: '#d29922' },
  info:     { label: 'Info',          color: '#58a6ff' },
}
const AGENT_EVENT_SEVERITY_RANK = { critical: 0, warning: 1, info: 2 }

// Tri par criticité (19/08/2026, demande utilisateur) : le plus critique d'abord, quelle que
// soit la date. À l'intérieur d'une même sévérité, le plus récent d'abord.
function sortAgentEvents(events) {
  return [...events].sort((a, b) => {
    const rankDiff = (AGENT_EVENT_SEVERITY_RANK[a.severity] ?? 3) - (AGENT_EVENT_SEVERITY_RANK[b.severity] ?? 3)
    if (rankDiff !== 0) return rankDiff
    return new Date(b.reported_at) - new Date(a.reported_at)
  })
}

// Regroupement par catégorie (19/08/2026, retour utilisateur — "je ne peux pas traiter tous
// les évènements avec une centaine d'agents") : à cette échelle, une liste plate même triée par
// criticité reste trop longue à dépouiller évènement par évènement. Grouper par catégorie
// ramène ça à une poignée de lignes (~7 catégories max, cf. docs/AGENT_DETECTION.md) avec un
// acquittement en masse par groupe — le bon niveau pour du bruit homogène (ex. persistance
// détectée en rafale au 1er rollout d'un poste), sans perdre l'accès au détail individuel.
function groupAgentEventsByCategory(events) {
  const byCategory = new Map()
  for (const e of events) {
    if (!byCategory.has(e.category)) byCategory.set(e.category, [])
    byCategory.get(e.category).push(e)
  }
  return [...byCategory.entries()]
    .map(([category, evs]) => ({
      category,
      events: evs,
      // Noms d'actifs concernés (19/08/2026, demande utilisateur — "il faudrait le nom de
      // l'actif avant qu'on clique dessus") : affichés directement sur la ligne de groupe,
      // pas seulement après dépliage — dédoublonnés, un même poste peut porter plusieurs
      // évènements de la même catégorie.
      hostnames: [...new Set(evs.map(e => e.hostname))].sort((a, b) => a.localeCompare(b)),
      worstRank: Math.min(...evs.map(e => AGENT_EVENT_SEVERITY_RANK[e.severity] ?? 3)),
    }))
    .sort((a, b) => a.worstRank - b.worstRank || b.events.length - a.events.length)
}

// Aperçu tronqué d'une liste de noms d'actifs sur la ligne de groupe — la liste complète reste
// dans le `title` (survol) pour ne pas casser la mise en page à 100 agents.
function previewHostnames(hostnames, max = 4) {
  if (hostnames.length <= max) return hostnames.join(', ')
  return `${hostnames.slice(0, max).join(', ')} +${hostnames.length - max} autre${hostnames.length - max > 1 ? 's' : ''}`
}

function fmtAgentEventDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Table partagée par le panneau critique (haut de page) et le détail par actif (ci-dessous,
// pour tout le reste) — seule la mise en avant visuelle change (`muted`), même logique
// d'acquittement individuel.
//
// `assetByAgentId` (19/08/2026, demande utilisateur — "avec l'actif directement sur ça ligne") :
// `AgentSecurityEvent.hostname` n'est qu'un instantané du hostname déclaré par l'agent (souvent
// un nom court, ex. "armadasenonches"), pas forcément identique à `Asset.name`/`Asset.hostname`
// (FQDN "armadasenonches.aer.loc" observé en conditions réelles) — résoudre via `agent_id` →
// `GET /agents` (chargé une fois par Durcissement()) plutôt que de comparer des chaînes.
//
// `hideAssetColumn` (19/08/2026, demande utilisateur — "l'historique tu devrais le mettre avec
// l'actif directement") : quand la table est rendue DANS la ligne dépliée d'un actif, répéter
// son nom sur chaque évènement serait redondant — seul le panneau critique global (plusieurs
// actifs mélangés) a besoin de cette colonne.
function AgentEventsTable({ events, onAck, busy, muted, assetByAgentId, hideAssetColumn }) {
  const headers = hideAssetColumn
    ? ['Date', 'Catégorie', 'Sévérité', 'Résumé', 'Statut', '']
    : ['Date', 'Actif', 'Catégorie', 'Sévérité', 'Résumé', 'Statut', '']
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {headers.map(h => (
              <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map(e => {
            const cat = AGENT_EVENT_CATEGORY[e.category] || { label: e.category, color: 'var(--text-muted)' }
            const sev = AGENT_EVENT_SEVERITY[e.severity] || AGENT_EVENT_SEVERITY.info
            const asset = assetByAgentId?.[e.agent_id]
            return (
              <tr key={e.id} style={{
                borderBottom: '1px solid var(--border-subtle)',
                background: (!muted && !e.acknowledged) ? `${sev.color}0f` : 'transparent',
                boxShadow: (!muted && !e.acknowledged) ? `inset 3px 0 0 ${sev.color}` : 'none',
              }}>
                <td className="px-4 py-2.5 text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>{fmtAgentEventDate(e.reported_at)}</td>
                {!hideAssetColumn && (
                  <td className="px-4 py-2.5 text-xs font-medium whitespace-nowrap">
                    {asset?.id ? (
                      <Link to={`/durcissement?asset=${asset.id}`} className="hover:underline" style={{ color: 'var(--text-primary)' }} title="Voir le durcissement de cet actif">
                        {asset.name}
                      </Link>
                    ) : (
                      <span style={{ color: 'var(--text-primary)' }} title="Actif non résolu — agent supprimé ou jamais rattaché">{e.hostname}</span>
                    )}
                  </td>
                )}
                <td className="px-4 py-2.5 whitespace-nowrap">
                  <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${cat.color}1a`, color: cat.color, border: `1px solid ${cat.color}55` }}>{cat.label}</span>
                </td>
                <td className="px-4 py-2.5 whitespace-nowrap">
                  <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ background: `${sev.color}1a`, color: sev.color }}>{sev.label}</span>
                </td>
                <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{e.summary}</td>
                {/* `persistence` : pas de notion d'acquittement (19/08/2026, retour utilisateur
                    — sans liste de référence de ce qui est normal sur ce poste, il n'y a rien
                    à valider). Lecture seule, avec une porte de sortie manuelle vers Incidents
                    si une ligne précise paraît louche (cf. docs/AGENT_DETECTION.md § Pont vers
                    Incidents) — jamais de qualification automatique. */}
                {e.category === 'persistence' ? (
                  <>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-faint)' }}>—</td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <DeclareIncidentButton sourceType="agent_security_event" sourceId={e.id} />
                    </td>
                  </>
                ) : (
                  <>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {e.acknowledged
                        ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Acquitté{e.ack_by ? ` (${e.ack_by})` : ''}</span>
                        : <span className="text-xs font-semibold" style={{ color: muted ? 'var(--text-muted)' : sev.color }}>Non acquitté</span>}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {!e.acknowledged && (
                        <button onClick={() => onAck(e.id)} disabled={busy}
                          className="text-xs px-2.5 py-1 rounded-lg font-medium disabled:opacity-40"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                          Acquitter
                        </button>
                      )}
                    </td>
                  </>
                )}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// Panneau global — réservé aux évènements CRITICAL (19/08/2026, retour utilisateur : "ne garder
// que le critique dans l'évènement détectés par les agents"). Tout le reste (warning/info)
// vit désormais directement sur la ligne dépliée de l'actif concerné, cf. AssetAgentEvents
// ci-dessous — cohérent avec la règle déjà en place sur les vulnérabilités (CRITICAL = décision
// humaine centralisée, le reste s'annote au cas par cas là où il vit, CLAUDE.md §1). Devenu un
// composant contrôlé : `Durcissement()` charge une seule fois évènements + agents et distribue
// (ici le sous-ensemble critique, à chaque actif le sien) plutôt que de dupliquer le fetch.
function AgentEventsPanel({ isAdmin, events, assetByAgentId, onAck, onAckAll, onAckCategory, busy, error }) {
  // Repliée par défaut (19/08/2026, retour utilisateur — "la page devient très chargée") : le
  // badge nav Durcissement (Layout.jsx) et le bandeau Dashboard alertent déjà de l'existence
  // d'évènements non acquittés ; cette section n'a besoin de prendre de la place que quand on
  // vient volontairement la consulter, même logique de dépliage à la demande que les lignes
  // d'actifs plus bas sur cette page.
  const [open, setOpen] = useState(false)
  // Une seule catégorie dépliée à la fois (19/08/2026) — même convention que les lignes
  // d'actifs dépliables plus bas sur cette page.
  const [expandedCategory, setExpandedCategory] = useState(null)

  // Réservé admin (route serveur) et masqué s'il n'y a rien à voir — pas de carte vide
  // permanente pour une fonctionnalité qui ne concerne qu'une poignée de postes à la fois.
  if (!isAdmin || !events || events.length === 0) return null
  const unack = events.filter(e => !e.acknowledged)
  const sorted = sortAgentEvents(events)

  return (
    <div style={CARD} className="overflow-hidden">
      {/* `<div>` cliquable plutôt que `<button>` — le bouton « Acquitter tout » est imbriqué
          dedans, et un bouton dans un bouton est invalide en HTML (même raison que les lignes
          d'actifs dépliables plus bas sur cette page, `<tr onClick>` et non `<button>`). */}
      <div onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-2 px-4 py-3 text-left cursor-pointer"
        style={open ? { borderBottom: '1px solid var(--border)' } : {}}>
        <div className="flex items-center gap-2 min-w-0">
          <span className="flex-shrink-0 transition-transform" style={{ transform: open ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
          <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>Évènements critiques détectés par les agents</p>
          {unack.length > 0 && (
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full flex-shrink-0" style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149' }}>
              {unack.length} à traiter
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {!open && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{events.length} au total</span>}
          {unack.length > 0 && (
            <button onClick={onAckAll} disabled={busy}
              className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-40"
              style={{ background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' }}>
              {busy ? '…' : 'Acquitter tout'}
            </button>
          )}
        </div>
      </div>

      {open && (
      <>
      <p className="text-xs px-4 pt-3" style={{ color: 'var(--text-muted)' }}>
        Élévation de privilèges, altération d'audit… — sévérité la plus grave, décision toujours
        humaine (même règle que le CRITICAL des vulnérabilités). Le reste (comptes créés,
        processus suspects, persistance…) s'affiche directement dans le détail de chaque actif
        concerné, plus bas sur cette page.
      </p>

      {error && (
        <div className="text-sm px-4 py-3" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149' }}>{error}</div>
      )}

      {groupAgentEventsByCategory(sorted).map(g => {
        const cat = AGENT_EVENT_CATEGORY[g.category] || { label: g.category, color: 'var(--text-muted)' }
        const isOpen = expandedCategory === g.category
        return (
          <Fragment key={g.category}>
            <div onClick={() => setExpandedCategory(isOpen ? null : g.category)}
              className="flex items-center justify-between gap-2 px-4 py-2.5 cursor-pointer"
              style={{ borderBottom: '1px solid var(--border-subtle)', background: isOpen ? MODULE_HOVER : 'transparent' }}
              onMouseEnter={ev => { if (!isOpen) ev.currentTarget.style.background = MODULE_HOVER }}
              onMouseLeave={ev => { if (!isOpen) ev.currentTarget.style.background = 'transparent' }}>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="flex-shrink-0 transition-transform text-xs" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
                  <span className="text-xs font-medium px-2 py-0.5 rounded flex-shrink-0" style={{ background: `${cat.color}1a`, color: cat.color, border: `1px solid ${cat.color}55` }}>{cat.label}</span>
                  <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>{g.events.length} évènement{g.events.length > 1 ? 's' : ''}</span>
                </div>
                {/* Noms des actifs concernés, visibles avant même de déplier le groupe
                    (19/08/2026, demande utilisateur) — tronqués (title = liste complète). */}
                <p className="text-xs truncate mt-0.5 pl-5" style={{ color: 'var(--text-faint)' }} title={g.hostnames.join(', ')}>
                  {previewHostnames(g.hostnames)}
                </p>
              </div>
              <button onClick={e => onAckCategory(g.category, e)} disabled={busy}
                className="text-xs px-2.5 py-1 rounded-lg font-medium disabled:opacity-40 flex-shrink-0"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                Acquitter le groupe
              </button>
            </div>
            {isOpen && <AgentEventsTable events={g.events} onAck={onAck} busy={busy} muted={false} assetByAgentId={assetByAgentId} />}
          </Fragment>
        )
      })}
      </>
      )}
    </div>
  )
}

// Détail par actif (19/08/2026, retour utilisateur — "l'historique tu devrais le mettre avec
// l'actif directement") : tout ce qui n'est pas CRITICAL (warning/info, cf. AgentEventsPanel
// ci-dessus) s'affiche dans la ligne dépliée de l'actif concerné, juste au-dessus du détail de
// durcissement — le contexte "quel poste" est déjà celui qu'on regarde, pas besoin de répéter
// son nom sur chaque ligne (`hideAssetColumn`). Masqué s'il n'y a rien pour cet actif.
function AssetAgentEvents({ events, onAck, busy }) {
  if (!events || events.length === 0) return null
  return (
    <div className="mt-3 rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
      <p className="text-xs font-semibold uppercase tracking-wide px-4 py-2" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
        Évènements détectés par l'agent ({events.length})
      </p>
      <AgentEventsTable events={sortAgentEvents(events)} onAck={onAck} busy={busy} muted hideAssetColumn />
    </div>
  )
}

function checksFor(asset) {
  // web_compliance (17/08/2026, asset_type="website") : même principe que network_compliance
  // ci-dessous — ni OS ni scan SSH/WinRM, checks passifs propres (en-têtes HTTP, TLS).
  const base = asset.asset_type === 'network'
    ? asset.network_compliance?.checks || []
    : asset.asset_type === 'website'
    ? asset.web_compliance?.checks || []
    : asset.last_scan_result?.compliance?.checks || []
  // os_eol_check (17/08/2026) : calculé serveur-side à la volée (routers/assets.py::_asset_dict,
  // jamais stocké) depuis os/os_version déjà connus — préfixé plutôt qu'ajouté à la fin, c'est
  // le check le plus actionnable quand il est présent (warn = OS en fin de support).
  return asset.os_eol_check ? [asset.os_eol_check, ...base] : base
}

function SummaryBadges({ summary }) {
  if (summary.total === 0) {
    return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun check collecté</span>
  }
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {summary.ok > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(63,185,80,0.1)', color: '#3fb950' }}>
          ✓ {summary.ok}
        </span>
      )}
      {summary.warn > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(251,143,68,0.1)', color: '#fb8f44' }}>
          ⚠ {summary.warn}
        </span>
      )}
      {summary.unknown > 0 && (
        <span className="text-xs px-1.5 py-0.5 rounded font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
          — {summary.unknown}
        </span>
      )}
    </div>
  )
}

const filterSelectStyle = { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
const activeFilterStyle = { background: `${MODULES.inventaire.color}1f`, color: MODULES.inventaire.color, border: `1px solid ${MODULES.inventaire.color}59` }

// Tri des colonnes (13/08/2026, demande utilisateur) — même convention visuelle que
// Vulnerabilities.jsx (flèche ↑/↓ sur l'en-tête actif), en client-side ici (tout le parc est
// déjà chargé en une fois par cette page, contrairement à Vulnerabilities.jsx qui pagine
// côté serveur — pas besoin d'aller-retour réseau pour trier une liste déjà en mémoire).
function SortHeader({ label, col, sort, onSort }) {
  const active = sort.by === col
  const arrow = active ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''
  return (
    <th
      onClick={() => onSort(col)}
      className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
      style={{ color: active ? MODULES.inventaire.color : 'var(--text-muted)' }}
    >
      {label}{arrow}
    </th>
  )
}

// Valeur comparable par colonne triable — seulement "summary"/"last_scan" (13/08/2026, retour
// utilisateur : OS/Catégorie ont trop peu de valeurs distinctes pour qu'un tri croissant/
// décroissant serve à quelque chose, ce qu'il fallait là c'est choisir QUELLES valeurs afficher
// — remplacé par des menus déroulants, cf. osOptions/categoryOptions plus bas). "summary" trie
// par nombre d'avertissements d'abord (le signal le plus actionnable), puis indéterminés — pas
// par nombre total de checks, qui ne dit rien de l'état de conformité. "last_scan" : jamais
// scanné traité comme le plus ancien possible (0), reste groupé en premier en tri croissant et
// en dernier en tri décroissant.
function sortValue(col, asset, summary) {
  switch (col) {
    case 'summary': return summary.warn * 1000 + summary.unknown
    case 'last_scan': return asset.last_scan ? new Date(asset.last_scan).getTime() : 0
    default: return ''
  }
}

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond. Réponse BRUTE de fetchAssets()
// (avant tri/filtrage local), pas les listes déjà filtrées par l'utilisateur — cette page
// est celle qui porte le payload par actif le plus lourd de l'app (last_scan_result.compliance/
// network_compliance en entier), le cache stocke donc la réponse complète telle que reçue.
let durcissementPageCache = null

export default function Durcissement() {
  const { isAnonymous } = usePresentation()
  // POST /assets/web-hardening/run réservé admin (18/08/2026, cf. audit/AUDIT_SECURITE.md
  // #14) — même schéma que pages/Assets.jsx::isAdmin.
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  // Scroll horizontal à la molette (19/08/2026, retour utilisateur) — cf. useHorizontalWheelScroll.js.
  const tableScrollRef = useHorizontalWheelScroll()
  const [assetList, setAssetList] = useState(() => {
    if (durcissementPageCache == null) return []
    return isAnonymous ? [...durcissementPageCache.map(anonymizeAsset), ...SYNTHETIC_ASSETS] : durcissementPageCache
  })
  const [loading, setLoading] = useState(() => durcissementPageCache == null)
  const [search, setSearch] = useState('')
  const [warnOnly, setWarnOnly] = useState(false)
  // "Actifs configurés uniquement" (13/08/2026, demande utilisateur ; critère corrigé 17/08/2026)
  // : ne garde que les actifs avec un compte de service ou un agent — exclut les actifs réseau
  // importés (Meraki/PRTG), les sites web (checks passifs, aucun credential) et les hôtes ESXi
  // (`collection_method="vsphere_api"`, pas de durcissement dans cette passe, cf.
  // docs/ARCHITECTURE.md § Intégration vSphere). 1er jet (`checks.length === 0`, proxy indirect)
  // cassé par l'ajout d'`os_eol_check` (17/08/2026, calculé même sans scan réel dès qu'un OS est
  // déclaré) — remplacé par un critère direct sur `collection_method`, qui ne dépend d'aucun
  // autre check et ne se recassera pas si un nouveau check "toujours présent" est ajouté plus tard.
  const [configuredOnly, setConfiguredOnly] = useState(false)
  // Filtres OS/Catégorie (13/08/2026) : menus déroulants plutôt qu'un tri — peu de valeurs
  // distinctes possibles (poignée d'OS, poignée de catégories), choisir LAQUELLE afficher est
  // plus utile qu'un ordre croissant/décroissant dessus. '' = toutes.
  const [osFilter, setOsFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  // Tri par défaut sur "Résumé" décroissant (19/08/2026, retour utilisateur — "met en premier
  // les actifs configurés à regarder") : `sortValue('summary', ...)` classe par nombre
  // d'avertissements puis d'indéterminés (cf. plus bas) — un actif non configuré n'a aucun
  // check donc une valeur de 0, il retombe naturellement en fin de liste sans logique séparée.
  const [sort, setSort] = useState({ by: 'summary', dir: 'desc' })
  const [searchParams, setSearchParams] = useSearchParams()
  // Bouton "Lancer le scan web" (17/08/2026) — seul déclencheur de POST /assets/web-hardening/run
  // exposé côté UI (l'endpoint existait déjà sans bouton, comme network-protocol-check/
  // switch-hardening juste à côté dans routers/assets.py, mais un actif "Site web" nouvellement
  // créé n'a sinon aucun moyen de se faire scanner sans curl direct).
  const [scanningWeb, setScanningWeb] = useState(false)
  const [webScanMsg, setWebScanMsg] = useState('')
  // Signal de fraîcheur des actifs agent (17/08/2026) — un actif collecté par l'agent Rust
  // pousse ses données lui-même (checkin), Allsafe ne peut pas le forcer à se reconnecter sur
  // planning comme un actif service_account (cf. services/scan_policy.py). Seuil dérivé
  // directement de la fréquence de la politique de scan du même groupe de criticité : une seule
  // source de vérité pour "quelle fraîcheur est attendue", pas un réglage séparé à maintenir.
  const [policyFrequencyByCriticite, setPolicyFrequencyByCriticite] = useState({})

  useEffect(() => {
    scanPolicies().then(r => {
      const map = {}
      for (const p of r.data.items) map[p.criticite] = p.frequency
      setPolicyFrequencyByCriticite(map)
    }).catch(() => {})
  }, [])

  // Évènements détectés par les agents (19/08/2026, cf. docs/AGENT_DETECTION.md) — chargé une
  // seule fois ici plutôt que dans AgentEventsPanel : le sous-ensemble CRITICAL va au panneau
  // global, le reste (warning/info) va directement sur la ligne dépliée de l'actif concerné
  // (retour utilisateur — "l'historique tu devrais le mettre avec l'actif directement").
  const [agentEvents, setAgentEvents] = useState(null)
  const [assetByAgentId, setAssetByAgentId] = useState({})
  const [agentEventsBusy, setAgentEventsBusy] = useState(false)
  const [agentEventsError, setAgentEventsError] = useState('')

  function loadAgentEvents() {
    Promise.all([agentSecurityEvents({ limit: 200 }), listAgents()])
      .then(([evRes, agRes]) => {
        setAgentEvents(evRes.data.events || [])
        const map = {}
        for (const a of agRes.data.items || []) {
          if (a.asset_id) map[a.id] = { id: a.asset_id, name: a.asset_name || a.hostname }
        }
        setAssetByAgentId(map)
        setAgentEventsError('')
      })
      .catch(() => { setAgentEvents([]); setAgentEventsError("Impossible de charger les évènements agent — le serveur a peut-être renvoyé une erreur.") })
  }
  useEffect(() => { if (isAdmin) loadAgentEvents() }, [isAdmin])

  async function ackAgentEvent(id) {
    setAgentEventsBusy(true)
    try { await ackAgentSecurityEvent(id, user?.full_name || 'Administration'); loadAgentEvents() }
    finally { setAgentEventsBusy(false) }
  }

  async function ackAllAgentEvents(e) {
    e.stopPropagation()
    setAgentEventsBusy(true)
    try { await ackAllAgentSecurityEvents(user?.full_name || 'Administration'); loadAgentEvents() }
    finally { setAgentEventsBusy(false) }
  }

  // Acquittement de masse scopé à une catégorie (routers/agents.py::ack_all_security_events,
  // filtre `category` ajouté le 19/08/2026) — une seule requête, pas une boucle d'appels
  // individuels : à l'échelle d'une centaine d'agents, un groupe peut porter des dizaines
  // d'évènements homogènes.
  async function ackAgentEventCategory(category, e) {
    e.stopPropagation()
    setAgentEventsBusy(true)
    try { await ackAllAgentSecurityEvents(user?.full_name || 'Administration', category); loadAgentEvents() }
    finally { setAgentEventsBusy(false) }
  }

  // CRITICAL au panneau global (décision humaine centralisée, cf. AgentEventsPanel) ; le reste
  // réparti par actif (`agent_id` → `Asset.id` via assetByAgentId) pour vivre sur sa ligne.
  const criticalAgentEvents = useMemo(
    () => (agentEvents || []).filter(e => e.severity === 'critical'),
    [agentEvents],
  )
  // Inclut aussi le CRITICAL (19/08/2026, retour utilisateur — le lien Dashboard "doit amener à
  // l'actif concerné", pas juste à la page) : le panneau global reste le point de triage
  // fleet-wide, mais atterrir sur la ligne d'un actif via ce lien doit y montrer l'évènement qui
  // a déclenché le bandeau, pas une ligne vide.
  const agentEventsByAssetId = useMemo(() => {
    const map = {}
    for (const e of agentEvents || []) {
      const assetId = assetByAgentId[e.agent_id]?.id
      if (!assetId) continue
      if (!map[assetId]) map[assetId] = []
      map[assetId].push(e)
    }
    return map
  }, [agentEvents, assetByAgentId])

  function agentStaleness(asset) {
    if (asset.collection_method !== 'agent' || !asset.last_scan) return null
    const criticite = asset.tags?.criticite || 'moyenne'
    const frequency = policyFrequencyByCriticite[criticite]
    if (!frequency) return null
    const maxAgeDays = frequency === 'daily' ? 1 : 7
    const ageDays = (Date.now() - new Date(asset.last_scan).getTime()) / 86400000
    if (ageDays <= maxAgeDays) return null
    return `Dernier checkin il y a ${Math.floor(ageDays)} jour(s) — attendu : ${frequency === 'daily' ? 'quotidien' : 'hebdomadaire'}`
  }

  function reload() {
    return fetchAssets()
      .then(r => {
        const raw = r.data || []
        durcissementPageCache = raw   // alimente le cache module pour le prochain remontage
        let list = raw
        if (isAnonymous) list = [...list.map(anonymizeAsset), ...SYNTHETIC_ASSETS]
        setAssetList(list)
      })
  }

  useEffect(() => { reload().finally(() => setLoading(false)) }, [isAnonymous])

  async function handleWebScan() {
    setScanningWeb(true)
    setWebScanMsg('')
    try {
      const { data } = await runWebHardeningCheck()
      await reload()
      setWebScanMsg(data.checked > 0
        ? `${data.checked} site(s) vérifié(s), ${data.warnings} avec avertissement(s)`
        : "Aucun actif \"Site web\" à vérifier")
    } catch {
      setWebScanMsg('Erreur lors du scan web')
    } finally {
      setScanningWeb(false)
      setTimeout(() => setWebScanMsg(''), 6000)
    }
  }

  // Deep-link depuis Assets.jsx ("Voir le durcissement/conformité de cet actif →",
  // ?asset=<id>) — même esprit que le bandeau de rattrapage CVE du Dashboard. Déplie la ligne
  // visée au lieu d'ouvrir une modale (13/08/2026).
  useEffect(() => {
    const assetId = searchParams.get('asset')
    if (!assetId || assetList.length === 0) return
    const target = assetList.find(a => a.id === assetId)
    if (target) {
      setExpandedId(target.id)
      searchParams.delete('asset')
      setSearchParams(searchParams, { replace: true })
      // Sans ça, la ligne se dépliait bien mais restait hors écran dans un tableau non paginé
      // (potentiellement des dizaines d'actifs) — perçu à tort comme "revenu sur la page de
      // base sans rien garder de sélectionné" (18/08/2026, retour utilisateur). Un frame
      // d'attente : la ligne doit être montée avant de pouvoir la cibler par id.
      requestAnimationFrame(() => {
        document.getElementById(`durcissement-row-${target.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      })
    }
  }, [assetList, searchParams, setSearchParams])

  const rows = useMemo(() => {
    return assetList.map(a => ({ asset: a, checks: checksFor(a), summary: complianceSummary(checksFor(a)) }))
  }, [assetList])

  // Options des menus déroulants OS/Catégorie — dérivées des actifs réellement présents plutôt
  // qu'une liste codée en dur (cf. principe "penser scalable", CLAUDE.md) : s'adapte
  // automatiquement à ce que le parc contient vraiment.
  const osOptions = useMemo(
    () => [...new Set(rows.map(r => r.asset.os).filter(Boolean))].sort((a, b) => a.localeCompare(b)),
    [rows],
  )
  const categoryOptions = useMemo(
    () => [...new Set(rows.map(r => assetCategory(r.asset)))].sort((a, b) => a.localeCompare(b)),
    [rows],
  )

  const sorted = useMemo(() => {
    if (!sort.by) return rows
    const dir = sort.dir === 'desc' ? -1 : 1
    return [...rows].sort((a, b) => {
      const va = sortValue(sort.by, a.asset, a.summary)
      const vb = sortValue(sort.by, b.asset, b.summary)
      if (va < vb) return -1 * dir
      if (va > vb) return 1 * dir
      return 0
    })
  }, [rows, sort])

  const filtered = sorted.filter(({ asset, summary }) => {
    if (search.trim() && !asset.name.toLowerCase().includes(search.trim().toLowerCase())) return false
    if (warnOnly && summary.warn === 0) return false
    if (configuredOnly) {
      if (asset.asset_type === 'network' || asset.asset_type === 'website') return false
      if (asset.collection_method !== 'service_account' && asset.collection_method !== 'agent') return false
    }
    if (osFilter && asset.os !== osFilter) return false
    if (categoryFilter && assetCategory(asset) !== categoryFilter) return false
    return true
  })

  function handleSort(col) {
    setSort(s => s.by === col ? { by: col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : { by: col, dir: 'desc' })
  }

  if (loading) return <PageLoader />

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M6 13.5V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m12-12V3.75m0 9.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 3.75V16.5m-6-9V3.75m0 3.75a1.5 1.5 0 010 3m0-3a1.5 1.5 0 000 3m0 9.75V10.5"
        title="Durcissement"
        color={MODULES.inventaire.color}
        subtitle="Conformité CIS-like du parc — compte de service ou agent, lecture seule."
      />

      <AgentEventsPanel
        isAdmin={isAdmin}
        events={criticalAgentEvents}
        assetByAgentId={assetByAgentId}
        onAck={ackAgentEvent}
        onAckAll={ackAllAgentEvents}
        onAckCategory={ackAgentEventCategory}
        busy={agentEventsBusy}
        error={agentEventsError}
      />

      <div className="flex flex-wrap items-center gap-2">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher un actif…"
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={filterSelectStyle} />
        <select value={osFilter} onChange={e => setOsFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={osFilter ? activeFilterStyle : filterSelectStyle}>
          <option value="">Tous les OS</option>
          {osOptions.map(os => <option key={os} value={os}>{os}</option>)}
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
          className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={categoryFilter ? activeFilterStyle : filterSelectStyle}>
          <option value="">Toutes les catégories</option>
          {categoryOptions.map(cat => <option key={cat} value={cat}>{cat}</option>)}
        </select>
        <button onClick={() => setWarnOnly(w => !w)}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={warnOnly
            ? { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.35)' }
            : filterSelectStyle}>
          ⚠ Avec avertissements uniquement
        </button>
        <button onClick={() => setConfiguredOnly(c => !c)}
          className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
          style={configuredOnly ? activeFilterStyle : filterSelectStyle}>
          Actifs configurés uniquement
        </button>
        {isAdmin && (
          <button onClick={handleWebScan} disabled={scanningWeb}
            title="Checks passifs (en-têtes HTTP, protocole TLS) sur tous les actifs Site web"
            className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-60"
            style={filterSelectStyle}>
            {scanningWeb ? 'Scan en cours…' : 'Lancer le scan web'}
          </button>
        )}
        {webScanMsg && <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{webScanMsg}</span>}
      </div>

      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto" ref={tableScrollRef}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Nom</th>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>OS</th>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Catégorie</th>
                <SortHeader label="Résumé" col="summary" sort={sort} onSort={handleSort} />
                <SortHeader label="Dernier scan" col="last_scan" sort={sort} onSort={handleSort} />
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif ne correspond à ces filtres</td></tr>
              )}
              {filtered.map(({ asset, checks, summary }) => {
                const isOpen = expandedId === asset.id
                return (
                  <Fragment key={asset.id}>
                    <tr
                      id={`durcissement-row-${asset.id}`}
                      onClick={() => setExpandedId(isOpen ? null : asset.id)}
                      className="cursor-pointer"
                      style={{ borderBottom: isOpen ? 'none' : '1px solid var(--border-subtle)', background: isOpen ? MODULE_HOVER : 'transparent' }}
                      onMouseEnter={e => { if (!isOpen) e.currentTarget.style.background = MODULE_HOVER }}
                      onMouseLeave={e => { if (!isOpen) e.currentTarget.style.background = 'transparent' }}
                    >
                      <td className="px-4 py-3 font-semibold" style={{ color: 'var(--text-primary)' }}>
                        <span className="inline-block mr-1.5 transition-transform" style={{ transform: isOpen ? 'rotate(90deg)' : 'none', color: 'var(--text-muted)' }}>›</span>
                        {asset.name}
                      </td>
                      <td className="px-4 py-3">
                        <OsLogo os={asset.os} size={18} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-center" title={assetCategory(asset)}>
                          <CategoryIcon category={assetCategory(asset)} style={{ color: categoryStyle(assetCategory(asset)).color }} />
                        </div>
                      </td>
                      <td className="px-4 py-3"><SummaryBadges summary={summary} /></td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <div className="flex items-center gap-1.5">
                          <span>{asset.last_scan ? new Date(asset.last_scan).toLocaleDateString('fr-FR') : '—'}</span>
                          {agentStaleness(asset) && (
                            <span title={agentStaleness(asset)} style={{ color: '#d29922' }}>
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                              </svg>
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td colSpan={5} className="px-4 pb-4 pt-1" style={{ background: 'var(--bg-secondary)' }}>
                          <ComplianceChecklist checks={checks} os={asset.os} assetType={asset.asset_type} maxHeight="420px" />
                          {isAdmin && (
                            <AssetAgentEvents events={agentEventsByAssetId[asset.id]} onAck={ackAgentEvent} busy={agentEventsBusy} />
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
