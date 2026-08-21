import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getAgent, agentCheckins, getAsset } from '../api/client.js'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import { StatusBadge, VersionBadge, DistroBadge, formatDateTime, contactFreshness, FRESHNESS_COLOR, FRESHNESS_LABEL } from '../components/AgentBadges.jsx'
import { MODULES } from '../constants/modules.js'
import { formatDisks } from '../utils/hardware.js'
import CriticiteBadge from '../components/CriticiteBadge.jsx'
import PendingUpdatesBadge from '../components/PendingUpdatesBadge.jsx'
import { complianceSummary } from '../components/ComplianceChecklist.jsx'
import { TYPE_LABELS } from '../utils/assetCategory.js'
import { tintedCard } from '../utils/cardStyle.js'

const MODULE_COLOR = MODULES.inventaire.color
const CARD = tintedCard(MODULE_COLOR)

// Nombre de check-ins chargés en une fois (18/08/2026) — pas de pagination pour ce premier
// jet : à ~24 check-ins/jour/agent (rythme horaire), 500 couvre déjà ~3 semaines d'historique,
// largement suffisant tant que le module Agents lui-même n'a que quelques jours d'existence
// réelle. `total` (distinct de la longueur de la liste) permet d'afficher "tronqué" sans
// se tromper si ça devient un jour nécessaire d'ajouter une vraie pagination.
const CHECKIN_LOAD_LIMIT = 500

// Même cadence que agent/src/daemon.rs::CHECKIN_INTERVAL (18/08/2026, retour utilisateur —
// "voir le cycle des scans") : un check-in = un scan complet côté agent (collect::collect()
// envoie hardware/paquets/compliance à chaque fois, pas de heartbeat allégé séparé) — donc
// l'historique des check-ins EST l'historique des scans, pas juste un journal de présence.
// Dupliqué ici plutôt qu'exposé par l'API : valeur figée côté agent, jamais configurable
// par actif ni lue depuis la base, une constante suffit.
const CHECKIN_INTERVAL_MS = 3600_000

function formatDuration(ms) {
  if (ms == null || ms < 0) return '—'
  const minutes = Math.round(ms / 60000)
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  const rem = minutes % 60
  if (hours < 24) return rem > 0 ? `${hours} h ${rem} min` : `${hours} h`
  const days = Math.floor(hours / 24)
  const remHours = hours % 24
  return remHours > 0 ? `${days} j ${remHours} h` : `${days} j`
}

// Actifs déjà en base avant l'ajout de la colonne `created_at` : rétrodatés à
// 2020-01-01T00:00:00Z par la migration (backfill, cf. schema_patches.sql) — cette date
// ne veut alors rien dire. On affiche "Avant le suivi" plutôt que ce faux horodatage.
// Même sentinelle que le badge "Nouveau" d'Assets.jsx traite implicitement (isNewAsset :
// une date 2020 n'est jamais "récente"), pas encore assez répandue pour un util partagé.
const CREATED_AT_SENTINEL_MS = Date.parse('2020-01-01T00:00:00Z')
function formatKnownSince(iso) {
  if (!iso) return '—'
  if (new Date(iso).getTime() === CREATED_AT_SENTINEL_MS) return 'Avant le suivi'
  return formatDateTime(iso)
}

function StatTile({ label, children }) {
  return (
    <div className="rounded-xl p-3" style={tintedCard(MODULE_COLOR)}>
      <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</p>
      <div className="text-sm mt-1" style={{ color: 'var(--text-primary)' }}>{children}</div>
    </div>
  )
}

// Résumé de durcissement (checks CIS-like de last_scan_result.compliance) — réutilise
// complianceSummary (ComplianceChecklist.jsx), mêmes icônes/couleurs que la page Durcissement.
// Remplace l'ancienne tuile "État réseau" (Meraki/PRTG), sans objet pour un poste suivi par
// agent : jamais rapproché d'une sonde réseau (network_status toujours None), alors que le
// durcissement EST le cœur de métier de l'agent. Cliquable vers le détail par actif.
function ComplianceTileValue({ asset }) {
  const s = complianceSummary(asset.last_scan_result?.compliance?.checks)
  if (s.total === 0) return <span style={{ color: 'var(--text-muted)' }}>Non évalué</span>
  return (
    <Link to={`/durcissement?asset=${asset.id}`} className="inline-flex items-center gap-2 hover:underline"
      title="Voir le détail du durcissement">
      <span style={{ color: '#3fb950' }}>✓ {s.ok}</span>
      <span style={{ color: '#fb8f44' }}>⚠ {s.warn}</span>
      {s.unknown > 0 && <span style={{ color: 'var(--text-muted)' }}>— {s.unknown}</span>}
    </Link>
  )
}

// Fiabilité de la dernière collecte (agent → apply_scan_result) — remplace l'ancienne tuile
// "Mises à jour disponibles", structurellement à 0 sur Windows (available_version jamais posé,
// impasse assumée côté agent, cf. routers/assets.py::_asset_dict). Surface plutôt si la collecte
// a abouti proprement : orthogonal au "Dernier contact" (fraîcheur) juste au-dessus.
function ScanReliabilityValue({ result }) {
  if (!result) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  if (result.reachable === false) return <span style={{ color: '#f85149' }}>Injoignable</span>
  if (result.error) return <span style={{ color: '#fb8f44' }} title={result.error}>Partielle</span>
  return <span style={{ color: '#3fb950' }}>Complète</span>
}

// Une entrée de la chronologie — un check-in normal, ou une coupure détectée par ce
// check-in (mêmes données, `gap_started_at` présent seulement dans ce second cas). Style
// calqué sur IncidentTimeline.jsx (carte à bordure gauche) pour rester cohérent avec le
// reste de l'app, sans réutiliser le composant lui-même : vocabulaire d'évènement différent
// (pas de event_type/author/notes ici, juste un check-in daté avec des métriques).
function CheckinEntry({ item }) {
  const hasGap = Boolean(item.gap_started_at)
  return (
    <div className="pl-3" style={{ borderLeft: `2px solid ${hasGap ? '#d29922' : item.on_demand ? '#58a6ff' : 'var(--border)'}` }}>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium flex items-center gap-1.5" style={{ color: 'var(--text-primary)' }}>
          {hasGap ? 'Coupure détectée, reconnecté' : 'Check-in'}
          {item.on_demand && (
            <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(88,166,255,0.12)', color: '#58a6ff' }}>
              à la demande
            </span>
          )}
        </p>
        <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{formatDateTime(item.checked_in_at)}</span>
      </div>
      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
        {item.package_count != null && <>{item.package_count} paquet{item.package_count > 1 ? 's' : ''} déclaré{item.package_count > 1 ? 's' : ''}</>}
        {item.agent_version && <>{item.package_count != null ? ' — ' : ''}version {item.agent_version}</>}
      </p>
      {hasGap && (
        <p className="text-xs mt-1 rounded-lg px-2.5 py-1.5 inline-block" style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922' }}>
          Hors ligne depuis le {formatDateTime(item.gap_started_at)} ({item.gap_failed_attempts ?? '?'} tentative{item.gap_failed_attempts > 1 ? 's' : ''} échouée{item.gap_failed_attempts > 1 ? 's' : ''}) —
          reconnecté après {formatDuration(new Date(item.checked_in_at) - new Date(item.gap_started_at))}
        </p>
      )}
    </div>
  )
}

// Évènement fondateur de la frise (génération du jeton, enrôlement) — même carte à bordure
// gauche que CheckinEntry, mais un jalon unique daté sans métriques. Toujours les plus anciens,
// donc affichés tout en bas (la liste va du plus récent au plus ancien).
function FoundingEntry({ title, subtitle, date, color }) {
  return (
    <div className="pl-3" style={{ borderLeft: `2px solid ${color}` }}>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{title}</p>
        <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{date ? formatDateTime(date) : '—'}</span>
      </div>
      {subtitle && <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{subtitle}</p>}
    </div>
  )
}

export default function AgentHistory() {
  const { id } = useParams()
  const [agent, setAgent] = useState(null)
  const [checkins, setCheckins] = useState(null)
  const [asset, setAsset] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setAgent(null); setCheckins(null); setAsset(null); setError('')
    Promise.all([getAgent(id), agentCheckins(id, CHECKIN_LOAD_LIMIT)])
      .then(([agentRes, checkinsRes]) => {
        if (cancelled) return
        setAgent(agentRes.data)
        setCheckins(checkinsRes.data)
        // Détails matériel/réseau/patrimoine (18/08/2026, retour utilisateur — "Dernier
        // contact" restait trop pauvre) : vient de l'actif rattaché, pas de l'agent
        // lui-même (le check-in alimente l'actif via apply_scan_result, cf. CLAUDE.md).
        // Best-effort — un agent orphelin (asset_id absent) ou une erreur ponctuelle ne
        // doit pas empêcher d'afficher le reste de la page.
        if (agentRes.data.asset_id) {
          getAsset(agentRes.data.asset_id).then(r => { if (!cancelled) setAsset(r.data) }).catch(() => {})
        }
      })
      .catch(e => { if (!cancelled) setError(e?.response?.data?.detail || 'Agent introuvable.') })
    return () => { cancelled = true }
  }, [id])

  if (error) {
    return (
      <div className="p-6 space-y-3">
        <Link to="/agents" className="text-xs inline-block" style={{ color: MODULE_COLOR }}>← Retour aux agents</Link>
        <p className="text-sm" style={{ color: '#f85149' }}>{error}</p>
      </div>
    )
  }
  if (!agent || !checkins) return <PageLoader />

  const items = checkins.items
  const gaps = items.filter(i => i.gap_started_at)
  const longestGapMs = gaps.length
    ? Math.max(...gaps.map(g => new Date(g.checked_in_at) - new Date(g.gap_started_at)))
    : null
  const onDemandCount = items.filter(i => i.on_demand).length
  const freshness = contactFreshness(agent.last_seen_at)
  // Le cycle horaire ne repart qu'à partir du DERNIER check-in réussi (cf. daemon.rs) — une
  // coupure en cours (agent hors ligne) rend cette estimation caduque, mieux vaut ne rien
  // afficher qu'une heure qui ne viendra pas plutôt que d'induire en erreur.
  const nextExpected = agent.status === 'enrolled' && agent.last_seen_at && freshness !== 'red'
    ? new Date(agent.last_seen_at).getTime() + CHECKIN_INTERVAL_MS
    : null

  return (
    <div className="p-6 space-y-5">
      <Link to="/agents" className="text-xs inline-block" style={{ color: MODULE_COLOR }}>← Retour aux agents</Link>

      <PageHero
        icon="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25"
        title={agent.hostname}
        color={MODULE_COLOR}
        subtitle={agent.asset_name ? `Actif lié : ${agent.asset_name}` : 'Aucun actif lié'}
      >
        <StatusBadge value={agent.status} />
      </PageHero>

      <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
        <StatTile label="Dernier contact">
          <span className="inline-flex items-center gap-1.5" style={{ color: FRESHNESS_COLOR[freshness] }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: 'currentColor' }} />
            {formatDateTime(agent.last_seen_at)}
          </span>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{FRESHNESS_LABEL[freshness]}</p>
        </StatTile>
        <StatTile label="Distribution"><DistroBadge os={agent.asset_os} version={agent.asset_os_version} /></StatTile>
        <StatTile label="Version agent"><VersionBadge version={agent.agent_version} outdated={agent.outdated} /></StatTile>
        <StatTile label="Enrôlé depuis">{formatDateTime(agent.enrolled_at)}</StatTile>
        <StatTile label="Cycle de scan">
          Toutes les heures
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>+ sondage 60s pour un scan à la demande</p>
        </StatTile>
        <StatTile label="Prochain scan attendu">
          {nextExpected != null ? formatDateTime(new Date(nextExpected).toISOString()) : '—'}
        </StatTile>
        <StatTile label="Check-ins enregistrés">
          {checkins.total}{checkins.total > items.length && <span className="text-xs ml-1" style={{ color: 'var(--text-muted)' }}>({items.length} affichés)</span>}
        </StatTile>
        <StatTile label="Dont à la demande">{onDemandCount}</StatTile>
        <StatTile label="Coupures détectées">{gaps.length}</StatTile>
        <StatTile label="Coupure la plus longue">{longestGapMs != null ? formatDuration(longestGapMs) : '—'}</StatTile>
        {asset && (
          <>
            <StatTile label="Adresse IP">
              <span className="font-mono">{asset.hardware?.ip || asset.ip_address || '—'}</span>
            </StatTile>
            <StatTile label="Paquets installés">{asset.package_count}</StatTile>
            <StatTile label="Vulnérabilités ouvertes">
              {asset.open_vuln_count > 0 ? (
                <Link to={`/vulnerabilities?asset_id=${asset.id}`} className="hover:underline" style={{ color: '#f85149' }}>
                  {asset.open_vuln_count}
                </Link>
              ) : '0'}
            </StatTile>
            <StatTile label="Criticité"><CriticiteBadge value={asset.tags?.criticite} /></StatTile>
            <StatTile label="Type d'actif">{TYPE_LABELS[asset.asset_type] || asset.asset_type || '—'}</StatTile>
            <StatTile label="Fin de support OS">
              {asset.os_eol_check ? (
                <>
                  <span style={{ color: asset.os_eol_check.status === 'warn' ? '#f85149' : '#3fb950' }}>
                    {asset.os_eol_check.status === 'warn' ? 'Dépassée' : 'À jour'}
                  </span>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{asset.os_eol_check.detail}</p>
                </>
              ) : '—'}
            </StatTile>
            <StatTile label="Durcissement"><ComplianceTileValue asset={asset} /></StatTile>
            <StatTile label="Mises à jour en attente"><PendingUpdatesBadge pendingUpdates={asset.pending_updates} /></StatTile>
            <StatTile label="Fiabilité du dernier scan"><ScanReliabilityValue result={asset.last_scan_result} /></StatTile>
            <StatTile label="Connu depuis">{formatKnownSince(asset.created_at)}</StatTile>
          </>
        )}
      </div>

      {/* Patrimoine matériel (18/08/2026, retour utilisateur — "Dernier contact" restait trop
          pauvre) : vient de l'actif rattaché (alimenté par le check-in agent via
          apply_scan_result), même contenu/mise en forme que la modale de scan d'Assets.jsx —
          pas dupliqué en composant partagé pour un seul autre usage, cf. principe scalable
          CLAUDE.md (extraction dès une DEUXIÈME réutilisation non triviale, pas préventive). */}
      {asset?.hardware && Object.keys(asset.hardware).length > 0 && (
        <div style={CARD} className="p-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Patrimoine matériel</h2>
            <Link to={`/durcissement?asset=${asset.id}`} className="text-xs hover:underline" style={{ color: MODULE_COLOR }}>
              Voir le durcissement/conformité →
            </Link>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>CPU : </span>
              <span style={{ color: 'var(--text-secondary)' }}>{asset.hardware.cpu || '—'}{asset.hardware.cores ? ` (${asset.hardware.cores} cœurs)` : ''}</span>
            </div>
            <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>RAM : </span>
              <span style={{ color: 'var(--text-secondary)' }}>{asset.hardware.ram_gb ? `${asset.hardware.ram_gb} Go` : '—'}</span>
            </div>
            <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Architecture : </span>
              <span style={{ color: 'var(--text-secondary)' }}>{asset.hardware.arch || '—'}</span>
            </div>
            <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Disques : </span>
              <span style={{ color: 'var(--text-secondary)' }}>{formatDisks(asset.hardware.disks)}</span>
            </div>
            <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Adresse MAC : </span>
              <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{asset.hardware.mac || '—'}</span>
            </div>
            <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Ports ouverts : </span>
              <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                {asset.hardware.open_ports?.length > 0 ? asset.hardware.open_ports.join(', ') : '—'}
              </span>
            </div>
          </div>
        </div>
      )}

      <div style={CARD} className="p-6">
        <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Historique des contacts</h2>
        <div className="space-y-3">
          {items.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun check-in enregistré pour cet agent.</p>
          ) : (
            <>
              {items.map(item => <CheckinEntry key={item.id} item={item} />)}
              {checkins.total > items.length && (
                <p className="text-xs pl-3" style={{ color: 'var(--text-muted)' }}>
                  … et {checkins.total - items.length} de plus (non chargés)
                </p>
              )}
            </>
          )}
          {/* Évènements fondateurs — toujours les plus anciens, donc en bas (frise du plus récent
              au plus ancien). Donnent l'historique "depuis le début" : enrôlement (validation par
              le poste), puis génération du jeton (par qui/quand) tout en bas. Affichés même sans
              aucun check-in (agent juste enrôlé). */}
          <FoundingEntry
            title="Poste enrôlé"
            subtitle="Jeton validé par le poste, identité de l'agent créée"
            date={agent.enrolled_at}
            color="#3fb950"
          />
          <FoundingEntry
            title="Jeton d'enrôlement généré"
            subtitle={agent.enrollment_token_created_at
              ? `par ${agent.enrollment_token_created_by || '—'}`
              : 'Détails indisponibles (jeton révoqué ou supprimé)'}
            date={agent.enrollment_token_created_at}
            color={MODULE_COLOR}
          />
        </div>
      </div>
    </div>
  )
}
