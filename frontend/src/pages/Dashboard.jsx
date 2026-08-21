import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import { stats as fetchStats, vulns as fetchVulns, assets as fetchAssets, updateVuln, analyzeIA, patchCheck, patchCheckStatus, patchCheckRun, syncMatch, syncMatchStatus, bulkPatch, falsePositiveCandidates, bulkFalsePositive, autoBasculeSummary, newVulnsSinceCount, assetsLifecycleSince, securityEventsCount, incidentsPendingCount, assetCompletionSummary, openUnretestedFindingsCount, getVulnOtherInstances, prtgSslCertificates, agentSecurityEventsCount } from '../api/client.js'
import { useAuth } from '../contexts/AuthContext.jsx'
import PageHero from '../components/PageHero.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ExploitBadge from '../components/ExploitBadge.jsx'
import CriticiteBadge from '../components/CriticiteBadge.jsx'
import ConnectivityDot from '../components/ConnectivityDot.jsx'
import { CRITICITE_LABELS } from '../constants/criticite.js'
import AnalysisModal from '../components/AnalysisModal.jsx'
import AnnotationModal from '../components/AnnotationModal.jsx'
import AnnotationDetailModal from '../components/AnnotationDetailModal.jsx'
import OtherInstancesModal from '../components/OtherInstancesModal.jsx'
import MarkdownNote from '../components/MarkdownNote.jsx'
import ToastStack from '../components/Toast.jsx'
import PageLoader from '../components/PageLoader.jsx'
import AssetDropdown from '../components/AssetDropdown.jsx'
import BulkQualifyModal from '../components/BulkQualifyModal.jsx'
import { cvssColor, epssColor } from '../utils/scoreColors.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import {
  FAKE_ASSETS, FAKE_VULNERABILITIES, anonymizeAsset, anonymizeVuln, isFakeId,
  computeDashboardStats, fakePatchCheckResult, fakeAnalysis,
} from '../utils/fakeData.js'
import { MODULES } from '../constants/modules.js'
import { tintedCard, CYBERVULN_CARD_TINT } from '../utils/cardStyle.js'
import { useTiltEnabled, tiltMouseMove, tiltMouseEnter, tiltMouseLeave } from '../utils/tilt3d.js'
import { useDashboardLayout } from '../contexts/DashboardLayoutContext.jsx'
import { WIDGET_LABELS, SIZE_SPAN, SIZE_LABELS, LOCKED_WIDGETS } from '../constants/dashboardLayout.js'

const CARD = tintedCard(CYBERVULN_CARD_TINT)
// Style "filtre actif" (17/08/2026) — même formule que CVEs.jsx/Vulnerabilities.jsx, couleur du
// module de cette page (CyberVuln).
const ACTIVE_SELECT_STYLE = { background: `${MODULES.cybervuln.color}1f`, color: MODULES.cybervuln.color, border: `1px solid ${MODULES.cybervuln.color}59`, outline: 'none', cursor: 'pointer' }
const SEV_COLORS = { CRITICAL: '#f85149', HIGH: '#fb8f44', 'MEDIUM+LOW': '#58a6ff' }
// Couleur par sévérité pour le filtre multi-sélection.
const SEV_CHIP = { CRITICAL: '#f85149', HIGH: '#fb8f44', MEDIUM: '#d29922', LOW: '#58a6ff' }

// Menu déroulant de sévérités (multi-sélection). Vide = toutes affichées.
function SeverityDropdown({ selected, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    function h(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const toggle = (s) => onChange(selected.includes(s) ? selected.filter(x => x !== s) : [...selected, s])
  const active = selected.length > 0
  const label = selected.length === 0 ? 'Toutes sévérités' : selected.length === 1 ? selected[0] : `${selected.length} sévérités`
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 text-xs px-2.5 py-1.5 rounded-lg"
        style={{
          background: active ? 'rgba(88,166,255,0.1)' : 'var(--bg-secondary)',
          color: active ? '#58a6ff' : 'var(--text-secondary)',
          border: `1px solid ${active ? 'rgba(88,166,255,0.3)' : 'var(--border)'}`,
        }}>
        {label}
        <svg className="w-3 h-3 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={open ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7'} />
        </svg>
      </button>
      {open && (
        <div className="absolute z-50 mt-1 rounded-xl py-1"
          style={{ top: '100%', left: 0, minWidth: 175, background: 'var(--bg-card)', border: '1px solid var(--border)', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}>
          {SEVS.map(s => (
            <label key={s} className="flex items-center gap-2.5 px-3 py-1.5 cursor-pointer text-sm"
              style={{ color: 'var(--text-secondary)' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,0.06)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <input type="checkbox" checked={selected.includes(s)} onChange={() => toggle(s)} className="w-3.5 h-3.5 accent-blue-500" />
              <span style={{ color: SEV_CHIP[s], fontWeight: 600 }}>{s}</span>
            </label>
          ))}
          {active && (
            <div className="px-3 pt-1.5 mt-1" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={() => onChange([])} className="text-xs" style={{ color: 'var(--text-muted)' }}>Tout décocher</button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Retravaillé le 14/08/2026 (retour utilisateur — "c'est très long", sans aucun signe
// que ça avance) : POST /api/sync/match ne bloque plus la requête jusqu'à la fin du
// calcul (jusqu'à 13,4M itérations, cf. services/cpe_matcher.py) — il se contente de
// lancer le run en fond et retourne aussitôt. Le pourcentage vient du polling de
// GET /api/sync/match-status, même patron que le bandeau "Analyse en cours" du patch
// check plus bas. `wasRunningRef` détecte la transition running→terminé pour afficher
// les toasts une seule fois (`last_result`, plus renvoyé directement par POST /match).
function MatchingCveButton({ onDone, onToast }) {
  const [status, setStatus] = useState('idle') // idle | running | done | error
  const [lastSyncedAt, setLastSyncedAt] = useState(null)
  const [progress, setProgress] = useState(null) // { checked, total } | null
  const pollRef = useRef(null)
  const wasRunningRef = useRef(false)

  const checkStatus = useCallback(() => {
    return syncMatchStatus().then(r => {
      const d = r.data
      setLastSyncedAt(d.last_synced_at)
      if (d.running) {
        wasRunningRef.current = true
        setStatus('running')
        setProgress(d.progress?.total ? d.progress : null)
        if (!pollRef.current) pollRef.current = setInterval(checkStatus, 1500)
        return
      }
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
      setProgress(null)
      // Ce poll voit `running: false` alors que le précédent le voyait `true` — le run
      // vient tout juste de se terminer pendant cette page, c'est le moment d'afficher
      // le résultat. Un simple montage de page sur un matching déjà inactif ne déclenche
      // jamais ces toasts (wasRunningRef reste à false).
      if (wasRunningRef.current) {
        wasRunningRef.current = false
        setStatus('done')
        const byAsset = d.last_result?.created_by_asset || []
        if (byAsset.length === 0) {
          onToast?.('Matching CVE terminé — aucune nouvelle CVE.', 'info')
        } else {
          for (const a of byAsset) {
            onToast?.(`${a.name || a.hostname} — ${a.count} nouvelle${a.count !== 1 ? 's' : ''} CVE`, 'success')
          }
        }
        onDone()
        setTimeout(() => setStatus('idle'), 5000)
      }
    }).catch(() => {})
  }, [onDone, onToast])

  useEffect(() => {
    checkStatus() // détecte aussi un run déjà en cours au montage (démarré par un autre onglet, ou au boot du backend)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function run() {
    try {
      const r = await syncMatch()
      if (r.data.status === 'already_running') onToast?.('Un matching est déjà en cours.', 'info')
      checkStatus()
    } catch {
      setStatus('error')
      setTimeout(() => setStatus('idle'), 5000)
    }
  }

  const pct = progress?.total ? Math.min(100, Math.round((progress.checked / progress.total) * 100)) : null

  const styles = {
    idle:    { background: 'rgba(251,143,68,0.1)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.25)' },
    running: { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' },
    done:    { background: 'rgba(63,185,80,0.1)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' },
    error:   { background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' },
  }
  const labels = {
    idle: 'Matching CVE',
    running: pct != null ? `En cours… ${pct}%` : 'En cours…',
    done: 'Terminé ✓', error: 'Erreur ✕',
  }

  return (
    <div className="flex flex-col items-end gap-1 flex-shrink-0">
      <button onClick={run} disabled={status === 'running'}
        className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-colors flex-shrink-0 disabled:opacity-60"
        style={styles[status]}
      >
        {status === 'running' ? (
          <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
        {labels[status]}
      </button>
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {lastSyncedAt
          ? `Dernière sync : ${new Date(lastSyncedAt).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`
          : 'Jamais synchronisé'}
      </span>
    </div>
  )
}

// `selectedAssetIds` (04/08/2026) : reflète le filtre d'actifs du Dashboard —
// un "Patch check global" lancé avec un filtre actif ne recontrôle plus tout
// le parc, seulement les actifs sélectionnés (demande explicite de
// l'utilisateur, jusque-là le bouton ignorait totalement ce filtre).
function PatchCheckRunButton({ selectedAssetIds = [], onToast }) {
  const [status, setStatus] = useState('idle')
  // Confirmation obligatoire avant la réévaluation forcée : contrairement au
  // check standard (qui ne touche que ce qui n'a jamais/plus été vérifié), elle
  // rejoue le contrôle sur tout le parc ouvert (ou la sélection) et peut basculer
  // un gros volume de vulns en `patched` d'un coup (non-CRITICAL). Un clic isolé
  // ne suffit pas.
  const [confirmForce, setConfirmForce] = useState(false)
  const scoped = selectedAssetIds.length > 0

  async function run(force = false) {
    setStatus('loading')
    setConfirmForce(false)
    try {
      const { data } = await patchCheckRun(force, selectedAssetIds)
      if (data.status === 'already_running') {
        // Retour mort côté backend depuis le 07/08/2026 (garde retirée, cf.
        // routers/patch_check.py) — gardé pour ne rien casser si elle revient,
        // mais ce cas n'arrive plus en pratique.
        setStatus('running')
        onToast?.('Un cycle est déjà en cours — la demande sera prise en compte à la fin de la passe actuelle.', 'violet')
      } else {
        setStatus('done')
        // `pending_count` (10/08/2026, demande explicite) : distingue "lancé, ça
        // tourne" de "rien à faire, déjà à jour" — calculé côté backend sur le
        // périmètre réel de CE cycle, pas déduit de GET /status (pas scopé pareil).
        if (data.pending_count === 0) {
          onToast?.('Patch check : déjà à jour, rien à vérifier.', 'success')
        } else {
          const n = data.pending_count
          onToast?.(`Patch check lancé — ${n} vulnérabilité${n !== 1 ? 's' : ''} à vérifier.`, 'info')
        }
      }
    } catch {
      setStatus('error')
      onToast?.('Échec du lancement du patch check.', 'error')
    }
    setTimeout(() => setStatus('idle'), 5000)
  }

  const styles = {
    idle:    { background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.25)' },
    loading: { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' },
    running: { background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.25)' },
    done:    { background: 'rgba(63,185,80,0.1)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' },
    error:   { background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' },
  }
  const labels = {
    idle: scoped ? `Patch check (${selectedAssetIds.length} actif${selectedAssetIds.length !== 1 ? 's' : ''})` : 'Patch check global',
    loading: 'Lancement…', running: 'Déjà en cours',
    done: 'Lancé ✓', error: 'Erreur ✕',
  }

  return (
    <>
      <div className="flex items-stretch flex-shrink-0">
        <button onClick={() => run(false)} disabled={status === 'loading'}
          title={scoped
            ? `Relance le contrôle patch (rattrapage + check des vulns jamais vérifiées) sur les ${selectedAssetIds.length} actif(s) du filtre, pas tout le parc`
            : "Relance le même contrôle patch (rattrapage + check des vulns jamais vérifiées) que celui exécuté automatiquement au démarrage"}
          className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-l-lg transition-colors disabled:opacity-60"
          style={styles[status]}
        >
          {status === 'loading' ? (
            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
          ) : (
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )}
          {labels[status]}
        </button>
        <button onClick={() => setConfirmForce(true)} disabled={status === 'loading'}
          title={scoped
            ? `Forcer une réévaluation complète — rejoue le contrôle sur les vulnérabilités ouvertes des ${selectedAssetIds.length} actif(s) du filtre, y compris celles vérifiées il y a moins de 24h`
            : "Forcer une réévaluation complète — rejoue le contrôle sur toutes les vulnérabilités ouvertes, y compris celles vérifiées il y a moins de 24h"}
          className="px-2 py-2 text-xs rounded-r-lg transition-colors disabled:opacity-60 active:scale-[0.97]"
          style={{ ...styles[status], borderLeft: '1px solid rgba(163,113,247,0.35)' }}
        >
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {confirmForce && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop"
          onClick={() => setConfirmForce(false)}>
          <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
            onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="font-semibold" style={{ color: '#a371f7' }}>Forcer une réévaluation complète</h2>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {scoped
                  ? `Contrôle read-only relancé sur les vulnérabilités ouvertes des ${selectedAssetIds.length} actif(s) du filtre`
                  : 'Contrôle read-only relancé sur toutes les vulnérabilités ouvertes'}
              </p>
            </div>
            <div className="p-6 space-y-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
              <p>
                Le contrôle standard ignore ce qui a été vérifié il y a moins de 24h. Cette option lève
                ce garde-fou : à utiliser après l'amélioration d'un signal de détection, sinon le stock
                déjà contrôlé garde un résultat calculé par l'ancienne logique.
              </p>
              <ul className="space-y-1.5 pl-4 list-disc" style={{ color: 'var(--text-muted)' }}>
                <li>Les vulns <strong>HIGH / MEDIUM / LOW</strong> dont le correctif est prouvé basculent
                    automatiquement en « corrigé » — potentiellement en grand nombre.</li>
                <li>Les <strong>CRITICAL</strong> ne basculent jamais seules : elles restent en attente de
                    votre validation.</li>
                <li>Aucune écriture sur les serveurs, aucun statut ni validateur existant modifié.
                    Chaque ligne reste réouvrable.</li>
                <li>Comptez ~15 à 30 min ; suivez l'avancement dans le bandeau « Analyse en cours ».</li>
              </ul>
            </div>
            <div className="px-6 py-4 flex items-center justify-end gap-2" style={{ borderTop: '1px solid var(--border)' }}>
              <button onClick={() => setConfirmForce(false)}
                className="text-xs px-3 py-2 rounded-lg active:scale-[0.97]"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              >Annuler</button>
              <button onClick={() => run(true)}
                className="text-xs px-3 py-2 rounded-lg font-medium active:scale-[0.97]"
                style={{ background: 'rgba(163,113,247,0.15)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.35)' }}
              >Lancer la réévaluation</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

// "il y a 3 min" / "il y a 2h" / "hier" / "12/07" — même esprit que les dates
// relatives déjà affichées ailleurs (colonnes "Clôturé le"), mais avec une
// granularité fine : un historique de notifications perd son sens si tout
// affiche la même date du jour.
function relativeTime(iso) {
  const diffMs = Date.now() - new Date(iso).getTime()
  const min = Math.floor(diffMs / 60000)
  if (min < 1) return "à l'instant"
  if (min < 60) return `il y a ${min} min`
  const h = Math.floor(min / 60)
  if (h < 24) return `il y a ${h}h`
  const j = Math.floor(h / 24)
  if (j === 1) return 'hier'
  if (j < 7) return `il y a ${j}j`
  return new Date(iso).toLocaleDateString('fr-FR')
}

// Espace disque restant par actif, affiché sur les cartes de la barre "Analyse en
// cours" (cf. plus bas) — plusieurs disques joints par virgule, comme
// Inventaire.jsx::formatDisks, mais l'espace libre plutôt que la taille totale
// (c'est le chiffre qui importe pour repérer un actif proche de la saturation).
function formatFreeSpace(hardware) {
  const disks = hardware?.disks
  if (!disks || disks.length === 0) return null
  return disks.map(d => `${d.name} ${d.free_gb ?? '?'}/${d.total_gb ?? '?'} Go libres`).join(', ')
}

// Estimation grossière (pas une garantie — un actif injoignable ralentit tout le
// lot) affichée sur la barre "Analyse en cours" du dashboard, cf. plus bas.
function formatEta(seconds) {
  if (seconds < 60) return 'moins d\'1 min'
  const min = Math.round(seconds / 60)
  if (min < 60) return `~${min} min`
  const h = Math.floor(min / 60)
  const m = min % 60
  return `~${h} h${m > 0 ? ` ${m}` : ''}`
}

// Charge la vuln d'une CVE de bascule (recherche serveur, donc trouvable même
// hors des listes plafonnées du Dashboard) et prépare les props du justificatif
// de clôture. Partagé par la cloche de notifications et le bandeau de rattrapage.
async function openCveJustification(it, setDetailModal, flash) {
  try {
    const r = await fetchVulns({ search: it.cve_id, per_page: 50 })
    const items = r.data.items || []
    const v = items.find(x => x.cve?.cve_id === it.cve_id && x.asset?.name === it.asset_name)
      || items.find(x => x.cve?.cve_id === it.cve_id) || items[0]
    if (!v) { flash?.(`${it.cve_id} introuvable`); return }
    const isFP = v.status === 'false_positive'
    const blocks = []
    if (v.notes) blocks.push({ heading: `Annotation de l'analyste${v.validated_by ? ` (${v.validated_by})` : ''}`, body: v.notes, markdown: true })
    if (v.patch_check_details) blocks.push({ heading: 'Résultat du contrôle technique', body: v.patch_check_details, markdown: false })
    setDetailModal({
      vuln: v,
      label: isFP ? 'Faux positif' : 'Correctif détecté',
      color: isFP ? '#a371f7' : '#3fb950',
      date: v.false_positive_at || v.patched_at,
      blocks,
      title: 'Justificatif de clôture',
      emptyText: 'Aucun justificatif enregistré pour cette clôture.',
    })
  } catch { flash?.(`Erreur lors du chargement de ${it.cve_id}`) }
}

function NotificationHistory() {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState(null)
  const [detailModal, setDetailModal] = useState(null)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  // Deux sources fusionnées (11/08/2026, demande explicite) — mêmes toasts que celui
  // qui vient de disparaître, quel que soit le déclencheur (bascule de CVE ou fin de
  // passe sur un actif). Chaque endpoint reste séparé côté backend (cf.
  // routers/patch_check.py::asset_completion_summary), fusionnés seulement ici pour
  // l'affichage — triés par date, plafonnés à 30 lignes après fusion.
  function toggle() {
    const next = !open
    setOpen(next)
    if (next) {
      setLoading(true)
      const since = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()
      Promise.all([
        autoBasculeSummary(since, 30).then(r => r.data).catch(() => ({ total: 0, items: [] })),
        assetCompletionSummary(since, 30).then(r => r.data).catch(() => ({ total: 0, items: [] })),
      ]).then(([cve, assets]) => {
        const merged = [
          ...cve.items.map(it => ({ ...it, kind: 'cve' })),
          ...assets.items.map(it => ({ ...it, kind: 'asset' })),
        ].sort((a, b) => new Date(b.at) - new Date(a.at))
        setData({ items: merged.slice(0, 30), total: cve.total + assets.total })
      }).catch(() => setData(null)).finally(() => setLoading(false))
    }
  }

  return (
    <>
    <div ref={ref} className="relative flex-shrink-0">
      <button onClick={toggle}
        title="Historique des notifications (7 derniers jours)"
        className="p-2 rounded-lg transition-colors"
        style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 rounded-xl overflow-hidden z-50"
          style={{ width: 340, maxHeight: 420, background: 'var(--bg-card)', border: '1px solid var(--border)', boxShadow: '0 8px 24px rgba(0,0,0,0.4)' }}
        >
          <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Notifications</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>7 derniers jours — ce que les toasts ont notifié (ou auraient notifié, absent au moment)</p>
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: 340 }}>
            {loading ? (
              <p className="px-4 py-6 text-xs text-center" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
            ) : !data || data.items.length === 0 ? (
              <p className="px-4 py-6 text-xs text-center" style={{ color: 'var(--text-muted)' }}>Aucune notification sur les 7 derniers jours.</p>
            ) : (
              <>
                {data.items.map((it, i) => (
                  <div key={i} className="px-4 py-2.5 flex items-start gap-2.5" style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    {it.kind === 'asset' ? (
                      <>
                        <span style={{ color: '#58a6ff' }} className="mt-0.5">
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" /></svg>
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                            <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{it.asset_name || it.hostname}</span>
                            {' '}terminé — {it.checked_count} vérifiée{it.checked_count !== 1 ? 's' : ''}
                            {it.auto_bascule_count > 0 && `, ${it.auto_bascule_count} bascule${it.auto_bascule_count !== 1 ? 's' : ''} automatique${it.auto_bascule_count !== 1 ? 's' : ''}`}
                          </p>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--text-faint)' }}>{relativeTime(it.at)}</p>
                        </div>
                      </>
                    ) : (
                      <>
                        <span style={{ color: it.status === 'patched' ? '#3fb950' : '#a371f7' }} className="mt-0.5">
                          {it.status === 'patched' ? (
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                          ) : (
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" /></svg>
                          )}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                            <button onClick={() => { setOpen(false); openCveJustification(it, setDetailModal) }}
                              className="font-mono font-semibold hover:underline" style={{ color: '#58a6ff' }}
                              title="Consulter le justificatif de clôture de cette CVE">
                              {it.cve_id}
                            </button>
                            {' '}sur {it.asset_name} — {it.status === 'patched' ? 'corrigée' : 'faux positif'}
                          </p>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--text-faint)' }}>{relativeTime(it.at)}</p>
                        </div>
                      </>
                    )}
                  </div>
                ))}
                {data.total > data.items.length && (
                  <p className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                    … et {data.total - data.items.length} de plus sur la période — voir "Vulnérabilités traitées" pour le détail complet.
                  </p>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
    {detailModal && (
      <AnnotationDetailModal
        vuln={detailModal.vuln}
        label={detailModal.label}
        color={detailModal.color}
        date={detailModal.date}
        blocks={detailModal.blocks}
        title={detailModal.title}
        emptyText={detailModal.emptyText}
        onClose={() => setDetailModal(null)}
      />
    )}
    </>
  )
}

const TOOLTIP_STYLE = { backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }

// Compteur léger, module Audits — findings encore ouverts sur un audit déjà terminé, jamais
// retestés (GET /audits/findings/open-unretested-count). Volontairement isolé du reste du
// Dashboard (état/effect propres) : pas d'intégration dans la logique de filtrage vuln
// existante, déjà très couplée (cf. STATUS.md).
function AuditFindingsCard() {
  const [count, setCount] = useState(null)
  useEffect(() => { openUnretestedFindingsCount().then(r => setCount(r.data.count)).catch(() => {}) }, [])
  if (!count) return null
  return (
    <Link to="/audits" style={CARD} className="p-4 flex items-center justify-between gap-3 hover:opacity-90 transition-opacity">
      <div>
        <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Findings d'audit</p>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          <strong style={{ color: '#d29922' }}>{count}</strong> finding{count !== 1 ? 's' : ''} ouvert{count !== 1 ? 's' : ''} sur un audit terminé, jamais retesté{count !== 1 ? 's' : ''}
        </p>
      </div>
      <span style={{ color: '#d29922' }}>⚠</span>
    </Link>
  )
}

// Certificats SSL surveillés par PRTG (04/08/2026, cf. services/prtg_matcher.py,
// GET /api/prtg/ssl-certificates) — seuils d'urgence arbitraires mais standards
// pour un renouvellement de certificat (< 14j = critique, < 30j = à prévoir).
// Toujours affichée si au moins un certificat est surveillé (contrairement à
// AuditFindingsCard qui se cache à 0) : "rien d'urgent" est une information utile
// en soi, pas juste une absence de contenu — évite de se demander si PRTG est
// bien branché ou s'il n'y a simplement rien à signaler.
const SSL_URGENCY = (days) => days < 14
  ? { color: '#f85149', label: 'Critique' }
  : days < 30
    ? { color: '#d29922', label: 'À prévoir' }
    : { color: '#3fb950', label: 'OK' }

function SslCertificatesCard() {
  const [certs, setCerts] = useState(null)
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => { prtgSslCertificates().then(r => setCerts(r.data)).catch(() => setCerts([])) }, [])

  useEffect(() => {
    if (!open) return
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  if (!certs || certs.length === 0) return null

  const soonest = certs[0]
  const urgentCount = certs.filter(c => c.days_remaining < 30).length
  const headline = urgentCount > 0
    ? { color: '#d29922', text: `${urgentCount} certificat${urgentCount !== 1 ? 's' : ''} SSL expirant sous 30 jours` }
    : { color: '#3fb950', text: `Aucun certificat SSL surveillé n'expire sous 30 jours` }

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(o => !o)} style={CARD}
        className="p-4 w-full flex items-center justify-between gap-3 hover:opacity-90 transition-opacity text-left"
      >
        <div>
          <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Certificats SSL (PRTG)</p>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            <strong style={{ color: headline.color }}>{headline.text}</strong>
            {' — prochain : '}{soonest.asset_name} dans {soonest.days_remaining} j
          </p>
        </div>
        <span style={{ color: headline.color }}>⚠</span>
      </button>

      {open && (
        <div className="absolute left-0 right-0 top-full mt-2 rounded-xl overflow-hidden z-50"
          style={{ maxHeight: 420, background: 'var(--bg-card)', border: '1px solid var(--border)', boxShadow: '0 8px 24px rgba(0,0,0,0.4)' }}
        >
          <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Certificats SSL surveillés</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{certs.length} certificat{certs.length !== 1 ? 's' : ''}, triés par expiration la plus proche</p>
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: 340 }}>
            {certs.map((c, i) => {
              const urgency = SSL_URGENCY(c.days_remaining)
              return (
                <Link key={i} to="/assets" onClick={() => setOpen(false)}
                  className="px-4 py-2.5 flex items-center justify-between gap-2.5 hover:opacity-80 transition-opacity"
                  style={{ borderBottom: '1px solid var(--border-subtle)' }}
                >
                  <div className="min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-secondary)' }}>{c.asset_name}</p>
                    <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-faint)' }}>{c.sensor}</p>
                  </div>
                  <span className="text-xs font-semibold flex-shrink-0" style={{ color: urgency.color }}>{c.days_remaining} j</span>
                </Link>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// Relief + tilt 3D (21/08/2026, demande explicite — 2e usage après Home.jsx, cf. utils/tilt3d.js
// et index.css § .tile-3d) : `--tile` reprend la couleur déjà passée pour la valeur elle-même,
// pas une nouvelle prop — les 4 KPI sont déjà chacun dans leur propre teinte.
function KpiCard({ label, value, sub, color, tiltEnabled }) {
  return (
    <div style={{ ...CARD, '--tile': color || 'var(--text-muted)' }} className="p-5 tile-3d"
      onMouseMove={tiltEnabled ? tiltMouseMove : undefined}
      onMouseEnter={tiltEnabled ? tiltMouseEnter : undefined}
      onMouseLeave={tiltEnabled ? tiltMouseLeave : undefined}>
      <span className="tile-3d-glare" aria-hidden="true" />
      <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</p>
      <p className="text-3xl font-bold mt-2" style={{ color: color || 'var(--text-primary)' }}>{value ?? '—'}</p>
      {sub && <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{sub}</p>}
    </div>
  )
}

// Dashboard personnalisable (21/08/2026, demande explicite) — enveloppe une tuile (KPI, barre de
// Filtres ou bloc de contenu) dans la grille réordonnable/redimensionnable. Réordonnancement en
// CSS pur (`order`, cf. constants/dashboardLayout.js) plutôt qu'en réécrivant l'ordre du JSX : le
// contenu de chaque tuile reste exactement là où il est déjà écrit dans le fichier (accès direct
// au state/handlers du composant Dashboard, aucune extraction risquée sur un fichier de cette
// taille) — seule sa position VISUELLE change. Drag-and-drop HTML5 natif (pas de nouvelle
// dépendance, cf. plan). Registre unique pour KPI + Filtres + blocs (21/08/2026, revenu sur un
// 1er essai à deux composants/deux grilles séparées — retour utilisateur : impossible de
// déplacer une tuile de part et d'autre de la barre de Filtres, `order` CSS ne jouant qu'entre
// enfants d'un même conteneur). "Filtres" est verrouillé (LOCKED_WIDGETS) : ni draggable, ni
// redimensionnable lui-même, mais reste une cible de dépôt valide pour les autres tuiles.
function Widget({ id, children }) {
  const { order, sizes, editMode, setWidgetSize, reorder, moveWidget } = useDashboardLayout()
  const [dragOver, setDragOver] = useState(false)
  const size = sizes[id] || 'full'
  const locked = LOCKED_WIDGETS.includes(id)
  const idx = order.indexOf(id)

  function handleDragStart(e) {
    e.dataTransfer.setData('text/plain', id)
    e.dataTransfer.effectAllowed = 'move'
  }
  function handleDragOver(e) {
    e.preventDefault()
    setDragOver(true)
  }
  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const fromId = e.dataTransfer.getData('text/plain')
    if (fromId) reorder(fromId, id)
  }

  return (
    <div
      style={{ gridColumn: `span ${SIZE_SPAN[size]}`, order: order.indexOf(id) }}
      draggable={editMode && !locked}
      onDragStart={editMode && !locked ? handleDragStart : undefined}
      onDragOver={editMode ? handleDragOver : undefined}
      onDragLeave={editMode ? () => setDragOver(false) : undefined}
      onDrop={editMode ? handleDrop : undefined}
    >
      {editMode && (
        <div className="flex items-center justify-between gap-2 mb-2 px-3 py-1.5 rounded-lg text-xs"
          style={{ background: 'rgba(88,166,255,0.1)', border: '1px dashed rgba(88,166,255,0.35)', cursor: locked ? 'default' : 'grab' }}>
          <span style={{ color: 'var(--text-secondary)' }}>{locked ? '🔒' : '⠿'} {WIDGET_LABELS[id]}</span>
          {!locked && (
            <div className="flex items-center gap-2 flex-shrink-0">
              {/* Boutons ◀/▶ (21/08/2026, retour utilisateur — "pour bouger entre eux c'est
                  compliqué") : alternative fiable au glisser-déposer, échange juste la tuile
                  avec sa voisine immédiate. Grisés en butée (1re/dernière position). */}
              <div className="flex gap-1">
                <button onClick={() => moveWidget(id, -1)} disabled={idx <= 0}
                  title="Déplacer avant"
                  className="w-5 h-5 flex items-center justify-center rounded text-[11px] font-semibold transition-colors disabled:opacity-30"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>‹</button>
                <button onClick={() => moveWidget(id, 1)} disabled={idx >= order.length - 1}
                  title="Déplacer après"
                  className="w-5 h-5 flex items-center justify-center rounded text-[11px] font-semibold transition-colors disabled:opacity-30"
                  style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>›</button>
              </div>
              <div className="flex gap-1">
                {['eighth', 'quarter', 'third', 'half', 'full'].map(s => (
                  <button key={s} onClick={() => setWidgetSize(id, s)}
                    className="px-1.5 py-0.5 rounded text-[10px] font-semibold transition-colors"
                    style={size === s
                      ? { background: '#58a6ff', color: '#fff' }
                      : { background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
                    {SIZE_LABELS[s]}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      <div style={{ outline: dragOver ? '2px dashed #58a6ff' : 'none', outlineOffset: 2, borderRadius: 12 }}>
        {children}
      </div>
    </div>
  )
}

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// Dashboard.jsx est entièrement redémonté à chaque navigation (pas de keep-alive de route,
// cf. Layout.jsx/App.jsx), donc revenir dessus relançait ~13 requêtes et l'écran de
// chargement plein écran à CHAQUE fois, pas seulement au premier chargement de la session
// (retour utilisateur, 14/08/2026 : "le Dashboard se recharge dès que je change de page").
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux (mécanisme déjà existant, cf. `silent` sur loadLists)
// les met à jour en fond — jamais reset explicitement, une session onglet = un cache.
let dashboardCache = null

export default function Dashboard() {
  const { isAnonymous } = usePresentation()
  const { editMode, setEditMode, resetToDefault } = useDashboardLayout()
  const { user } = useAuth()
  const tiltEnabled = useTiltEnabled()
  const [kpis, setKpis] = useState(() => dashboardCache?.kpis ?? null)
  const [openVulns, setOpenVulns] = useState(() => dashboardCache?.openVulns ?? [])
  const [patchedVulns, setPatchedVulns] = useState(() => dashboardCache?.patchedVulns ?? [])
  const [awaitingVulns, setAwaitingVulns] = useState(() => dashboardCache?.awaitingVulns ?? [])
  // Totaux serveur par statut — les badges des tableaux s'appuient dessus plutôt
  // que sur la longueur des listes chargées (plafonnées par `per_page`).
  const [totals, setTotals] = useState(() => dashboardCache?.totals ?? { open: 0, patched: 0, awaiting: 0 })
  // `false` si un cache existe déjà (remontage) — évite l'écran de chargement plein
  // écran systématique, cf. commentaire de `dashboardCache` plus haut.
  const [loading, setLoading] = useState(() => !dashboardCache)
  const [actionMsg, setActionMsg] = useState('')
  // Rattrapage des bascules automatiques survenues depuis la dernière visite
  // (le cycle autonome tourne aussi la nuit, cf. tasks/scheduled_tasks.py, sans
  // que personne ne regarde l'écran) — `null` tant que non chargé/non pertinent.
  const [catchUp, setCatchUp] = useState(null)
  // Toasts — bascules auto détectées EN DIRECT par le polling (page déjà
  // ouverte), complémentaires au bandeau de rattrapage ci-dessus (qui couvre
  // lui l'absence, ex. cycle de nuit). Remplace l'ancien flash bleu générique
  // pour ce cas précis — les autres flash() (actions manuelles de l'analyste)
  // restent inchangés, un clic délibéré mérite un retour au même endroit.
  const [toasts, setToasts] = useState([])
  const TOAST_LIFETIME = 6000
  const TOAST_EXIT = 150   // doit correspondre à la durée de l'animation 'toast-out'

  function pushToast(message, variant = 'info') {
    const id = `${Date.now()}-${Math.random()}`
    setToasts(prev => [...prev, { id, message, variant, leaving: false }])
    setTimeout(() => dismissToast(id), TOAST_LIFETIME)
  }

  function dismissToast(id) {
    // Marque "leaving" pour jouer l'animation de sortie avant de retirer
    // réellement l'entrée — un retrait immédiat sauterait l'animation.
    setToasts(prev => prev.map(t => t.id === id ? { ...t, leaving: true } : t))
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), TOAST_EXIT)
  }
  const [analysisModal, setAnalysisModal] = useState(null)
  const [patchModal, setPatchModal] = useState(null)
  // Bouton "Détail" (07/08/2026, demande explicite) — commandes SSH/WinRM et
  // retour brut du contrôle, repliés par défaut. Remis à false à chaque
  // nouveau contrôle, cf. handlePatchCheck.
  const [showDebugCommands, setShowDebugCommands] = useState(false)
  const [awaitingModal, setAwaitingModal] = useState(null)
  const [falsePositiveModal, setFalsePositiveModal] = useState(null)
  const [patchedModal, setPatchedModal] = useState(null)
  // Pré-remplissage de l'annotation depuis le justificatif technique déjà affiché
  // (04/08/2026, demande explicite) — vide si "✓ Corrigé" est cliqué directement
  // depuis la ligne (pas de résultat de patch check frais sous la main à cet instant).
  const [patchedModalPrefill, setPatchedModalPrefill] = useState('')
  // "Déjà résolu ailleurs" (04/08/2026) — même fonctionnalité que Vulnerabilities.jsx,
  // cf. son commentaire pour le détail (badge alimenté par resolved_elsewhere_count
  // déjà présent dans la réponse de fetchVulns, détail chargé au clic seulement).
  const [otherInstancesModal, setOtherInstancesModal] = useState(null)
  const [bulkPatchedModalOpen, setBulkPatchedModalOpen] = useState(false)
  const [editNoteModal, setEditNoteModal] = useState(null)
  const [detailModal, setDetailModal] = useState(null)
  const [patchLoading, setPatchLoading] = useState({})
  const [patchDetected, setPatchDetected] = useState(() => dashboardCache?.patchDetected ?? {})
  const [openLimit, setOpenLimit] = useState(10)
  const [patchedLimit, setPatchedLimit] = useState(10)
  const [awaitingLimit, setAwaitingLimit] = useState(10)
  const [selectedIds, setSelectedIds] = useState(new Set())
  // Lignes en cours de sortie de "à traiter" (fondu bref avant la bascule
  // réelle vers "traitées") — évite la disparition instantanée qui rend une
  // validation groupée difficile à suivre visuellement.
  const [leavingIds, setLeavingIds] = useState(new Set())
  // Candidats "faux positif" (CVE sans objet sur l'actif) — chargés depuis le
  // backend, qui seul sait revérifier les règles de matching courantes.
  const [fpCandidates, setFpCandidates] = useState([])
  const [fpModalOpen, setFpModalOpen] = useState(false)
  const [batchProgress, setBatchProgress] = useState(null)
  // Miroir de batchProgress pour l'intervalle de rafraîchissement (deps stables) :
  // sans ref, l'intervalle capturerait la valeur du montage et ne se suspendrait
  // jamais pendant un patch check groupé.
  const batchProgressRef = useRef(null)
  const [batchRowStatus, setBatchRowStatus] = useState({})  // id → 'pending'|'checking'|'done'|'not_found'|'error'
  const [batchStats, setBatchStats] = useState({ current: 0, total: 0, detected: 0 })
  // `severities` : multi-sélection (vide = toutes affichées). Filtre les trois
  // tableaux (à traiter / en attente / traitées) par sévérité de CVE.
  const [dashFilter, setDashFilter] = useState({ severities: [], search: '', onlyDetected: false, onlyFalsePositive: false, onlyResolvedElsewhere: false, criticite: '' })
  const [awaitingSearch, setAwaitingSearch] = useState('')
  const [patchedSearch, setPatchedSearch] = useState('')
  // Résultats serveur d'une recherche de CVE traitée : la liste locale n'est
  // chargée que jusqu'à `per_page` (200, triée par score), donc une CVE traitée
  // hors fenêtre (typiquement une LOW) y est absente et introuvable en local.
  // null = pas de recherche en cours (on utilise la liste locale).
  const [remotePatched, setRemotePatched] = useState(null)
  const [remotePatchedTotal, setRemotePatchedTotal] = useState(null)   // total exact en base pour le filtre serveur actif
  const [patchedStatusFilter, setPatchedStatusFilter] = useState('')
  const [assetList, setAssetList] = useState(() => dashboardCache?.assetList ?? [])
  const [selectedAssetIds, setSelectedAssetIds] = useState([])
  const [dashSort, setDashSort] = useState({ by: 'severity', dir: 'desc' })
  // Tri indépendant des sections "en attente" et "traitées" (même mécanique que
  // "à traiter" : clic sur l'en-tête Sévérité/Score bascule desc/asc).
  const [awaitingSort, setAwaitingSort] = useState({ by: 'severity', dir: 'desc' })
  const [patchedSort, setPatchedSort]   = useState({ by: 'severity', dir: 'desc' })
  const [autoCheck, setAutoCheck] = useState({ current: null, pending: 0, total: 0, assets: [], startedAt: null })
  // Dernier cycle connu (persisté en base, cf. main.py::_check_interrupted_patch_cycle) —
  // seul "interrupted" est affiché : un redémarrage du backend (--reload en dev) a coupé
  // le cycle avant qu'il n'ait pu tout vérifier, alors qu'aucun cycle actif n'est visible
  // par ailleurs. Rien à afficher pour "completed"/"running" (déjà couvert par la barre
  // de progression ci-dessous quand un cycle est réellement en cours).
  const [lastCycleInfo, setLastCycleInfo] = useState({ status: null, at: null })
  // Évènements agent non acquittés (19/08/2026, cf. docs/AGENT_DETECTION.md) — bandeau
  // persistant distinct du honeypot DB (jamais fusionnés, § Décisions figées de la doc :
  // "les évènements agent ne partagent pas la bannière rouge du Dashboard avec le honeypot
  // DB"), couleur cyan (module Inventaire) plutôt que rouge pour rester visuellement distinct.
  // Ouvert à tout connecté, comme le badge nav Durcissement (le détail/l'acquittement restent
  // réservés admin sur la page elle-même).
  const [agentEventsCount, setAgentEventsCount] = useState(0)
  // Lien direct vers l'actif concerné (19/08/2026, retour utilisateur — "il doit amener à
  // l'actif concerné et non à la page") — le serveur ne le renseigne que quand un seul actif
  // porte les criticals en attente (routers/agents.py::security_events_count) ; ambigu (plusieurs
  // actifs) ou vide, on retombe sur la page Durcissement seule.
  const [agentEventsAssetId, setAgentEventsAssetId] = useState(null)
  useEffect(() => {
    if (isAnonymous) { setAgentEventsCount(0); setAgentEventsAssetId(null); return }
    let alive = true
    const load = () => agentSecurityEventsCount()
      .then(r => { if (alive) { setAgentEventsCount(r.data.unacknowledged || 0); setAgentEventsAssetId(r.data.asset_id || null) } })
      .catch(() => {})
    load()
    const t = setInterval(load, 30000)
    return () => { alive = false; clearInterval(t) }
  }, [isAnonymous])
  const lastCompletedRef = useRef(null)
  // Total du cycle en cours, pour la barre de progression — capturé au premier tick
  // où une vérification est active, remis à zéro une fois le cycle terminé.
  const runTotalRef = useRef(0)
  // Notification par actif terminé (08/08/2026, demande explicite ; 11/08/2026,
  // alignée sur le même comportement que la notification CVE ci-dessus — plus de
  // garde `firstPollRef`) : nombre de bascules automatiques vues pendant son
  // contrôle + CVE ouvertes restantes par sévérité. `autoBasculeCountRef` compte
  // par actif (clé hostname||asset_name, remise à zéro dès la notification
  // poussée) ; `notifiedDoneAssetsRef` évite de notifier deux fois le même actif
  // dans un même cycle — seul garde-fou qui reste, exactement comme `lastCompletedRef`
  // ci-dessus pour les CVE (dédoublonnage par clé déjà vue, jamais de silence sur le
  // premier poll). L'ancienne garde `firstPollRef` ("rien au premier poll, sinon
  // rouvrir la page mi-cycle spammerait") avait un vrai coût : un actif qui terminait
  // pendant que l'onglet était fermé/rechargé était marqué "déjà notifié" sans que le
  // toast n'ait jamais été vu — silence permanent sur cet actif, signalé par
  // l'utilisateur ("je ne reçois pas la notification... avant j'avais l'info").
  const autoBasculeCountRef = useRef({})
  const notifiedDoneAssetsRef = useRef(new Set())
  // Miroir toujours à jour de openVulns, pour l'effet de polling ci-dessous : cet
  // effet ne se relance jamais (deps []), donc toute closure qu'il capture au montage
  // resterait figée sur openVulns=[] pour toujours sans ce ref.
  const openVulnsRef = useRef(openVulns)
  useEffect(() => { openVulnsRef.current = openVulns }, [openVulns])
  // Même besoin que openVulnsRef : le polling (deps []) doit pouvoir retrouver
  // une vuln "en attente de correctif" que le cycle autonome vient de basculer
  // en patched, sans figer sur l'état du montage initial.
  const awaitingVulnsRef = useRef(awaitingVulns)
  useEffect(() => { awaitingVulnsRef.current = awaitingVulns }, [awaitingVulns])
  // Même besoin : les handlers appelés depuis le polling (moveVulnToPatched) doivent
  // rafraîchir les KPI avec la sélection d'actifs *courante*, pas celle du montage.
  const selectedAssetIdsRef = useRef(selectedAssetIds)
  useEffect(() => { selectedAssetIdsRef.current = selectedAssetIds }, [selectedAssetIds])
  useEffect(() => { batchProgressRef.current = batchProgress }, [batchProgress])

  function statsParams() {
    const ids = selectedAssetIdsRef.current
    return ids.length ? { asset_id: ids.join(',') } : {}
  }
  function refreshStats() {
    // Mode Présentation : les KPI sont recalculés localement (displayKpis,
    // dérivé de assetScopedOpen/Patched/Awaiting) — pas besoin d'appeler le
    // backend, qui ignorerait de toute façon les vulns/actifs fictifs.
    if (isAnonymous) return
    return fetchStats(statsParams()).then(s => setKpis(s.data))
  }

  const today = new Date().toLocaleDateString('fr-FR')

  // Chargement des 3 tableaux. Extrait en useCallback (et non plus enfermé dans
  // un useEffect de montage) pour pouvoir être rejoué : le cycle de patch check
  // autonome et la sync NVD modifient la base en continu, or les listes ne se
  // rafraîchissaient jamais après le montage — il fallait changer de page pour
  // voir les nouvelles bascules (incident 21/07/2026).
  //
  // `asset_id` est passé au serveur plutôt que filtré côté client : c'est ce qui
  // rend les totaux (`total` de la réponse) exacts pour la sélection courante.
  // Le filtre client `matchesAssetFilter` est conservé — il reste nécessaire en
  // mode Présentation, où des vulns fictives sont fusionnées après coup.
  const loadLists = useCallback((opts = {}) => {
    const { silent = false } = opts
    if (!silent) setLoading(true)
    // `configured_only` (07/08/2026, demande explicite) : sans sélection
    // explicite, ces 3 listes (open/patched/awaiting) doivent refléter le même
    // périmètre "actifs configurés" que /api/stats juste au-dessus — sinon les
    // KPI affichaient "3 actifs" pendant que ces tableaux montraient encore des
    // vulns des 69 non configurés (`asset_id` absent = aucun filtre côté
    // GET /api/vulnerabilities avant ce paramètre).
    // `max_age_years: 2` (07/08/2026, demande explicite) : le dashboard reste
    // volontairement borné aux CVE récentes, même avec un actif sélectionné —
    // "trop chargé" sinon. Pour un historique complet sur un actif, la page
    // Vulnérabilités reste l'outil (bouton "CVE anciennes" dédié, cf. son
    // propre `max_age_years`) — pas une raison de lever la limite ici.
    const scope = {
      ...(selectedAssetIds.length ? { asset_id: selectedAssetIds.join(',') } : { configured_only: true }),
      max_age_years: 2,
    }
    return Promise.all([
      fetchVulns({ status: 'open', per_page: 200, page: 1, ...scope }),
      fetchVulns({ status: 'patched', per_page: 200, page: 1, ...scope }),
      fetchVulns({ status: 'awaiting_fix', per_page: 200, page: 1, ...scope }),
      // Cas mixte (27/07/2026, cf. STATUS.md) : un paquet visé par la CVE est
      // absent, l'autre installé n'a aucun correctif Debian — statut dédié
      // mais même section "en attente" que `awaiting_fix` (juste un badge
      // "partiel" en plus), pas de bucket séparé.
      fetchVulns({ status: 'awaiting_fix_partial', per_page: 200, page: 1, ...scope }),
      fetchVulns({ status: 'false_positive', per_page: 200, page: 1, ...scope }),
      fetchAssets(),
    ]).then(([open, patched, awaiting, awaitingPartial, falsePos, assetsRes]) => {
      let openItems = open.data.items || []
      // "Traitées" regroupe les deux issues terminales : corrigée (patched) et
      // faux positif (false_positive) — triées ensemble par date de clôture.
      let closed = [...(patched.data.items || []), ...(falsePos.data.items || [])]
        .sort((a, b) => new Date(b.patched_at || b.false_positive_at || 0) - new Date(a.patched_at || a.false_positive_at || 0))
      let awaitingItems = [...(awaiting.data.items || []), ...(awaitingPartial.data.items || [])]
        .sort((a, b) => new Date(b.awaiting_fix_at || 0) - new Date(a.awaiting_fix_at || 0))
      let assetsList = assetsRes.data || []

      // Totaux serveur — les badges affichaient jusqu'ici la longueur des listes
      // *chargées*, donc plafonnée par `per_page` : "50 corrigées" alors que la
      // base en comptait 4600, et un écart permanent avec la carte KPI juste
      // au-dessus (qui, elle, lit /api/stats). Cf. STATUS.md 21/07/2026.
      const newTotals = {
        open: open.data.total ?? openItems.length,
        patched: (patched.data.total ?? 0) + (falsePos.data.total ?? 0),
        awaiting: (awaiting.data.total ?? 0) + (awaitingPartial.data.total ?? 0),
      }
      setTotals(newTotals)

      if (isAnonymous) {
        // Mode Présentation : noms/IP/analystes réels remplacés par des
        // équivalents fictifs (id réel conservé, actions inchangées), parc
        // complété par des actifs et vulnérabilités 100% inventés.
        openItems = [...openItems.map(anonymizeVuln), ...FAKE_VULNERABILITIES.filter(v => v.status === 'open')]
        const fakeClosed = FAKE_VULNERABILITIES.filter(v => v.status === 'patched' || v.status === 'false_positive')
        closed = [...closed.map(anonymizeVuln), ...fakeClosed]
          .sort((a, b) => new Date(b.patched_at || b.false_positive_at || 0) - new Date(a.patched_at || a.false_positive_at || 0))
        awaitingItems = [...awaitingItems.map(anonymizeVuln), ...FAKE_VULNERABILITIES.filter(v => v.status === 'awaiting_fix')]
        assetsList = [...assetsList.map(anonymizeAsset), ...FAKE_ASSETS]
      }

      const sortedAssets = [...assetsList].sort((a, b) => a.name.localeCompare(b.name))
      setOpenVulns(openItems)
      setPatchedVulns(closed)
      setAwaitingVulns(awaitingItems)
      setAssetList(sortedAssets)
      // Reprend les badges "Patch détecté" déjà persistés (ex: CRITICAL vérifiée par le
      // check auto avant l'ouverture du dashboard) — pas seulement ceux vus en live via le polling.
      // Remplacement (pas fusion) : c'est la vérité serveur, et une vuln réouverte
      // voit son patch_check_result effacé côté backend — un merge garderait un badge périmé.
      const persisted = {}
      openItems.forEach(v => { if (v.patch_detected) persisted[v.id] = true })
      setPatchDetected(persisted)
      // Alimente le cache module (cf. déclaration en tête de fichier) pour que le
      // prochain remontage du composant réaffiche ces données instantanément.
      dashboardCache = {
        ...dashboardCache,
        openVulns: openItems, patchedVulns: closed, awaitingVulns: awaitingItems,
        totals: newTotals, assetList: sortedAssets, patchDetected: persisted,
      }
      // Purge les sélections pointant vers des lignes qui ne sont plus ouvertes
      // (basculées entre-temps par le cycle autonome) — sinon une action groupée
      // porterait sur des ids fantômes.
      const openIds = new Set(openItems.map(v => v.id))
      setSelectedIds(prev => new Set([...prev].filter(id => openIds.has(id))))
    }).finally(() => { if (!silent) setLoading(false) })
  }, [isAnonymous, selectedAssetIds])

  // Bug réel corrigé (11/08/2026, signalé par l'utilisateur — "je sélectionne un actif,
  // ça actualise la page et je ne peux pas le sélectionner") : `loadLists` change de
  // référence à chaque changement de `selectedAssetIds` (son propre tableau de
  // dépendances juste au-dessus), donc CET effet se rejoue à chaque coche dans
  // `AssetDropdown` — avec `silent` par défaut à `false`, chaque coche remplaçait tout
  // le Dashboard par `<PageLoader/>` (cf. plus bas), démontant le dropdown ouvert avant
  // que l'utilisateur ait fini de cocher. Seul le TOUT PREMIER appel (montage de page)
  // doit afficher le loader plein écran ; les suivants (réaction au filtre Actifs) sont
  // des rafraîchissements de données déjà visibles, pas un premier chargement — même
  // logique `silent` que le rafraîchissement périodique de 30s un peu plus bas.
  // `dashboardCache` (pas un ref par instance, cf. sa déclaration en tête de fichier) :
  // un aller-retour sur une autre page puis retour ici est un REMONTAGE, pas le même
  // "premier appel" — sans ce changement, revenir sur le Dashboard rejouait le loader
  // plein écran à chaque fois (retour utilisateur, 14/08/2026).
  useEffect(() => {
    loadLists({ silent: dashboardCache != null })
  }, [loadLists])

  // Recherche/filtre serveur des vulns traitées : la liste locale est plafonnée à
  // 200 (triée par score), donc une vuln traitée hors fenêtre (typiquement une LOW)
  // y est invisible. Dès qu'on tape une recherche OU qu'on coche une sévérité, on
  // interroge le backend (par CVE et/ou sévérité) et on ne garde que les statuts
  // terminaux affichés dans cette section (patched / false_positive).
  useEffect(() => {
    const term = patchedSearch.trim()
    const sevs = dashFilter.severities
    if (isAnonymous || (!term && sevs.length === 0)) { setRemotePatched(null); setRemotePatchedTotal(null); return }
    const t = setTimeout(() => {
      // Même périmètre que loadLists (07/08/2026) : cette recherche ignorait
      // jusqu'ici la sélection d'actifs (et le défaut "configurés"), remontant
      // des vulns hors filtre dès qu'on tapait un terme. `max_age_years: 2`
      // même raison que loadLists — une CVE résolue trop ancienne pour être
      // trouvée ici reste consultable sur la page Vulnérabilités.
      const base = {
        per_page: 200,
        max_age_years: 2,
        ...(selectedAssetIds.length ? { asset_id: selectedAssetIds.join(',') } : { configured_only: true }),
      }
      if (term) base.search = term
      if (sevs.length) base.severity = sevs.join(',')
      // Deux appels (patched + false_positive) : chacun renvoie son `total` exact
      // → on connaît le vrai nombre de traitées en base pour ce filtre (affichage
      // "X sur Y"), et on ramène jusqu'à 200 de chaque statut au lieu de 200 mêlés.
      Promise.all([
        fetchVulns({ ...base, status: 'patched' }),
        fetchVulns({ ...base, status: 'false_positive' }),
      ])
        .then(([p, f]) => {
          setRemotePatched([...(p.data.items || []), ...(f.data.items || [])])
          setRemotePatchedTotal((p.data.total || 0) + (f.data.total || 0))
        })
        .catch(() => { setRemotePatched(null); setRemotePatchedTotal(null) })
    }, 300)
    return () => clearTimeout(t)
  }, [patchedSearch, dashFilter.severities, isAnonymous, selectedAssetIds])

  const loadFpCandidates = useCallback(() => {
    if (isAnonymous) return Promise.resolve()
    // Même périmètre que loadLists (07/08/2026, demande explicite) : cette liste
    // ("Faux positifs proposés") interrogeait tout le parc sans le moindre
    // filtre, y compris les 69 actifs jamais configurés — d'où le "151" affiché
    // alors que le reste du dashboard n'en montre plus que 3. Une sélection
    // explicite à un seul actif reste possible (bouton "CVE anciennes" ailleurs
    // dans l'app) ; au-delà d'un actif, `false-positive-candidates` ne sait
    // filtrer que sur un seul `asset_id` — pas de sélection multiple ici.
    const singleAssetId = selectedAssetIds.length === 1 ? selectedAssetIds[0] : undefined
    return falsePositiveCandidates(singleAssetId, !singleAssetId).then(r => setFpCandidates(r.data.items || [])).catch(() => {})
  }, [isAnonymous, selectedAssetIds])

  useEffect(() => { loadFpCandidates() }, [loadFpCandidates])

  // Index des ids candidats, pour le filtre "faux positif uniquement" du tableau.
  const fpCandidateIds = new Set(fpCandidates.map(v => v.id))
  // Motif par vuln, affiché en infobulle du badge — l'analyste voit *pourquoi*
  // sans ouvrir la modale de qualification.
  const fpReasonById = new Map(fpCandidates.map(v => [v.id, v.justification]))

  async function handleFpConfirm(vulnIds, validator, notes) {
    const r = await bulkFalsePositive(vulnIds, validator, notes)
    const applied = r.data.applied?.length || 0
    setFpModalOpen(false)
    setSelectedIds(new Set())
    flash(`${applied} vulnérabilité(s) qualifiée(s) en faux positif — validé par ${validator}`)
    await Promise.all([loadLists({ silent: true }), loadFpCandidates()])
  }

  // Rafraîchissement périodique silencieux (30s) — garde les 3 tableaux alignés
  // sur le travail du cycle autonome et de la sync NVD, sans changer de page.
  // Ne remplace pas le polling de progression (3s, plus fin, cf. plus bas) mais
  // le rattrape : ce dernier ne voit que la *dernière* vérification terminée, or
  // le cycle en enchaîne plusieurs par tick depuis l'optimisation du relevé par
  // actif — les bascules intermédiaires étaient perdues pour l'affichage.
  //
  // Suspendu pendant un patch check groupé : un remplacement de liste en plein
  // milieu ferait sauter la progression par ligne (batchRowStatus).
  // KPI (03/08/2026) : le fetch initial de refreshStats() (plus bas) est en
  // `.catch(() => {})` — un échec transitoire (base sous charge pendant un
  // cycle de patch check/matching) laissait `kpis` bloqué à `null` pour toute
  // la session, sans jamais se rattraper ("sur undefined actifs", "0% — 0/0"
  // constatés en usage réel). Rejoué ici comme les 3 tableaux : un raté
  // s'efface tout seul au tick suivant.
  useEffect(() => {
    const id = setInterval(() => {
      if (batchProgressRef.current) return
      loadLists({ silent: true })
      loadFpCandidates()
      refreshStats()
    }, 30000)
    return () => clearInterval(id)
  }, [loadLists, loadFpCandidates])

  // KPI recalculés sur la sélection d'actifs — se relance au montage (sélection
  // vide = parc entier) et à chaque changement de sélection. En mode
  // Présentation, displayKpis (plus bas) prend le relais localement — inutile
  // d'interroger un backend qui ignore les actifs/vulns fictifs.
  useEffect(() => {
    if (isAnonymous) return
    fetchStats(selectedAssetIds.length ? { asset_id: selectedAssetIds.join(',') } : {})
      .then(s => { setKpis(s.data); dashboardCache = { ...dashboardCache, kpis: s.data } })
      .catch(() => {})
  }, [selectedAssetIds, isAnonymous])

  // Bandeau de rattrapage — une seule fois au montage du Dashboard. Repère
  // "dernière visite" suivi par navigateur (localStorage), pas par session
  // serveur — un même compte ouvert sur deux postes aura donc deux rattrapages
  // indépendants, assumé (même mécanique avant l'authentification réelle).
  // Absent en mode Présentation : les cve_id/noms d'actifs renvoyés par l'API
  // sont réels, jamais anonymisés côté serveur pour ces endpoints.
  //
  // Étoffé le 18/08/2026 (demande explicite) pour rassembler ici tout ce qui a
  // pu se passer sans que personne ne regarde l'écran (cycle autonome de nuit,
  // sync NVD, actifs ajoutés/retirés côté AD/SSH...), plutôt que de laisser
  // chaque signal dans son coin (WelcomeOverlay au login, badges de la sidebar,
  // pages dédiées) — mêmes sources que WelcomeOverlay.jsx pour la partie
  // sécurité/NIS 2, composées ici en un seul bandeau persistant au lieu d'un
  // écran qui se referme après quelques secondes.
  useEffect(() => {
    if (isAnonymous) return
    const key = 'last_seen_auto_bascule'
    const since = localStorage.getItem(key)
    const now = new Date().toISOString()
    if (!since) {
      // Première visite sur ce navigateur : rien à rattraper, juste amorcer le repère.
      localStorage.setItem(key, now)
      return
    }
    // Alertes de sécurité (déception/honeypots) réservées à l'admin dans le reste
    // de l'app (cf. CLAUDE.md § Authentification, /api/security/* hors compteur
    // badge) — même restriction reprise ici côté affichage, demande explicite.
    const isAdmin = user?.role === 'admin'
    Promise.allSettled([
      autoBasculeSummary(since),
      newVulnsSinceCount(since),
      assetsLifecycleSince(since),
      isAdmin ? securityEventsCount() : Promise.resolve(null),
      incidentsPendingCount(),
    ]).then(([bascule, newVulns, lifecycle, security, nis2]) => {
      localStorage.setItem(key, now)
      const b  = bascule.status  === 'fulfilled' ? bascule.value.data  : null
      const nv = newVulns.status === 'fulfilled' ? newVulns.value.data : null
      const lc = lifecycle.status === 'fulfilled' ? lifecycle.value.data : null
      const sec = security?.status === 'fulfilled' ? security.value?.data : null
      const n2 = nis2.status === 'fulfilled' ? nis2.value.data : null
      const nis2Total = (n2?.overdue || 0) + (n2?.imminent || 0)
      const securityCount = sec?.unacknowledged || 0
      const hasAnything = (b?.total > 0) || (nv?.total > 0) || (lc?.added_count > 0)
        || (lc?.removed_count > 0) || securityCount > 0 || nis2Total > 0
      if (hasAnything) setCatchUp({ bascule: b, newVulns: nv, lifecycle: lc, securityCount, nis2Total })
    })
  }, [isAnonymous, user])

  // Progression du contrôle automatique de patch au démarrage (lecture seule).
  // CRITICAL : signalement seul (badge, validation manuelle requise).
  // HIGH/MEDIUM/LOW : la vuln a déjà été basculée en `patched` côté backend
  // (cf. CLAUDE.md) — on répercute juste ce déplacement dans l'UI.
  useEffect(() => {
    let cancelled = false
    async function poll() {
      try {
        const { data } = await patchCheckStatus()
        if (cancelled) return
        // `data.running` (pas `data.pending > 0`, cf. STATUS.md — bug corrigé) :
        // `pending` n'est qu'un décompte du backlog de vulns à revérifier, quasi
        // toujours > 0 sur un vrai parc — l'utiliser comme signal d'activité
        // affichait "Analyse en cours" en permanence, y compris hors cycle,
        // à chaque rechargement de page.
        const active = data.running === true
        if (active && runTotalRef.current === 0) {
          // Nouveau cycle détecté : +1 pour la machine déjà en cours d'analyse
          runTotalRef.current = data.pending + (data.current ? 1 : 0)
          // Nouveau cycle = nouvelle série de notifications "actif terminé" possible.
          notifiedDoneAssetsRef.current = new Set()
          autoBasculeCountRef.current = {}
        } else if (!active) {
          runTotalRef.current = 0
        }
        // Le poll (3s) manque souvent le court instant où `current` est renseigné —
        // chaque contrôle individuel est en général plus rapide que l'intervalle de
        // poll. On garde le dernier actif/CVE connu tant que le cycle continue,
        // plutôt que de retomber sur un texte générique à chaque creux.
        setAutoCheck(prev => ({
          current: data.current ?? (active ? prev.current : null),
          pending: data.pending,
          total: runTotalRef.current,
          assets: data.assets || [],
          startedAt: data.started_at || null,
        }))
        setLastCycleInfo({ status: data.last_cycle_status || null, at: data.last_cycle_at || null })
        const done = data.last_completed
        // Dédupe par vuln_id + horodatage : le seul vuln_id ne suffit pas si la même
        // vuln est vérifiée deux fois (réouverte puis re-checkée) — sans l'horodatage,
        // la 2e complétion serait ignorée car déjà "vue".
        const doneKey = done ? `${done.vuln_id}-${done.checked_at}` : null
        if (doneKey && doneKey !== lastCompletedRef.current) {
          lastCompletedRef.current = doneKey
          if (done.auto_patched) {
            moveVulnToPatched(done.vuln_id, 'Auto (patch check)', done.not_applicable ? 'false_positive' : 'patched')
            pushToast(
              done.not_applicable
                ? `${done.cve_id} qualifié faux positif (produit non installé sur ${done.asset_name})`
                : `${done.cve_id} corrigé automatiquement (patch détecté sur ${done.asset_name})`,
              done.not_applicable ? 'violet' : 'success',
            )
            // Compté par actif pour le toast "actif terminé" ci-dessous — remis à
            // zéro dès que ce toast est poussé (cf. plus bas).
            const bKey = done.hostname || done.asset_name
            autoBasculeCountRef.current[bKey] = (autoBasculeCountRef.current[bKey] || 0) + 1
          } else if (done.patch_detected) {
            setPatchDetected(prev => ({ ...prev, [done.vuln_id]: true }))
          }
        }

        // Notification par actif terminé (08/08/2026) : détecte les actifs qui
        // viennent de passer à checked >= total depuis le poll précédent — même
        // logique de dédoublonnage que la notification CVE ci-dessus (clé déjà vue),
        // sans garde "premier poll" (cf. commentaire sur notifiedDoneAssetsRef).
        for (const a of (data.assets || [])) {
          const isAssetDone = a.total > 0 && a.checked >= a.total
          if (!isAssetDone || notifiedDoneAssetsRef.current.has(a.asset_id)) continue
          notifiedDoneAssetsRef.current.add(a.asset_id)

          const bKey = a.hostname || a.asset_name
          const bascules = autoBasculeCountRef.current[bKey] || 0
          delete autoBasculeCountRef.current[bKey]

          const openForAsset = openVulnsRef.current.filter(v => v.asset?.id === a.asset_id)
          const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
          for (const v of openForAsset) {
            const sev = v.cve?.severity
            if (sev in bySeverity) bySeverity[sev]++
          }
          const sevSummary = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            .map(s => `${bySeverity[s]} ${s}`)
            .join(', ')

          pushToast(
            `${a.asset_name || a.hostname} terminé — ${bascules} bascule${bascules !== 1 ? 's' : ''} automatique${bascules !== 1 ? 's' : ''} · `
            + `CVE restantes : ${sevSummary}`,
            'info',
          )
        }
      } catch { /* silencieux — simple indicateur de progression */ }
    }
    poll()
    const id = setInterval(poll, 3000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  // Filtre "Actifs" (un/plusieurs/tous, case vide = tous) — s'applique à tout :
  // KPI, graphiques, badges de comptage et contenu des 3 tableaux. Contrairement
  // aux filtres sévérité/recherche (locaux à chaque tableau), c'est un vrai
  // changement de périmètre, donc tout doit suivre — d'où la version côté
  // backend (GET /api/stats?asset_id=...) pour les KPI plutôt qu'un simple
  // recalcul client (qui donnerait des taux subtilement faux, cf. commentaire
  // sur statsParams ci-dessus).
  // Actifs "entièrement configurés" (07/08/2026, cf. services/stats.py côté
  // backend — même définition : au moins un scan SSH/WinRM réussi,
  // `package_count > 0`). Sans sélection explicite, c'est ce périmètre qui fait
  // foi pour matchesAssetFilter (déjà le cas côté serveur pour openVulns/
  // patchedVulns/awaitingVulns via `configured_only` dans loadLists, mais
  // fpCandidates ci-dessous n'est filtré que côté client) — pas en mode
  // Présentation, où les actifs fictifs (FAKE_ASSETS) n'existent jamais dans
  // cette liste réelle et seraient sinon exclus à tort.
  const configuredAssetIds = assetList.filter(a => a.asset_type !== 'network' && a.package_count > 0).map(a => a.id)
  const effectiveAssetIds = selectedAssetIds.length ? selectedAssetIds : (isAnonymous ? [] : configuredAssetIds)

  function matchesAssetFilter(v) {
    return !effectiveAssetIds.length || effectiveAssetIds.includes(v.asset?.id)
  }
  const assetScopedOpen     = openVulns.filter(matchesAssetFilter)
  const assetScopedAwaiting = awaitingVulns.filter(matchesAssetFilter)
  const assetScopedPatched  = patchedVulns.filter(matchesAssetFilter)

  // Comptes affichés dans les badges de chaque tableau. En mode réel : le total
  // serveur (`totals`), car les listes sont plafonnées à 200 lignes et leur
  // longueur ne reflète donc pas la réalité. En mode Présentation : la longueur
  // de la liste, seule à inclure les vulnérabilités fictives que le serveur ignore.
  const openCount     = isAnonymous ? assetScopedOpen.length     : totals.open
  const awaitingCount = isAnonymous ? assetScopedAwaiting.length : totals.awaiting
  // Total "corrigées" affiché : quand un filtre serveur est actif (recherche ou
  // sévérité cochée), c'est le total EXACT en base pour ce filtre ; sinon le total global.
  const patchedCount  = isAnonymous ? assetScopedPatched.length
    : (remotePatched !== null ? (remotePatchedTotal ?? remotePatched.length) : totals.patched)
  // Vrai quand le tableau ne montre qu'une partie du total (plafond `per_page`) —
  // sert à l'indiquer explicitement plutôt que de laisser croire à une liste complète.
  const openTruncated     = !isAnonymous && assetScopedOpen.length     < totals.open

  // Mode Présentation : KPI recalculés localement depuis les listes déjà
  // fusionnées réel+fictif (cf. computeDashboardStats), le backend n'ayant
  // aucune connaissance des données de démonstration.
  const displayKpis = isAnonymous
    ? computeDashboardStats(assetScopedOpen, assetScopedPatched, assetScopedAwaiting, selectedAssetIds.length || assetList.length)
    : kpis

  // Compteurs dynamiques dérivés de assetScopedOpen (mis à jour à chaque action)
  const openCritical = assetScopedOpen.filter(v => v.cve?.severity === 'CRITICAL').length
  const openHigh     = assetScopedOpen.filter(v => v.cve?.severity === 'HIGH').length
  const openMedLow   = assetScopedOpen.filter(v => v.cve?.severity === 'MEDIUM' || v.cve?.severity === 'LOW').length
  // Compteur du filtre "Correctif déjà appliqué ailleurs" — `resolved_elsewhere_count` vient
  // déjà de chaque ligne chargée (jamais tronqué, cf. commentaire sur le filtre lui-même).
  const resolvedElsewhereOpenCount = assetScopedOpen.filter(v => v.resolved_elsewhere_count > 0).length

  const sevChartData = [
    { name: 'CRITICAL', value: openCritical },
    { name: 'HIGH',     value: openHigh },
    { name: 'MEDIUM+LOW', value: openMedLow },
  ].filter(d => d.value > 0)

  const assetCounts = {}
  assetScopedOpen.forEach(v => {
    const name = v.asset?.name || 'Inconnu'
    assetCounts[name] = (assetCounts[name] || 0) + 1
  })
  const topAssets = Object.entries(assetCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }))

  const patchedToday = assetScopedPatched.filter(v => v.patched_at && new Date(v.patched_at).toLocaleDateString('fr-FR') === today)

  const patchRate = displayKpis?.patch_rate_percent ?? 0
  // Mêmes seuils/couleurs que "Taux de correction par sévérité" : 100/80/50
  const patchRateColor = patchRate >= 80 ? '#3fb950' : patchRate >= 50 ? '#d29922' : '#f85149'

  const awaitingRate = displayKpis?.awaiting_fix_rate_percent ?? 0

  function flash(msg) { setActionMsg(msg); setTimeout(() => setActionMsg(''), 4000) }

  // Consulter une CVE du bandeau de rattrapage — même justificatif que la cloche
  // de notifications (helper partagé openCveJustification, recherche serveur).
  const consultCatchUpCve = (it) => openCveJustification(it, setDetailModal, flash)

  // Déplace une vuln (déjà `patched` côté backend) vers "traitées", qu'elle
  // vienne de "à traiter" ou de "en attente de correctif" (cf. RECHECK_INTERVAL
  // côté patch_checker.py — le cycle autonome revérifie aussi les vulns en
  // attente et les bascule dès qu'un correctif est détecté). N'appelle jamais
  // l'API — utilisé quand le backend a déjà fait la bascule (check manuel ou
  // automatique sur du non-CRITICAL).
  // Ajuste les totaux serveur localement après une action, pour que les badges
  // réagissent immédiatement sans attendre le rafraîchissement périodique. Le
  // prochain loadLists() les réaligne de toute façon sur la vérité serveur.
  function bumpTotals(delta) {
    setTotals(t => ({
      open:     Math.max(0, t.open     + (delta.open     || 0)),
      patched:  Math.max(0, t.patched  + (delta.patched  || 0)),
      awaiting: Math.max(0, t.awaiting + (delta.awaiting || 0)),
    }))
  }

  // `status` : `patched` (correctif détecté) ou `false_positive` (produit absent).
  // Les deux atterrissent dans le tableau "traitées", qui regroupe les issues
  // terminales — seuls le badge et l'horodatage diffèrent.
  function moveVulnToPatched(vulnId, validator, status = 'patched', note) {
    // Fondu bref avant la bascule réelle (180ms, cf. animate-row-leave dans
    // tailwind.config.js) — la ligne reste visible et se referme au lieu de
    // disparaître d'un coup, surtout perceptible sur une validation groupée.
    setLeavingIds(prev => new Set(prev).add(vulnId))
    setTimeout(() => {
      const now = new Date().toISOString()
      // Lecture via les refs (toujours à jour), pas via la closure d'état : appelée
      // depuis l'effet de polling (deps []), qui capte pour toujours l'état du
      // montage initial — sans les refs, les listes y resteraient figées à [].
      const fromOpen = openVulnsRef.current.find(v => v.id === vulnId)
      const vuln = fromOpen || awaitingVulnsRef.current.find(v => v.id === vulnId)
      setLeavingIds(prev => { const n = new Set(prev); n.delete(vulnId); return n })
      if (!vuln) return
      bumpTotals(fromOpen ? { open: -1, patched: +1 } : { awaiting: -1, patched: +1 })

      setOpenVulns(prev => prev.filter(v => v.id !== vulnId))
      setAwaitingVulns(prev => prev.filter(v => v.id !== vulnId))
      const isFp = status === 'false_positive'
      setPatchedVulns(prev => (
        prev.some(v => v.id === vulnId)
          ? prev
          : [{
              ...vuln,
              status,
              patched_at: isFp ? null : now,
              false_positive_at: isFp ? now : null,
              awaiting_fix_at: null,
              validated_by: validator,
              ...(note ? { notes: note } : {}),
            }, ...prev]
      ))
      setPatchDetected(prev => { const n = { ...prev }; delete n[vulnId]; return n })
      setSelectedIds(prev => { const n = new Set(prev); n.delete(vulnId); return n })
      refreshStats()
    }, 180)
  }

  // Bascule en masse une sélection vers "traitées" — même geste que le
  // "✓ Corrigé" unitaire (AnnotationModal), répété sur la sélection au lieu
  // d'être cliqué une par une. Pas de restriction de sévérité : l'analyste
  // choisit un seul validateur pour toute la sélection, ce qui reste une
  // action manuelle explicite (cf. CLAUDE.md — CRITICAL toujours validé par
  // un humain, satisfait ici par la sélection + le clic de confirmation).
  async function handleBulkMarkPatched(ids, validator, note) {
    const idArr = [...ids]
    if (!isAnonymous) await bulkPatch(idArr, validator, note)
    idArr.forEach(id => moveVulnToPatched(id, validator, 'patched', note))
    flash(`${idArr.length} vulnérabilité${idArr.length > 1 ? 's' : ''} corrigée${idArr.length > 1 ? 's' : ''} — validé par ${validator}`)
    setBulkPatchedModalOpen(false)
    // Après l'animation de sortie (180ms), réaligne listes et totaux sur le serveur.
    if (!isAnonymous) setTimeout(() => loadLists({ silent: true }), 400)
  }

  // Mode Présentation : le valideur choisi (AnnotationModal) est toujours
  // fictif dès que isAnonymous est actif — jamais écrit dans la vraie base,
  // même pour une vulnérabilité réelle affichée sous nom anonymisé.
  // `note` reste optionnelle ici, contrairement à AnnotationModal en attente/
  // faux positif — corriger une vuln non-CRITICAL est une action rapide.
  async function handleShowOtherInstances(vuln) {
    setOtherInstancesModal({ vuln, cveId: vuln.cve.cve_id, entries: [], loading: true })
    if (isAnonymous) {
      setOtherInstancesModal({ vuln, cveId: vuln.cve.cve_id, entries: [], loading: false })
      return
    }
    try {
      const r = await getVulnOtherInstances(vuln.id)
      setOtherInstancesModal({ vuln, cveId: vuln.cve.cve_id, entries: r.data || [], loading: false })
    } catch {
      setOtherInstancesModal({ vuln, cveId: vuln.cve.cve_id, entries: [], loading: false })
    }
  }

  // Reprend une justification vue sur un autre actif — pré-remplit l'AnnotationModal
  // "Marquer comme corrigé" (même geste que "✓ Corrigé" depuis la ligne), jamais
  // d'action tant que l'analyste ne confirme pas explicitement.
  function handleReuseJustification(vuln, note) {
    setPatchedModal(vuln)
    setPatchedModalPrefill(note)
    setOtherInstancesModal(null)
  }

  // Badge "déjà résolu ailleurs" — même logique que Vulnerabilities.jsx (compteur
  // déjà calculé côté serveur pour toute la page, détail chargé au clic seulement).
  // Même famille visuelle que "Correctif détecté ?"/"Faux positif ?" ci-dessous
  // (pastille en pointillés, à côté de l'identifiant CVE) — libellé "correctif
  // déjà appliqué" privilégié quand au moins une autre instance est réellement
  // `patched` (cas dominant en pratique), repli générique "déjà qualifié" sinon.
  function renderOtherInstancesBadge(v) {
    if (!v.resolved_elsewhere_count) return null
    const n = v.patched_elsewhere_count > 0 ? v.patched_elsewhere_count : v.resolved_elsewhere_count
    const plural = n > 1 ? 's' : ''
    const isPatched = v.patched_elsewhere_count > 0
    const label = isPatched
      ? `Correctif déjà appliqué sur ${n} autre${plural} actif${plural}`
      : `Déjà qualifié sur ${n} autre${plural} actif${plural}`
    const color = isPatched ? '#3fb950' : '#a371f7'
    return (
      <button onClick={() => handleShowOtherInstances(v)}
        // Pas de whitespace-nowrap (12/08/2026, demande utilisateur) : ce badge, texte
        // dynamique assez long ("Correctif déjà appliqué sur N autres actifs"), refusait
        // sinon de passer à la ligne et débordait de la colonne CVE (largeur fixe depuis
        // le correctif table-layout) par-dessus la colonne Sévérité voisine.
        className="text-xs font-normal px-1.5 py-0.5 rounded text-left"
        style={{ background: 'transparent', color, border: `1px dashed ${color}7a` }}
        title="Voir le diagnostic/la justification posés sur le(s) autre(s) actif(s) concerné(s) par cette CVE"
      >{isPatched ? '✅' : '🔁'} {label}</button>
    )
  }

  async function handleMarkPatched(vuln, validator, note) {
    if (!isAnonymous) await updateVuln(vuln.id, { status: 'patched', validated_by: validator, ...(note ? { notes: note } : {}) })
    moveVulnToPatched(vuln.id, validator, 'patched', note)
    flash(`${vuln.cve?.cve_id} corrigé — validé par ${validator}`)
    setPatchedModal(null)
    setPatchedModalPrefill('')
  }

  // Déplace une vuln de "à traiter" vers "en attente d'un patch correctif".
  async function handleMarkAwaitingFix(vuln, note, validator) {
    if (!isAnonymous) await updateVuln(vuln.id, { status: 'awaiting_fix', notes: note, validated_by: validator })
    const now = new Date().toISOString()
    setOpenVulns(prev => prev.filter(v => v.id !== vuln.id))
    setAwaitingVulns(prev => [{ ...vuln, status: 'awaiting_fix', awaiting_fix_at: now, notes: note, validated_by: validator }, ...prev])
    setSelectedIds(prev => { const n = new Set(prev); n.delete(vuln.id); return n })
    setAwaitingModal(null)
    bumpTotals({ open: -1, awaiting: +1 })
    refreshStats()
    flash(`${vuln.cve?.cve_id} marqué en attente d'un patch correctif — validé par ${validator}`)
  }

  // Modifie l'annotation d'une vuln déjà "en attente de correctif", sans
  // toucher au statut ni à awaiting_fix_at — juste la note et l'analyste qui
  // la corrige (ex : préciser un nouvel élément trouvé sur le paquet).
  async function handleUpdateNote(vuln, note, validator) {
    if (!isAnonymous) await updateVuln(vuln.id, { notes: note, validated_by: validator })
    setAwaitingVulns(prev => prev.map(v => v.id === vuln.id ? { ...v, notes: note, validated_by: validator } : v))
    flash(`${vuln.cve?.cve_id} — annotation mise à jour`)
    setEditNoteModal(null)
  }

  // Déplace une vuln de "à traiter" vers "traitées", taguée "faux positif" —
  // état terminal comme "patched", mais sans passer par une vérification réelle.
  async function handleMarkFalsePositive(vuln, note, validator) {
    if (!isAnonymous) await updateVuln(vuln.id, { status: 'false_positive', notes: note, validated_by: validator })
    const now = new Date().toISOString()
    setOpenVulns(prev => prev.filter(v => v.id !== vuln.id))
    setPatchedVulns(prev => [{ ...vuln, status: 'false_positive', false_positive_at: now, notes: note, validated_by: validator }, ...prev])
    setSelectedIds(prev => { const n = new Set(prev); n.delete(vuln.id); return n })
    setFalsePositiveModal(null)
    bumpTotals({ open: -1, patched: +1 })
    refreshStats()
    flash(`${vuln.cve?.cve_id} marqué comme faux positif — validé par ${validator}`)
  }

  // Réouvre une vuln vers "à traiter", qu'elle vienne de "traitées" (patched ou
  // faux positif) ou de "en attente de correctif" — les boutons "↩ Réouvrir"
  // partagent ce handler.
  async function handleReopen(vuln) {
    if (!isFakeId(vuln.id)) await updateVuln(vuln.id, { status: 'open' })
    const wasAwaiting = vuln.status === 'awaiting_fix' || vuln.status === 'awaiting_fix_partial'
    setPatchedVulns(prev => prev.filter(v => v.id !== vuln.id))
    setAwaitingVulns(prev => prev.filter(v => v.id !== vuln.id))
    setOpenVulns(prev => [{ ...vuln, status: 'open', patched_at: null, awaiting_fix_at: null, false_positive_at: null }, ...prev])
    bumpTotals(wasAwaiting ? { awaiting: -1, open: +1 } : { patched: -1, open: +1 })
    refreshStats()
    flash(`${vuln.cve?.cve_id} réouvert`)
  }

  async function handlePatchCheck(vuln, force = false) {
    setPatchLoading(l => ({ ...l, [vuln.id]: true }))
    setPatchModal({ vuln, result: null })
    setShowDebugCommands(false)
    if (isFakeId(vuln.id)) {
      setTimeout(() => {
        const result = fakePatchCheckResult(vuln)
        setPatchModal({ vuln, result, autoPatched: false })
        if (result.patch_detected) setPatchDetected(prev => ({ ...prev, [vuln.id]: true }))
        setPatchLoading(l => ({ ...l, [vuln.id]: false }))
      }, 500)
      return
    }
    try {
      const r = await patchCheck(vuln.id, force)
      const result = r.data.check_result
      setPatchModal({ vuln, result, autoPatched: r.data.auto_patched })
      if (r.data.auto_patched) {
        moveVulnToPatched(vuln.id, 'Auto (patch check)', result.not_applicable ? 'false_positive' : 'patched')
      } else if (result.patch_detected) {
        setPatchDetected(prev => ({ ...prev, [vuln.id]: true }))
      }
    } catch (e) {
      const msg = e?.response?.data?.detail || 'Erreur lors du patch check'
      setPatchModal({ vuln, result: { patch_detected: null, error: msg, kb_checked: [] } })
    }
    finally { setPatchLoading(l => ({ ...l, [vuln.id]: false })) }
  }

  async function handleAnalyze(vuln) {
    if (isFakeId(vuln.id)) {
      setAnalysisModal({ analysis: fakeAnalysis(vuln), cve_id: vuln.cve?.cve_id, description: vuln.cve?.description })
      return
    }
    flash('Analyse IA en cours…')
    try {
      const result = await analyzeIA(vuln.cve?.cve_id, vuln.asset?.id)
      setActionMsg('')
      setAnalysisModal({ analysis: result.data.analysis, cve_id: vuln.cve?.cve_id, description: vuln.cve?.description })
    } catch { flash('Erreur lors de l\'analyse IA') }
  }

  function toggleSelect(id) {
    setSelectedIds(prev => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }

  function toggleSelectAll() {
    // filteredOpenVulns (pas openVulns) : sinon "tout sélectionner" porte sur
    // les 1ers éléments de la liste brute non filtrée, pas sur les lignes
    // réellement affichées — invisible avec peu de filtres actifs, mais très
    // visible avec un filtre restrictif (ex: "Patch détecté uniquement").
    const visibleIds = filteredOpenVulns.slice(0, openLimit).map(v => v.id)
    const allSelected = visibleIds.every(id => selectedIds.has(id))
    if (allSelected) {
      setSelectedIds(prev => {
        const n = new Set(prev)
        visibleIds.forEach(id => n.delete(id))
        return n
      })
    } else {
      setSelectedIds(prev => {
        const n = new Set(prev)
        visibleIds.forEach(id => n.add(id))
        return n
      })
    }
  }

  async function handleBatchPatchCheck(ids) {
    const idArr = [...ids]
    let detected = 0
    const initialStatus = {}
    idArr.forEach(id => { initialStatus[id] = 'pending' })
    setBatchRowStatus(initialStatus)
    setBatchStats({ current: 0, total: idArr.length, detected: 0 })

    for (let i = 0; i < idArr.length; i++) {
      const vuln = openVulns.find(v => v.id === idArr[i])
      if (!vuln) continue
      setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'checking' }))
      setBatchStats(prev => ({ ...prev, current: i + 1 }))
      setBatchProgress(`Patch check ${i + 1}/${idArr.length}…`)
      if (isFakeId(vuln.id)) {
        await new Promise(r => setTimeout(r, 250))
        const result = fakePatchCheckResult(vuln)
        if (result.patch_detected) {
          setPatchDetected(prev => ({ ...prev, [vuln.id]: true }))
          detected++
          setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'done' }))
          setBatchStats(prev => ({ ...prev, detected: prev.detected + 1 }))
        } else {
          setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'not_found' }))
        }
        continue
      }
      try {
        const r = await patchCheck(vuln.id)
        const result = r.data.check_result
        if (r.data.auto_patched) {
          detected++
          setBatchStats(prev => ({ ...prev, detected: prev.detected + 1 }))
          moveVulnToPatched(vuln.id, 'Auto (patch check)')
        } else if (result.patch_detected) {
          setPatchDetected(prev => ({ ...prev, [vuln.id]: true }))
          detected++
          setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'done' }))
          setBatchStats(prev => ({ ...prev, detected: prev.detected + 1 }))
        } else {
          setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'not_found' }))
        }
      } catch {
        setBatchRowStatus(prev => ({ ...prev, [idArr[i]]: 'error' }))
      }
    }
    setBatchProgress(null)
    flash(`Patch check terminé — ${detected} patch${detected !== 1 ? 's' : ''} détecté${detected !== 1 ? 's' : ''}`)
    setSelectedIds(new Set())
    // Resynchronise : un lot peut avoir basculé des lignes que les mises à jour
    // locales ci-dessus n'ont pas toutes reflétées (vuln hors des 200 chargées).
    if (!isAnonymous) loadLists({ silent: true })
    setTimeout(() => { setBatchRowStatus({}); setBatchStats({ current: 0, total: 0, detected: 0 }) }, 8000)
  }

  const STATUSES_OPEN = ['open', 'in_progress', 'accepted_risk']
  const STATUS_LABELS_DASH = { open: 'Ouvert', in_progress: 'En cours', accepted_risk: 'Risque accepté' }
  const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

  // Tri partagé par les trois sections (à traiter / en attente / traitées).
  function sortVulns(list, sort) {
    return [...list].sort((a, b) => {
      let va, vb
      if (sort.by === 'severity') {
        va = SEV_ORDER[a.cve?.severity] ?? 0
        vb = SEV_ORDER[b.cve?.severity] ?? 0
      } else if (sort.by === 'score') {
        va = a.cve?.cvss_score ?? 0
        vb = b.cve?.cvss_score ?? 0
      } else {
        va = a.cve?.published ? new Date(a.cve.published).getTime() : 0
        vb = b.cve?.published ? new Date(b.cve.published).getTime() : 0
      }
      return sort.dir === 'desc' ? vb - va : va - vb
    })
  }
  // Bascule desc/asc au clic d'un en-tête (ou tri par une nouvelle colonne).
  const makeSortToggle = (setter) => (col) =>
    setter(s => s.by === col ? { by: col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : { by: col, dir: 'desc' })

  // Filtre sévérité multi-sélection, partagé par les trois tableaux (vide = tout).
  const sevMatch = (v) => dashFilter.severities.length === 0 || dashFilter.severities.includes(v.cve?.severity)
  // Criticité métier de l'actif (04/08/2026, demande explicite) — même donnée/mêmes
  // valeurs que la page Actifs (`asset.tags.criticite`, réglable là-bas), filtre
  // purement côté client comme la sévérité, partagé par les trois tableaux.
  const criticiteMatch = (v) => !dashFilter.criticite || (v.asset?.criticite || 'moyenne') === dashFilter.criticite

  // Bug réel corrigé (04/08/2026) : "Faux positifs proposés" filtrait
  // `assetScopedOpen`, qui ne charge que les 200 vulns "à traiter" les mieux
  // scorées (cf. loadLists) — les candidats faux positif (souvent d'anciennes
  // CVE, donc mal classées par score) n'y figurent quasi jamais. Constaté en
  // conditions réelles : 75 candidats, **zéro** présent dans les 200 chargées,
  // la case cochée vidait donc entièrement le tableau au lieu de les montrer.
  // `fpCandidates` est déjà la liste complète et indépendante (chargée sans
  // plafond de score) — on en fait la source à la place dès que la case est
  // cochée, sans jamais la recouper avec la liste tronquée.
  const openSource = dashFilter.onlyFalsePositive ? fpCandidates.filter(matchesAssetFilter) : assetScopedOpen
  const filteredOpenVulns = sortVulns(
    openSource.filter(v => {
      if (!sevMatch(v)) return false
      if (!criticiteMatch(v)) return false
      if (dashFilter.search && !v.cve?.cve_id?.toLowerCase().includes(dashFilter.search.trim().toLowerCase())) return false
      // v.patch_detected : dernier résultat de patch check persisté côté backend
      // (peut venir du cycle autonome, pas seulement d'un check lancé dans cette
      // session). patchDetected[v.id] : check lancé pendant cette session, pas
      // encore reflété par un refetch — les deux sources se complètent.
      if (dashFilter.onlyDetected && !(v.patch_detected || patchDetected[v.id])) return false
      // `resolved_elsewhere_count` vient déjà de chaque ligne de assetScopedOpen
      // (posé par le backend dans la même réponse que fetchVulns) — pas besoin
      // d'un changement de source comme pour "Faux positifs proposés" ci-dessus,
      // cette donnée n'est jamais tronquée par le plafond des 200 lignes.
      if (dashFilter.onlyResolvedElsewhere && !v.resolved_elsewhere_count) return false
      return true
    }),
    dashSort,
  )

  const filteredAwaitingVulns = sortVulns(
    assetScopedAwaiting.filter(v =>
      sevMatch(v) &&
      criticiteMatch(v) &&
      (!awaitingSearch.trim() || v.cve?.cve_id?.toLowerCase().includes(awaitingSearch.trim().toLowerCase()))
    ),
    awaitingSort,
  )
  // Recherche active hors des 200 chargées → on part des résultats serveur
  // (déjà limités aux statuts traités), sinon de la liste locale.
  const patchedSource = remotePatched !== null ? remotePatched.filter(matchesAssetFilter) : assetScopedPatched
  const filteredPatchedVulns = sortVulns(
    patchedSource.filter(v =>
      sevMatch(v) &&
      criticiteMatch(v) &&
      (!patchedStatusFilter || v.status === patchedStatusFilter) &&
      (!patchedSearch.trim() || v.cve?.cve_id?.toLowerCase().includes(patchedSearch.trim().toLowerCase()))
    ),
    patchedSort,
  )

  const handleAwaitingSort = makeSortToggle(setAwaitingSort)
  const handlePatchedSort  = makeSortToggle(setPatchedSort)

  function handleDashSort(col) {
    setDashSort(s => s.by === col ? { by: col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : { by: col, dir: 'desc' })
  }

  const selectStyle = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
    color: 'var(--text-secondary)', padding: '5px 10px', fontSize: 12, outline: 'none', cursor: 'pointer',
  }
  const hasDashFilter = dashFilter.severities.length > 0 || dashFilter.search || dashFilter.onlyDetected || dashFilter.onlyFalsePositive || dashFilter.onlyResolvedElsewhere || dashFilter.criticite || selectedAssetIds.length > 0

  if (loading) return <PageLoader />

  const visibleIds = filteredOpenVulns.slice(0, openLimit).map(v => v.id)
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every(id => selectedIds.has(id))

  return (
    <div className="p-6 space-y-6">
      <PageHero
        icon="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
        title="Dashboard" color={MODULES.cybervuln.color}
        subtitle="Vue d'ensemble de la posture de sécurité"
      >
        <div className="flex items-start gap-2">
          {/* Dashboard personnalisable (21/08/2026, demande explicite) — bascule le mode
              édition en direct sur la page (poignées de drag + boutons de taille par bloc,
              cf. Widget ci-dessus). Disposition persistée en localStorage
              (DashboardLayoutContext.jsx), dispositions prédéfinies dans Paramètres. */}
          <button onClick={() => setEditMode(m => !m)}
            title={editMode ? 'Terminer la personnalisation' : 'Personnaliser le dashboard'}
            className="p-2 rounded-lg transition-colors flex-shrink-0"
            style={editMode
              ? { background: '#58a6ff', color: '#fff' }
              : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
            {editMode ? (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            )}
          </button>
          {/* Réinitialiser la disposition (21/08/2026, retour utilisateur — "remettre les dispos
              de base" pendant les tests) : accès direct depuis la page plutôt que de repasser
              par Paramètres > Tableau de bord à chaque fois. N'efface rien de définitif —
              ré-applique juste le preset "Par défaut" (cf. constants/dashboardLayout.js). */}
          {editMode && (
            <button onClick={resetToDefault}
              title="Réinitialiser la disposition (ordre et tailles d'origine)"
              className="p-2 rounded-lg transition-colors flex-shrink-0"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          )}
          <MatchingCveButton onDone={() => { refreshStats() }} onToast={pushToast} />
          <PatchCheckRunButton selectedAssetIds={selectedAssetIds} onToast={pushToast} />
          <NotificationHistory />
        </div>
      </PageHero>

      {/* Rattrapage : tout ce qui s'est passé depuis la dernière visite sur ce
          navigateur (cycle de nuit compris) — cf. useEffect ci-dessus. Persistant
          (pas de setTimeout comme le flash) : peut contenir plusieurs rubriques,
          l'analyste doit pouvoir le lire à son rythme. Purement informatif — aucune
          rubrique n'appelle à une action, cf. leurs pages respectives pour agir. */}
      {catchUp && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-start gap-3" style={{ background: 'rgba(63,185,80,0.08)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' }}>
          <span className="text-base leading-none mt-0.5">👋</span>
          <div className="flex-1 space-y-2.5">
            <p className="font-medium">Depuis votre dernière visite</p>

            {catchUp.bascule?.total > 0 && (
              <div>
                <p style={{ color: 'var(--text-primary)' }}>
                  {catchUp.bascule.patched_count > 0 && <>{catchUp.bascule.patched_count} corrigée{catchUp.bascule.patched_count > 1 ? 's' : ''} automatiquement</>}
                  {catchUp.bascule.patched_count > 0 && catchUp.bascule.false_positive_count > 0 && ', '}
                  {catchUp.bascule.false_positive_count > 0 && <>{catchUp.bascule.false_positive_count} qualifiée{catchUp.bascule.false_positive_count > 1 ? 's' : ''} faux positif</>}
                  {' '}— sans action de votre part.
                </p>
                {catchUp.bascule.items?.length > 0 && (
                  <ul className="mt-1 space-y-0.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {catchUp.bascule.items.map((it, i) => (
                      <li key={i}>
                        {/* Consulter la CVE sans quitter le Dashboard : ouvre son
                            justificatif de clôture (chargé par recherche serveur, donc
                            trouvable même si la vuln est hors des listes plafonnées).
                            Désactivé en Présentation : les cve_id y sont fictifs. */}
                        {isAnonymous
                          ? <span className="font-mono">{it.cve_id}</span>
                          : <button onClick={() => consultCatchUpCve(it)}
                              className="font-mono hover:underline" style={{ color: '#58a6ff' }}
                              title="Consulter le justificatif de clôture de cette CVE">
                              {it.cve_id}
                            </button>}
                        {' '}sur {it.asset_name}
                        {' — '}{it.status === 'patched' ? 'corrigée' : 'faux positif'}
                      </li>
                    ))}
                    {catchUp.bascule.total > catchUp.bascule.items.length && (
                      <li style={{ color: 'var(--text-muted)' }}>… et {catchUp.bascule.total - catchUp.bascule.items.length} de plus (voir "Vulnérabilités traitées" ci-dessous)</li>
                    )}
                  </ul>
                )}
              </div>
            )}

            {/* Nouvelles vulnérabilités détectées sur le parc — inverse du rattrapage
                ci-dessus (des problèmes qui apparaissent, pas qui se résolvent seuls),
                même source que la sync NVD/le matching CPE qui tourne en fond. */}
            {catchUp.newVulns?.total > 0 && (
              <div>
                <p style={{ color: 'var(--text-primary)' }}>
                  {catchUp.newVulns.total} nouvelle{catchUp.newVulns.total > 1 ? 's' : ''} vulnérabilité{catchUp.newVulns.total > 1 ? 's' : ''} détectée{catchUp.newVulns.total > 1 ? 's' : ''} sur le parc.
                </p>
                {catchUp.newVulns.items?.length > 0 && (
                  <ul className="mt-1 space-y-0.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {catchUp.newVulns.items.map((it, i) => (
                      <li key={i}>
                        <span className="font-mono">{it.cve_id}</span>{' '}({it.severity}) sur {it.asset_name}
                      </li>
                    ))}
                    {catchUp.newVulns.total > catchUp.newVulns.items.length && (
                      <li style={{ color: 'var(--text-muted)' }}>… et {catchUp.newVulns.total - catchUp.newVulns.items.length} de plus (voir "Vulnérabilités ouvertes" ci-dessous)</li>
                    )}
                  </ul>
                )}
              </div>
            )}

            {/* Actifs ajoutés/supprimés — sync AD/SSH, import CSV, ou suppression
                manuelle depuis Actifs (cf. models.AssetDeletionLog pour la trace,
                l'actif lui-même n'existe plus une fois supprimé). */}
            {(catchUp.lifecycle?.added_count > 0 || catchUp.lifecycle?.removed_count > 0) && (
              <div>
                <p style={{ color: 'var(--text-primary)' }}>
                  {catchUp.lifecycle.added_count > 0 && <>{catchUp.lifecycle.added_count} actif{catchUp.lifecycle.added_count > 1 ? 's' : ''} ajouté{catchUp.lifecycle.added_count > 1 ? 's' : ''}</>}
                  {catchUp.lifecycle.added_count > 0 && catchUp.lifecycle.removed_count > 0 && ', '}
                  {catchUp.lifecycle.removed_count > 0 && <>{catchUp.lifecycle.removed_count} supprimé{catchUp.lifecycle.removed_count > 1 ? 's' : ''}</>}
                  {' '}dans l'inventaire.
                </p>
                {(catchUp.lifecycle.added?.length > 0 || catchUp.lifecycle.removed?.length > 0) && (
                  <ul className="mt-1 space-y-0.5 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {catchUp.lifecycle.added?.map((a, i) => <li key={`added-${i}`}>+ {a.name}</li>)}
                    {catchUp.lifecycle.removed?.map((a, i) => <li key={`removed-${i}`}>− {a.name}</li>)}
                  </ul>
                )}
              </div>
            )}

            {/* Alertes de sécurité (déception/honeypots) — réservé admin, même
                restriction que la page qui les détaille (cf. useEffect ci-dessus). */}
            {catchUp.securityCount > 0 && (
              <p style={{ color: 'var(--text-primary)' }}>
                <Link to="/settings/administration" className="hover:underline">
                  {catchUp.securityCount} alerte{catchUp.securityCount > 1 ? 's' : ''} de sécurité non acquittée{catchUp.securityCount > 1 ? 's' : ''}
                </Link>.
              </p>
            )}

            {catchUp.nis2Total > 0 && (
              <p style={{ color: 'var(--text-primary)' }}>
                <Link to="/incidents" className="hover:underline">
                  {catchUp.nis2Total} échéance{catchUp.nis2Total > 1 ? 's' : ''} NIS 2 à traiter
                </Link>.
              </p>
            )}
          </div>
          <button onClick={() => setCatchUp(null)} className="p-1 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }} title="Fermer">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
      )}

      {(actionMsg || batchProgress) && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' }}>
          <svg className="w-4 h-4 animate-spin flex-shrink-0" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
          {batchProgress || actionMsg}
        </div>
      )}

      {/* Dernier cycle connu en défaut (persisté en base, cf. main.py::
          _check_interrupted_patch_cycle et services/patch_checker.py) — seulement
          quand aucun cycle n'est visiblement en cours (sinon la barre ci-dessous
          suffit déjà). "interrupted" = redémarrage du backend (--reload en dev) qui
          a coupé le cycle en plein milieu ; "failed" = exception réelle pendant le
          cycle, process resté vivant (cf. logs backend pour le détail). */}
      {autoCheck.total === 0 && (lastCycleInfo.status === 'interrupted' || lastCycleInfo.status === 'failed') && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2"
          style={lastCycleInfo.status === 'failed'
            ? { background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }
            : { background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.25)' }}
        >
          <span>⚠</span>
          <span>
            {lastCycleInfo.status === 'failed'
              ? "Le dernier cycle de patch check a échoué (erreur pendant l'exécution)"
              : "Le dernier cycle de patch check a été interrompu par un redémarrage du backend avant d'avoir tout vérifié"}
            {lastCycleInfo.at ? ` (${new Date(lastCycleInfo.at).toLocaleString('fr-FR')})` : ''}
            {lastCycleInfo.status === 'failed'
              ? ' — voir les logs backend pour le détail, relancez manuellement une fois la cause corrigée.'
              : ' — un nouveau cycle reprend automatiquement là où il s\'est arrêté.'}
          </span>
        </div>
      )}

      {/* Évènements agent non acquittés (19/08/2026, cf. docs/AGENT_DETECTION.md) — bandeau
          persistant distinct du honeypot DB (jamais fusionnés, § Décisions figées de la doc),
          cyan (module Inventaire) plutôt que rouge pour rester visuellement dissocié. */}
      {agentEventsCount > 0 && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2"
          style={{ background: 'rgba(57,197,207,0.1)', color: '#39c5cf', border: '1px solid rgba(57,197,207,0.25)' }}>
          <span>🛡️</span>
          <Link to={agentEventsAssetId ? `/durcissement?asset=${agentEventsAssetId}` : '/durcissement'} className="hover:underline">
            {agentEventsCount} évènement{agentEventsCount > 1 ? 's' : ''} critique{agentEventsCount > 1 ? 's' : ''} détecté{agentEventsCount > 1 ? 's' : ''} par un agent (élévation de privilèges, altération d'audit…)
          </Link>
        </div>
      )}

      {autoCheck.total > 0 && (() => {
        const checked = Math.max(autoCheck.total - autoCheck.pending - 1, 0)
        const percent = Math.min(100, Math.round((checked / autoCheck.total) * 100))
        // Horodatage serveur (started_at) plutôt qu'un chrono local : un simple
        // rechargement de la page ne doit pas faire perdre le point de départ.
        const elapsedSec = autoCheck.startedAt ? (Date.now() - new Date(autoCheck.startedAt).getTime()) / 1000 : 0
        // Rythme calculé sur au moins 3 vérifications et 5s écoulées — sous ce seuil,
        // une estimation serait trop bruitée (un seul actif lent fausserait tout).
        const rate = checked >= 3 && elapsedSec >= 5 ? checked / elapsedSec : 0
        const etaSeconds = rate > 0 ? (autoCheck.total - checked) / rate : null
        const currentKey = autoCheck.current?.hostname || autoCheck.current?.asset_name
        // Croisé avec assetList (déjà chargé au montage de la page, cf. fetchAssets)
        // plutôt que d'ajouter OS/hardware côté backend au suivi du cycle — cette
        // donnée existe déjà en mémoire côté front, pas besoin d'un aller-retour de plus.
        const assetById = new Map(assetList.map(a => [a.id, a]))
        return (
          <div className="text-sm px-4 py-3 rounded-xl flex flex-col gap-2.5" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.25)' }}>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <svg className="w-4 h-4 animate-spin flex-shrink-0" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                {/* `current` peut être brièvement null entre deux actifs (poll capté
                    pile au changement de machine) alors que le cycle continue
                    (`pending` > 0) — texte générique plutôt que de masquer tout le
                    bloc, pour que la barre ne clignote plus (demande utilisateur). */}
                {autoCheck.current ? (
                  <span className="truncate">
                    Analyse en cours ({/windows/i.test(autoCheck.current.os) ? 'WinRM' : 'SSH'}) — <span className="font-semibold">{autoCheck.current.asset_name}</span>
                    {autoCheck.current.hostname ? ` (${autoCheck.current.hostname})` : ''} · {autoCheck.current.cve_id}
                  </span>
                ) : (
                  <span>Analyse en cours…</span>
                )}
              </div>
              <span className="text-xs font-semibold flex-shrink-0 px-2 py-0.5 rounded-full" style={{ background: 'rgba(88,166,255,0.22)' }}>
                {percent}%
              </span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(0,0,0,0.2)' }}>
              <div
                className="h-full rounded-full transition-all duration-500 progress-bar-shimmer"
                style={{ width: `${percent}%`, background: 'linear-gradient(90deg, var(--accent-blue), #58a6ff)' }}
              />
            </div>
            <div className="flex items-center justify-between text-xs opacity-75">
              <span>{checked}/{autoCheck.total} vérifiées</span>
              {etaSeconds !== null && <span>{formatEta(etaSeconds)} restant{etaSeconds >= 60 ? 'es' : 'e'}</span>}
            </div>

            {autoCheck.assets.length > 0 && (
              <div className="flex flex-col gap-1.5 pt-2.5 mt-0.5 max-h-48 overflow-y-auto pr-0.5" style={{ borderTop: '1px solid rgba(88,166,255,0.2)' }}>
                {autoCheck.assets.map(a => {
                  const isDone = a.total > 0 && a.checked >= a.total
                  const isCurrent = !isDone && (a.hostname === currentKey || a.asset_name === currentKey)
                  const assetPercent = a.total > 0 ? Math.min(100, Math.round((a.checked / a.total) * 100)) : 0
                  const asset = assetById.get(a.asset_id)
                  const osLabel = asset ? [asset.os, asset.os_version].filter(Boolean).join(' ') : null
                  const freeSpace = asset ? formatFreeSpace(asset.hardware) : null
                  return (
                    <div key={a.asset_id}
                      title={`${a.checked}/${a.total} vérifiées`}
                      className="flex flex-col gap-1 px-2.5 py-1.5 rounded-lg text-xs transition-colors"
                      style={{
                        background: isCurrent ? 'rgba(88,166,255,0.16)' : isDone ? 'rgba(63,185,80,0.07)' : 'rgba(0,0,0,0.14)',
                        border: `1px solid ${isCurrent ? 'rgba(88,166,255,0.45)' : 'transparent'}`,
                        opacity: isDone || isCurrent ? 1 : 0.5,
                      }}
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                          style={{ background: isDone ? '#3fb950' : isCurrent ? '#58a6ff' : 'rgba(255,255,255,0.15)', color: '#fff' }}
                        >
                          {isDone ? (
                            <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                          ) : isCurrent ? (
                            <svg className="w-2.5 h-2.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                          ) : null}
                        </span>
                        <span className="truncate flex-1" style={{ fontWeight: isCurrent ? 600 : 400, color: isDone ? '#3fb950' : 'inherit' }}>{a.asset_name || a.hostname || a.asset_id}</span>
                        <div className="w-20 h-1.5 rounded-full overflow-hidden flex-shrink-0" style={{ background: 'rgba(0,0,0,0.25)' }}>
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${isCurrent ? 'progress-bar-shimmer' : ''}`}
                            style={{ width: `${assetPercent}%`, background: isDone ? '#3fb950' : 'linear-gradient(90deg, var(--accent-blue), #58a6ff)' }}
                          />
                        </div>
                        <span className="flex-shrink-0 font-semibold" style={{ minWidth: 32, textAlign: 'right' }}>{assetPercent}%</span>
                      </div>
                      {(osLabel || freeSpace) && (
                        <div className="truncate pl-[26px] opacity-70" style={{ fontSize: 11 }}>
                          {[osLabel, freeSpace].filter(Boolean).join(' · ')}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })()}

      {/* Grille unique réordonnable/redimensionnable — KPI, Filtres et blocs de contenu
          (21/08/2026, demande explicite : pouvoir déplacer une tuile de part et d'autre de la
          barre de Filtres, impossible avec des grilles séparées). 24 colonnes — 1/8=3, 1/4=6,
          1/3=8, 1/2=12, plein=24 (cf. Widget plus haut, registre dans constants/dashboardLayout.js).
          "Filtres" fait partie de la grille mais reste verrouillé (LOCKED_WIDGETS) : les autres
          tuiles peuvent être déposées avant/après lui, lui ne bouge/redimensionne jamais. */}
      {/* `gridAutoFlow: 'dense'` (21/08/2026, retour utilisateur — tuiles "qui bloquent"/se
          superposent mal) : sans lui, une tuile pleine largeur placée entre deux tuiles plus
          étroites laisse un trou dans la ligne (l'algorithme de placement par défaut n'avance
          jamais en arrière) au lieu de laisser les tuiles suivantes reboucher l'espace libre. */}
      <div className="grid gap-4 tile-3d-grid" style={{ gridTemplateColumns: 'repeat(24, 1fr)', gridAutoFlow: 'dense' }}>
        <Widget id="kpiExposedAssets">
          <KpiCard label="Actifs exposés"
            value={displayKpis?.exposed_assets}
            color="#fb8f44"
            tiltEnabled={tiltEnabled}
            // `assets_to_configure` (07/08/2026) : le dashboard ne compte par défaut
            // que les actifs "entièrement configurés" (au moins un scan SSH/WinRM
            // réussi, cf. services/stats.py) — sans ce rappel, "sur 3 actifs" serait
            // pris pour tout le parc plutôt que pour la fraction déjà vérifiée.
            // Absent (undefined) dès qu'un filtre "Actifs" explicite est actif
            // (le concept ne s'applique qu'au périmètre par défaut).
            sub={displayKpis ? [
              `sur ${displayKpis.total_assets} actifs`,
              displayKpis.assets_to_configure > 0 ? `(${displayKpis.assets_to_configure} à configurer)` : null,
            ].filter(Boolean).join(' ') : undefined} />
        </Widget>
        <Widget id="kpiOpenVulns">
          <KpiCard label="Vulns ouvertes"
            value={openCount}
            color="var(--text-primary)"
            tiltEnabled={tiltEnabled} />
        </Widget>
        <Widget id="kpiAwaitingFix">
          <KpiCard label="En attente d'un patch"
            value={`${awaitingRate}%`}
            color="#d29922"
            tiltEnabled={tiltEnabled}
            sub={`${assetScopedAwaiting.length} vuln${assetScopedAwaiting.length !== 1 ? 's' : ''} bloquée${assetScopedAwaiting.length !== 1 ? 's' : ''}`} />
        </Widget>
        <Widget id="kpiPatchRate">
          <KpiCard label="Taux de correction global"
            value={`${patchRate}%`}
            color={patchRateColor}
            tiltEnabled={tiltEnabled}
            sub={patchRate === 100 ? 'Excellent' : patchRate >= 80 ? 'Bon' : patchRate >= 50 ? 'À améliorer' : 'Critique'} />
        </Widget>

        {/* Filtres — verrouillé (LOCKED_WIDGETS) : reste en une seule ligne pleine largeur,
            mais peut désormais se retrouver n'importe où dans l'ordre choisi par l'utilisateur
            (21/08/2026, demande explicite) plutôt que figé juste après les KPI. */}
        <Widget id="filtres">
        <div style={{ ...CARD, padding: '12px 20px', display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Filtres</span>
        {/* `selected={selectedAssetIds}` — PAS `effectiveAssetIds` (bug réel corrigé
            11/08/2026, signalé par l'utilisateur : "le bouton tout décoché ne
            fonctionne pas... je dois désélectionner les autres à la main"). Le choix
            initial (07/08/2026) affichait `effectiveAssetIds` — les actifs "configurés"
            déjà pré-cochés par défaut — pour rendre visible le périmètre implicite
            quand il n'y avait que 3 actifs configurés au total. Le parc est passé à
            plusieurs centaines depuis : ça précochait pratiquement toute la liste par
            défaut, rendant "sélectionner un seul actif" impossible sans tout décocher
            à la main, et rendait "Tout décocher" invisible (`onChange([])` vide bien
            `selectedAssetIds`, mais `effectiveAssetIds` — affiché — retombe aussitôt
            sur la liste complète des actifs configurés puisque `selectedAssetIds` est
            vide). Le libellé du bouton ("Tous les actifs" quand rien n'est explicitement
            coché, cf. AssetDropdown.jsx) reste suffisant pour signaler le périmètre par
            défaut — la liste de cases à cocher, elle, doit refléter uniquement ce que
            l'utilisateur a lui-même choisi. */}
        <AssetDropdown assetList={assetList} selected={selectedAssetIds} onChange={setSelectedAssetIds} />
        {/* Sévérités : menu déroulant multi-sélection (aucune cochée = toutes).
            Filtre les trois tableaux ; la section "traitées" est filtrée côté
            serveur (au-delà des 200 chargées) dès qu'une sévérité est cochée. */}
        <SeverityDropdown
          selected={dashFilter.severities}
          onChange={sevs => setDashFilter(f => ({ ...f, severities: sevs }))}
        />
        {/* Criticité métier de l'actif (04/08/2026, demande explicite) — même
            donnée/mêmes valeurs que le filtre équivalent sur la page Actifs,
            filtre purement client comme la sévérité, partagé par les trois
            tableaux (à traiter / en attente / traitées). */}
        <select
          value={dashFilter.criticite}
          onChange={e => setDashFilter(f => ({ ...f, criticite: e.target.value }))}
          className="text-xs px-2.5 py-1.5 rounded-lg"
          style={dashFilter.criticite ? ACTIVE_SELECT_STYLE : { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-secondary)', outline: 'none', cursor: 'pointer' }}
        >
          <option value="">Toutes criticités</option>
          {Object.entries(CRITICITE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <input
          value={dashFilter.search}
          onChange={e => setDashFilter(f => ({ ...f, search: e.target.value }))}
          placeholder="Rechercher un CVE (à traiter)…"
          className="text-xs px-2.5 py-1.5 rounded-lg"
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', width: 220 }}
        />
        <label className="flex items-center gap-1.5 cursor-pointer select-none ml-1"
          title="N'affiche que les vulnérabilités où un correctif a déjà été détecté (signal patch check), en attente de validation"
        >
          <input type="checkbox" checked={dashFilter.onlyDetected}
            onChange={e => setDashFilter(f => ({ ...f, onlyDetected: e.target.checked }))}
            className="w-3.5 h-3.5 accent-blue-500"
          />
          <span className="text-xs font-medium" style={{ color: dashFilter.onlyDetected ? '#3fb950' : 'var(--text-secondary)' }}>
            ✓ Patch détecté uniquement
          </span>
        </label>
        <label className="flex items-center gap-1.5 cursor-pointer select-none"
          title="N'affiche que les CVE ne concernant pas réellement l'actif (produit non installé, ou rattachement que les règles de matching actuelles ne créeraient plus)"
        >
          <input type="checkbox" checked={dashFilter.onlyFalsePositive}
            onChange={e => setDashFilter(f => ({ ...f, onlyFalsePositive: e.target.checked }))}
            className="w-3.5 h-3.5 accent-blue-500"
          />
          <span className="text-xs font-medium" style={{ color: dashFilter.onlyFalsePositive ? '#a371f7' : 'var(--text-secondary)' }}>
            🚫 Faux positifs proposés{fpCandidates.length ? ` (${fpCandidates.length})` : ''}
          </span>
        </label>
        <label className="flex items-center gap-1.5 cursor-pointer select-none"
          title="N'affiche que les CVE déjà corrigées, faux positif ou risque accepté sur au moins un autre actif — pour reprendre directement la justification déjà posée ailleurs"
        >
          <input type="checkbox" checked={dashFilter.onlyResolvedElsewhere}
            onChange={e => setDashFilter(f => ({ ...f, onlyResolvedElsewhere: e.target.checked }))}
            className="w-3.5 h-3.5 accent-blue-500"
          />
          <span className="text-xs font-medium" style={{ color: dashFilter.onlyResolvedElsewhere ? '#3fb950' : 'var(--text-secondary)' }}>
            ✅ Correctif déjà appliqué ailleurs{resolvedElsewhereOpenCount ? ` (${resolvedElsewhereOpenCount})` : ''}
          </span>
        </label>
        {hasDashFilter && (
          <button onClick={() => { setDashFilter({ severities: [], search: '', onlyDetected: false, onlyFalsePositive: false, onlyResolvedElsewhere: false, criticite: '' }); setSelectedAssetIds([]) }}
            className="text-xs px-2.5 py-1.5 rounded-lg"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
          >Réinitialiser</button>
        )}
        </div>
        </Widget>

        <Widget id="auditFindings"><AuditFindingsCard /></Widget>
        <Widget id="sslCertificates"><SslCertificatesCard /></Widget>
        <Widget id="patchRateBySeverity">
      <div style={CARD} className="p-5">
        <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>Taux de correction par sévérité</h2>
        <div className="flex flex-col gap-3">
          {[
            { key: 'critical', label: 'CRITICAL', color: '#f85149', bg: 'rgba(248,81,73,0.08)', border: 'rgba(248,81,73,0.2)' },
            { key: 'high',     label: 'HIGH',     color: '#fb8f44', bg: 'rgba(251,143,68,0.08)', border: 'rgba(251,143,68,0.2)' },
            { key: 'medium',   label: 'MEDIUM',   color: '#d29922', bg: 'rgba(210,153,34,0.08)', border: 'rgba(210,153,34,0.2)' },
            { key: 'low',      label: 'LOW',      color: '#58a6ff', bg: 'rgba(88,166,255,0.08)', border: 'rgba(88,166,255,0.2)' },
          ].map(({ key, label, color, bg, border }) => {
            const s = displayKpis?.severity_rates?.[key]
            const rate = s?.rate ?? 0
            const patched = s?.patched ?? 0
            const total = s?.total ?? 0
            const done = rate === 100
            const textColor = done ? '#3fb950' : color
            const rowBg = done ? 'rgba(63,185,80,0.08)' : bg
            const rowBorder = done ? 'rgba(63,185,80,0.25)' : border
            const barColor = done ? '#3fb950' : rate >= 80 ? '#3fb950' : rate >= 50 ? '#d29922' : color
            return (
              <div key={key} style={{ background: rowBg, border: `1px solid ${rowBorder}`, borderRadius: 8 }} className="px-4 py-3">
                <div className="flex items-center gap-4">
                  <span className="text-xs font-bold uppercase tracking-wider w-16 flex-shrink-0" style={{ color: textColor }}>
                    {done ? '✓ ' : ''}{label}
                  </span>
                  <div className="flex-1">
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(0,0,0,0.15)' }}>
                      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${rate}%`, background: barColor }} />
                    </div>
                  </div>
                  <span className="text-sm font-bold tabular-nums min-w-[3rem] text-right flex-shrink-0" style={{ color: barColor }}>{rate}%</span>
                  <span className="text-xs tabular-nums min-w-[5.5rem] text-right flex-shrink-0" style={{ color: done ? '#3fb950' : 'var(--text-muted)' }}>{patched}/{total}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
        </Widget>

        <Widget id="charts">
      {/* Graphiques — relief + tilt 3D comme les KPI ci-dessus (21/08/2026, demande explicite),
          `--tile` reprend CYBERVULN_CARD_TINT (pas de couleur individuelle ici, contrairement
          aux KpiCard). */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 tile-3d-grid">
        <div style={{ ...CARD, '--tile': CYBERVULN_CARD_TINT }} className="p-5 tile-3d"
          onMouseMove={tiltEnabled ? tiltMouseMove : undefined}
          onMouseEnter={tiltEnabled ? tiltMouseEnter : undefined}
          onMouseLeave={tiltEnabled ? tiltMouseLeave : undefined}>
          <span className="tile-3d-glare" aria-hidden="true" />
          <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>Répartition des vulnérabilités ouvertes</h2>
          {sevChartData.length === 0
            ? <p className="text-sm text-center py-16" style={{ color: 'var(--text-muted)' }}>Aucune donnée</p>
            : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={sevChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="45%"
                    innerRadius={52}
                    outerRadius={78}
                  >
                    {sevChartData.map(entry => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#8b949e'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    itemStyle={{ color: 'var(--text-primary)' }}
                    labelStyle={{ color: 'var(--text-muted)', display: 'none' }}
                  />
                  <Legend
                    wrapperStyle={{ fontSize: 12, paddingTop: 8 }}
                    formatter={value => <span style={{ color: 'var(--text-secondary)' }}>{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            )
          }
        </div>

        <div style={{ ...CARD, '--tile': CYBERVULN_CARD_TINT }} className="p-5 tile-3d"
          onMouseMove={tiltEnabled ? tiltMouseMove : undefined}
          onMouseEnter={tiltEnabled ? tiltMouseEnter : undefined}
          onMouseLeave={tiltEnabled ? tiltMouseLeave : undefined}>
          <span className="tile-3d-glare" aria-hidden="true" />
          <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>Actifs les plus exposés</h2>
          {topAssets.length === 0
            ? <p className="text-sm text-center py-16" style={{ color: 'var(--text-muted)' }}>Aucune donnée</p>
            : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topAssets} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} />
                  <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(88,166,255,0.05)' }} />
                  <Bar dataKey="count" fill="var(--accent-blue)" name="Vulns" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )
          }
        </div>
      </div>
        </Widget>

        <Widget id="openVulns">
      {/* Vulnérabilités à traiter */}
      <div style={CARD} className="overflow-hidden">
        <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Vulnérabilités à traiter</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Cliquez sur "✓ Corrigé" pour déplacer vers le tableau ci-dessous
              {/* Le plafond de 200 ne s'applique qu'à la liste "à traiter" par score —
                  "Faux positifs proposés" bascule sur la liste complète des candidats
                  (cf. openSource ci-dessus), jamais tronquée de la même façon. */}
              {!dashFilter.onlyFalsePositive && openTruncated && ` — ${assetScopedOpen.length} affichées sur ${openCount} (voir la page Vulnérabilités pour la liste complète)`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {selectedIds.size > 0 && (
              <button
                onClick={() => handleBatchPatchCheck(selectedIds)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors"
                style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.25)' }}
              >
                🔍 Patch check ({selectedIds.size})
              </button>
            )}
            {selectedIds.size > 0 && (
              <button
                onClick={() => setBulkPatchedModalOpen(true)}
                className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-[background-color,transform] duration-150 active:scale-[0.97]"
                style={{ background: 'rgba(63,185,80,0.2)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.5)' }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(63,185,80,0.3)'}
                onMouseLeave={e => e.currentTarget.style.background = 'rgba(63,185,80,0.2)'}
              >
                ✓ Corrigé ({selectedIds.size})
              </button>
            )}
            {/* Qualification groupée en faux positif — pendant du "✓ Corrigé (N)".
                Restreint aux lignes que le backend a identifiées comme sans objet :
                marquer faux positif reste un jugement, on ne l'ouvre pas à
                n'importe quelle sélection. Le décompte indique la part éligible. */}
            {selectedIds.size > 0 && [...selectedIds].some(id => fpCandidateIds.has(id)) && (
              <button
                onClick={() => setFpModalOpen(true)}
                title="Qualifier en faux positif les lignes sélectionnées qui ne concernent pas réellement l'actif — annotation et analyste requis"
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors active:scale-[0.97]"
                style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }}
              >
                🚫 Faux positif ({[...selectedIds].filter(id => fpCandidateIds.has(id)).length})
              </button>
            )}
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full" style={{ background: 'rgba(248,81,73,0.12)', color: '#f85149' }}>
              {openCount} ouverte{openCount !== 1 ? 's' : ''}
            </span>
            <select value={openLimit} onChange={e => setOpenLimit(Number(e.target.value))}
              className="text-xs rounded-lg px-2 py-1"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', outline: 'none' }}>
              <option value={10}>10 lignes</option>
              <option value={25}>25 lignes</option>
              <option value={50}>50 lignes</option>
              <option value={9999}>Tout voir</option>
            </select>
          </div>
        </div>
        <div className="overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
          {/* table-layout: fixed + largeur par colonne (12/08/2026, demande utilisateur —
              2e correctif de suite sur ce tableau) : en `table-layout: auto` (défaut), un
              `max-width` posé sur la seule cellule CVE n'est pas fiablement respecté par
              l'algorithme de calcul de largeur des colonnes — Sévérité/Score se sont
              retrouvées comprimées à une largeur quasi nulle et leur badge (`white-space:
              nowrap`) débordait par-dessus la colonne CVE au lieu d'être contenu dans la
              sienne. Une largeur fixe par colonne élimine la cause, pas seulement le
              symptôme — plus aucune colonne ne peut empiéter sur sa voisine quel que soit
              le contenu. Colonne Actions élargie + boutons en flex-wrap (5 boutons ne
              tenaient jamais sur une ligne, c'était le vrai plus gros poste de largeur). */}
          <table className="w-full text-sm" style={{ tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                <th className="px-4 py-3" style={{ width: 32 }}>
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={toggleSelectAll}
                    className="rounded"
                    style={{ accentColor: '#58a6ff', cursor: 'pointer' }}
                  />
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', width: 200 }}>CVE</th>
                {batchStats.total > 0 && (
                  <th className="px-4 py-3" style={{ width: 120 }}>
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                          {batchProgress ? `${batchStats.current}/${batchStats.total}` : `✓ ${batchStats.detected} détecté${batchStats.detected !== 1 ? 's' : ''}`}
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${batchStats.total > 0 ? Math.round((batchStats.current / batchStats.total) * 100) : 0}%`,
                            background: batchProgress ? '#58a6ff' : '#3fb950',
                          }}
                        />
                      </div>
                    </div>
                  </th>
                )}
                {[['severity', 'Sévérité', 90], ['score', 'Score', 60]].map(([col, label, width]) => {
                  const active = dashSort.by === col
                  return (
                    <th key={col} onClick={() => handleDashSort(col)}
                      className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
                      style={{ color: active ? '#58a6ff' : 'var(--text-muted)', width }}
                    >{label}{active ? (dashSort.dir === 'desc' ? ' ↓' : ' ↑') : ''}</th>
                  )
                })}
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', width: 60 }} title="Exploit Prediction Scoring System — probabilité d'exploitation active sous 30 jours">EPSS</th>
                {[['date', 'Publié', 90]].map(([col, label, width]) => {
                  const active = dashSort.by === col
                  return (
                    <th key={col} onClick={() => handleDashSort(col)}
                      className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
                      style={{ color: active ? '#58a6ff' : 'var(--text-muted)', width }}
                    >{label}{active ? (dashSort.dir === 'desc' ? ' ↓' : ' ↑') : ''}</th>
                  )
                })}
                {[['Actif', 110], ['Criticité', 90], ['Détecté', 90], ['Actions', 320]].map(([h, width]) => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', width }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredOpenVulns.length === 0 && (
                <tr><td colSpan={batchStats.total > 0 ? 9 : 8} className="px-4 py-10 text-center text-sm" style={{ color: '#3fb950' }}>✓ Aucune vulnérabilité ouverte</td></tr>
              )}
              {filteredOpenVulns.slice(0, openLimit).map(v => {
                const detected = patchDetected[v.id]
                // Candidat faux positif : CVE sans objet sur l'actif. Signalé
                // visuellement comme "Patched"/"En attente" le sont déjà, pour
                // que l'état se lise dans le tableau sans ouvrir de modale.
                // Le vert "patch détecté" reste prioritaire si les deux
                // coexistent : un correctif prouvé prime sur "sans objet".
                const isFpCandidate = !detected && fpCandidateIds.has(v.id)
                const rowTint = detected
                  ? { bg: 'rgba(63,185,80,0.07)', hover: 'rgba(63,185,80,0.12)', border: '#3fb950' }
                  : isFpCandidate
                  ? { bg: 'rgba(163,113,247,0.07)', hover: 'rgba(163,113,247,0.13)', border: '#a371f7' }
                  : { bg: 'rgba(248,81,73,0.05)', hover: 'rgba(248,81,73,0.1)', border: 'rgba(248,81,73,0.4)' }
                const isSelected = selectedIds.has(v.id)
                const isLeaving = leavingIds.has(v.id)
                return (
                  <tr key={v.id} className={`transition-colors ${isLeaving ? 'animate-row-leave pointer-events-none' : ''}`} style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    background: rowTint.bg,
                    borderLeft: `3px solid ${rowTint.border}`,
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = rowTint.hover}
                    onMouseLeave={e => e.currentTarget.style.background = rowTint.bg}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleSelect(v.id)}
                        style={{ accentColor: '#58a6ff', cursor: 'pointer' }}
                      />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>
                      {/* Colonne CVE larguer fixée à 200px sur le <th> (cf. commentaire plus
                          haut sur `tableLayout: fixed`) : le lien CVE est sur sa propre ligne,
                          les badges en dessous dans un flex-wrap qui se contient désormais
                          naturellement dans la largeur réelle de la cellule, sans plus jamais
                          déborder sur la colonne Sévérité voisine. */}
                      <a href={`https://nvd.nist.gov/vuln/detail/${v.cve?.cve_id}`} target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()} className="hover:underline block truncate">{v.cve?.cve_id}</a>
                      <div className="flex flex-wrap items-center gap-1.5 mt-1">
                        {/* "Correctif détecté ?" — contour pointillé, comme le badge faux
                            positif : c'est une **détection en attente de validation** sur une
                            ligne encore `open` (typiquement une CRITICAL, que la règle
                            CLAUDE.md interdit de basculer automatiquement), à ne pas confondre
                            avec le badge plein "Patched" de "traitées" qui signale une clôture
                            effective. Les deux étaient identiques, d'où la confusion légitime
                            de l'utilisateur : « je vois que celles-ci sont patched, c'est sûr ? » */}
                        {detected && (
                          <span className="text-xs font-normal px-1.5 py-0.5 rounded whitespace-nowrap"
                            style={{ background: 'transparent', color: '#3fb950', border: '1px dashed #3fb9507a' }}
                            title="Correctif détecté par le contrôle read-only — en attente de votre validation (les CRITICAL ne basculent jamais automatiquement)"
                          >Correctif détecté ?</span>
                        )}
                        {/* "Faux positif ?" avec point d'interrogation et contour pointillé :
                            c'est une **proposition** du système sur une ligne encore ouverte, pas
                            une qualification actée. Le badge plein du tableau "traitées" signifie,
                            lui, qu'un analyste (ou la bascule auto) a tranché. Sans cette
                            distinction, les deux étaient visuellement identiques et laissaient
                            croire à une décision déjà prise. */}
                        {isFpCandidate && (
                          <span className="text-xs font-normal px-1.5 py-0.5 rounded whitespace-nowrap"
                            style={{ background: 'transparent', color: '#a371f7', border: '1px dashed #a371f77a' }}
                            title={`Proposition du système, à confirmer — ${fpReasonById.get(v.id) || 'CVE ne concernant pas réellement cet actif'}`}
                          >Faux positif ?</span>
                        )}
                        {renderOtherInstancesBadge(v)}
                      </div>
                      {/* Justification visible en clair, pas seulement au survol (04/08/2026,
                          demande explicite) — sert à trier/décider d'un coup d'œil sur toute
                          la liste plutôt que de survoler chaque badge un par un. */}
                      {isFpCandidate && fpReasonById.get(v.id) && (
                        <p className="mt-0.5 text-xs font-normal">{fpReasonById.get(v.id)}</p>
                      )}
                    </td>
                    {batchStats.total > 0 && (
                      <td className="px-4 py-3 w-36">
                        {(() => {
                          const s = batchRowStatus[v.id]
                          if (!s) return null
                          if (s === 'pending') return (
                            <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-faint)' }}>
                              <span className="w-2 h-2 rounded-full inline-block" style={{ background: 'var(--border)' }} />
                              En attente
                            </span>
                          )
                          if (s === 'checking') return (
                            <span className="flex items-center gap-1.5 text-xs" style={{ color: '#58a6ff' }}>
                              <svg className="w-3.5 h-3.5 animate-spin flex-shrink-0" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                              </svg>
                              Vérif…
                            </span>
                          )
                          if (s === 'done') return (
                            <span className="flex items-center gap-1.5 text-xs font-semibold" style={{ color: '#3fb950' }}>
                              <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                              </svg>
                              Patch détecté
                            </span>
                          )
                          if (s === 'not_found') return (
                            <span className="flex items-center gap-1.5 text-xs" style={{ color: '#fb8f44' }}>
                              <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                              </svg>
                              Non trouvé
                            </span>
                          )
                          if (s === 'error') return (
                            <span className="flex items-center gap-1.5 text-xs" style={{ color: '#f85149' }}>
                              <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              Erreur
                            </span>
                          )
                          return null
                        })()}
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <div style={{ display: 'inline-grid', justifyItems: 'start', gap: 4, position: 'relative' }}>
                        <SeverityBadge value={v.cve?.severity} />
                        <ExploitBadge kev={v.cve?.kev} kevRansomware={v.cve?.kev_ransomware} msfModule={v.cve?.msf_module} msfRank={v.cve?.msf_best_rank} compact spread />
                      </div>
                    </td>
                    <td className="px-4 py-3 font-semibold" style={{ color: cvssColor(v.cve?.cvss_score) }}>{v.cve?.cvss_score ?? '—'}</td>
                    <td className="px-4 py-3 text-xs font-semibold" style={{ color: epssColor(v.cve?.epss_score) }}>{v.cve?.epss_score != null ? (v.cve.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{v.cve?.published ? new Date(v.cve.published).toLocaleDateString('fr-FR') : '—'}</td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <ConnectivityDot assetType={v.asset?.asset_type} reachable={v.asset?.scan_reachable} error={v.asset?.scan_error} />
                        {v.asset?.name}
                      </div>
                    </td>
                    <td className="px-4 py-3"><CriticiteBadge value={v.asset?.criticite} /></td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>{v.detected_at ? new Date(v.detected_at).toLocaleDateString('fr-FR') : '—'}</td>
                    <td className="px-4 py-3">
                      {/* flex-wrap : 5 boutons dans une colonne fixée à 320px (cf. tableLayout
                          fixed plus haut) ne tiennent jamais sur une seule ligne — passent sur
                          2 lignes plutôt que de forcer la colonne à s'élargir. */}
                      <div className="flex flex-wrap gap-1.5">
                        <button onClick={() => handleAnalyze(v)}
                          className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-colors"
                          style={{ background: 'var(--accent-blue)', color: '#fff' }}
                          onMouseEnter={e => e.currentTarget.style.background = '#388bfd'}
                          onMouseLeave={e => e.currentTarget.style.background = 'var(--accent-blue)'}
                        >Analyser</button>
                        <button onClick={() => { if (!patchLoading[v.id]) handlePatchCheck(v) }}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={patchLoading[v.id]
                            ? { background: 'var(--accent-blue)', color: '#fff', border: 'none' }
                            : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
                          }
                        >{patchLoading[v.id] ? '⏳ Vérif…' : '🔍 Patch check'}</button>
                        <button onClick={() => setAwaitingModal(v)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.25)' }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(210,153,34,0.2)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'rgba(210,153,34,0.1)'}
                        >⏳ En attente</button>
                        <button onClick={() => setFalsePositiveModal(v)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.25)' }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(163,113,247,0.2)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'rgba(163,113,247,0.1)'}
                        >🚫 Faux positif</button>
                        <button onClick={() => { setPatchedModal(v); setPatchedModalPrefill(v.patch_check_details || '') }}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={{ background: detected ? 'rgba(63,185,80,0.2)' : 'rgba(63,185,80,0.1)', color: '#3fb950', border: `1px solid ${detected ? 'rgba(63,185,80,0.5)' : 'rgba(63,185,80,0.25)'}` }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(63,185,80,0.3)'}
                          onMouseLeave={e => e.currentTarget.style.background = detected ? 'rgba(63,185,80,0.2)' : 'rgba(63,185,80,0.1)'}
                        >✓ Corrigé</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
        </Widget>

        <Widget id="awaitingFix">
      {/* Vulnérabilités en attente d'un patch correctif */}
      <div style={CARD} className="overflow-hidden">
        <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Vulnérabilités en attente d'un patch correctif</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Aucun correctif éditeur/distro disponible pour l'instant — revérifiées automatiquement</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              value={awaitingSearch}
              onChange={e => setAwaitingSearch(e.target.value)}
              placeholder="Rechercher un CVE…"
              className="text-xs px-2.5 py-1.5 rounded-lg"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', width: 180 }}
            />
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full" style={{ background: 'rgba(210,153,34,0.12)', color: '#d29922' }}>
              {awaitingCount} en attente
            </span>
            <select value={awaitingLimit} onChange={e => setAwaitingLimit(Number(e.target.value))}
              className="text-xs rounded-lg px-2 py-1"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', outline: 'none' }}>
              <option value={10}>10 lignes</option>
              <option value={25}>25 lignes</option>
              <option value={50}>50 lignes</option>
              <option value={9999}>Tout voir</option>
            </select>
          </div>
        </div>
        {filteredAwaitingVulns.length === 0 ? (
          <p className="px-5 py-10 text-sm text-center" style={{ color: 'var(--text-muted)' }}>
            {assetScopedAwaiting.length === 0 ? 'Aucune vulnérabilité en attente de correctif' : 'Aucun résultat pour cette recherche'}
          </p>
        ) : (
          <div className="overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>CVE</th>
                  {[['severity', 'Sévérité'], ['score', 'Score']].map(([col, label]) => {
                    const active = awaitingSort.by === col
                    return (
                      <th key={col} onClick={() => handleAwaitingSort(col)}
                        className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
                        style={{ color: active ? '#58a6ff' : 'var(--text-muted)' }}
                      >{label}{active ? (awaitingSort.dir === 'desc' ? ' ↓' : ' ↑') : ''}</th>
                    )
                  })}
                  <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }} title="Exploit Prediction Scoring System — probabilité d'exploitation active sous 30 jours">EPSS</th>
                  {['Actif', 'Criticité', 'En attente depuis', 'Validé par / Annotation', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAwaitingVulns.slice(0, awaitingLimit).map(v => (
                  <tr key={v.id} className={`transition-colors ${leavingIds.has(v.id) ? 'animate-row-leave pointer-events-none' : ''}`} style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    background: 'rgba(210,153,34,0.05)',
                    borderLeft: '3px solid rgba(210,153,34,0.4)',
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(210,153,34,0.1)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'rgba(210,153,34,0.05)'}
                  >
                    <td className="px-4 py-3 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>
                      <a href={`https://nvd.nist.gov/vuln/detail/${v.cve?.cve_id}`} target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()} className="hover:underline">{v.cve?.cve_id}</a>
                      <span className="ml-2 text-xs font-normal px-1.5 py-0.5 rounded" style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922' }}>En attente</span>
                      {v.status === 'awaiting_fix_partial' && (
                        <span className="ml-1 text-xs font-normal px-1.5 py-0.5 rounded" style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922', border: '1px dashed rgba(210,153,34,0.5)' }}
                          title="Un des paquets visés par cette CVE est absent sur l'actif — seul l'autre est réellement en attente d'un correctif Debian">partiel</span>
                      )}
                      {renderOtherInstancesBadge(v)}
                    </td>
                    <td className="px-4 py-3">
                      <div style={{ display: 'inline-grid', justifyItems: 'start', gap: 4, position: 'relative' }}>
                        <SeverityBadge value={v.cve?.severity} />
                        <ExploitBadge kev={v.cve?.kev} kevRansomware={v.cve?.kev_ransomware} msfModule={v.cve?.msf_module} msfRank={v.cve?.msf_best_rank} compact spread />
                      </div>
                    </td>
                    <td className="px-4 py-3 font-semibold" style={{ color: cvssColor(v.cve?.cvss_score) }}>{v.cve?.cvss_score ?? '—'}</td>
                    <td className="px-4 py-3 text-xs font-semibold" style={{ color: epssColor(v.cve?.epss_score) }}>{v.cve?.epss_score != null ? (v.cve.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                    <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <ConnectivityDot assetType={v.asset?.asset_type} reachable={v.asset?.scan_reachable} error={v.asset?.scan_error} />
                        {v.asset?.name}
                      </div>
                    </td>
                    <td className="px-4 py-3"><CriticiteBadge value={v.asset?.criticite} /></td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {v.awaiting_fix_at ? new Date(v.awaiting_fix_at).toLocaleDateString('fr-FR') : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs max-w-xs" style={{ color: 'var(--text-secondary)' }}>
                      <div className="flex flex-col gap-1 items-start">
                        {v.validated_by
                          ? <span className="px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{v.validated_by}</span>
                          : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                        {v.notes && (
                          <div onClick={() => setDetailModal({ vuln: v, label: v.status === 'awaiting_fix_partial' ? "En attente d'un patch correctif (partiel)" : "En attente d'un patch correctif", color: '#d29922', date: v.awaiting_fix_at })}
                            className="max-w-xs cursor-pointer transition-opacity hover:opacity-70"
                            title="Cliquer pour voir le détail"
                          >
                            <MarkdownNote text={v.notes} className="text-xs line-clamp-2" />
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5">
                        <button onClick={() => { if (!patchLoading[v.id]) handlePatchCheck(v) }}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                          style={patchLoading[v.id]
                            ? { background: 'var(--accent-blue)', color: '#fff', border: 'none' }
                            : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
                          }
                        >{patchLoading[v.id] ? '⏳ Vérif…' : '🔍 Patch check'}</button>
                        <button onClick={() => setEditNoteModal(v)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
                          onMouseEnter={e => { e.currentTarget.style.background = 'var(--border)'; e.currentTarget.style.color = '#d29922' }}
                          onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                        >✏️ Modifier</button>
                        <button onClick={() => handleReopen(v)}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
                          onMouseEnter={e => { e.currentTarget.style.background = 'var(--border)'; e.currentTarget.style.color = '#fb8f44' }}
                          onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                        >↩ Réouvrir</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
        </Widget>

        <Widget id="patchedVulns">
      {/* Vulnérabilités traitées */}
      <div style={CARD} className="overflow-hidden">
        <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Vulnérabilités traitées</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {patchedToday.length > 0 ? `${patchedToday.length} correction${patchedToday.length > 1 ? 's' : ''} aujourd'hui (${today})` : 'Aucune correction aujourd\'hui'}
              {!isAnonymous && patchedCount > filteredPatchedVulns.length && ` — ${filteredPatchedVulns.length} affichées sur ${patchedCount} (voir la page Vulnérabilités pour la liste complète)`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <select value={patchedStatusFilter} onChange={e => setPatchedStatusFilter(e.target.value)}
              className="text-xs rounded-lg px-2 py-1"
              style={patchedStatusFilter ? ACTIVE_SELECT_STYLE : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', outline: 'none' }}>
              <option value="">Tous statuts</option>
              <option value="patched">Corrigées uniquement</option>
              <option value="false_positive">Faux positifs uniquement</option>
            </select>
            <input
              value={patchedSearch}
              onChange={e => setPatchedSearch(e.target.value)}
              placeholder="Rechercher un CVE…"
              className="text-xs px-2.5 py-1.5 rounded-lg"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', width: 180 }}
            />
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full" style={{ background: 'rgba(63,185,80,0.12)', color: '#3fb950' }}>
              {patchedCount} corrigée{patchedCount !== 1 ? 's' : ''}
            </span>
            <select value={patchedLimit} onChange={e => setPatchedLimit(Number(e.target.value))}
              className="text-xs rounded-lg px-2 py-1"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', outline: 'none' }}>
              <option value={10}>10 lignes</option>
              <option value={25}>25 lignes</option>
              <option value={50}>50 lignes</option>
              <option value={9999}>Tout voir</option>
            </select>
          </div>
        </div>
        {filteredPatchedVulns.length === 0 ? (
          <p className="px-5 py-10 text-sm text-center" style={{ color: 'var(--text-muted)' }}>
            {assetScopedPatched.length === 0 ? 'Aucune vulnérabilité corrigée' : 'Aucun résultat pour cette recherche'}
          </p>
        ) : (
          <div className="overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>CVE</th>
                  {[['severity', 'Sévérité'], ['score', 'Score']].map(([col, label]) => {
                    const active = patchedSort.by === col
                    return (
                      <th key={col} onClick={() => handlePatchedSort(col)}
                        className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
                        style={{ color: active ? '#58a6ff' : 'var(--text-muted)' }}
                      >{label}{active ? (patchedSort.dir === 'desc' ? ' ↓' : ' ↑') : ''}</th>
                    )
                  })}
                  <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }} title="Exploit Prediction Scoring System — probabilité d'exploitation active sous 30 jours">EPSS</th>
                  {['Actif', 'Criticité', 'Clôturé le', 'Validé par / Annotation', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredPatchedVulns.slice(0, patchedLimit).map(v => {
                  const isFalsePositive = v.status === 'false_positive'
                  const closedAt = v.patched_at || v.false_positive_at
                  const isToday = closedAt && new Date(closedAt).toLocaleDateString('fr-FR') === today
                  const badgeColor = isFalsePositive ? '#a371f7' : '#3fb950'
                  return (
                    <tr key={v.id} className="transition-colors" style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      background: isToday ? 'rgba(63,185,80,0.06)' : 'transparent',
                      borderLeft: isToday ? '3px solid #3fb950' : '3px solid transparent',
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = isToday ? 'rgba(63,185,80,0.1)' : 'rgba(88,166,255,0.03)'}
                      onMouseLeave={e => e.currentTarget.style.background = isToday ? 'rgba(63,185,80,0.06)' : 'transparent'}
                    >
                      <td className="px-4 py-3 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>
                        <a href={`https://nvd.nist.gov/vuln/detail/${v.cve?.cve_id}`} target="_blank" rel="noopener noreferrer"
                          onClick={e => e.stopPropagation()} className="hover:underline">{v.cve?.cve_id}</a>
                        <span className="ml-2 text-xs font-normal px-1.5 py-0.5 rounded" style={{ background: `${badgeColor}26`, color: badgeColor }}>
                          {isFalsePositive ? 'Faux positif' : 'Patched'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div style={{ display: 'inline-grid', justifyItems: 'start', gap: 4, position: 'relative' }}>
                          <SeverityBadge value={v.cve?.severity} />
                          <ExploitBadge kev={v.cve?.kev} kevRansomware={v.cve?.kev_ransomware} msfModule={v.cve?.msf_module} msfRank={v.cve?.msf_best_rank} compact spread />
                        </div>
                      </td>
                      <td className="px-4 py-3 font-semibold" style={{ color: cvssColor(v.cve?.cvss_score) }}>{v.cve?.cvss_score ?? '—'}</td>
                      <td className="px-4 py-3 text-xs font-semibold" style={{ color: epssColor(v.cve?.epss_score) }}>{v.cve?.epss_score != null ? (v.cve.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                      <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <ConnectivityDot assetType={v.asset?.asset_type} reachable={v.asset?.scan_reachable} error={v.asset?.scan_error} />
                        {v.asset?.name}
                      </div>
                    </td>
                      <td className="px-4 py-3"><CriticiteBadge value={v.asset?.criticite} /></td>
                      <td className="px-4 py-3 text-xs" style={{ color: isToday ? '#3fb950' : 'var(--text-muted)' }}>
                        {closedAt ? new Date(closedAt).toLocaleDateString('fr-FR') : '—'}
                        {isToday && <span className="ml-1.5 opacity-70">{new Date(closedAt).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}</span>}
                      </td>
                      <td className="px-4 py-3 text-xs max-w-xs" style={{ color: 'var(--text-secondary)' }}>
                        {isFalsePositive ? (
                          <div className="flex flex-col gap-1 items-start">
                            {v.validated_by
                              ? <span className="px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{v.validated_by}</span>
                              : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                            {v.notes && (
                              <div onClick={() => setDetailModal({ vuln: v, label: 'Faux positif', color: '#a371f7', date: v.false_positive_at })}
                                className="max-w-xs cursor-pointer transition-opacity hover:opacity-70"
                                title="Cliquer pour voir le détail"
                              >
                                <MarkdownNote text={v.notes} className="text-xs line-clamp-2" />
                              </div>
                            )}
                          </div>
                        ) : (
                          v.validated_by
                            ? <span className="px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{v.validated_by}</span>
                            : <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1.5">
                          {/* Justificatif de clôture — quelle qu'en soit l'origine.
                              Ne couvrait que les corrections automatiques (détail technique du
                              patch check) : une ligne qualifiée à la main par un analyste
                              n'avait aucun bouton, alors que c'est précisément là que le
                              raisonnement humain doit rester consultable (audit NIS 2).
                              Les deux sources sont concaténées quand elles coexistent. */}
                          {(v.notes || v.patch_check_details) && (() => {
                            const blocks = []
                            if (v.notes) blocks.push({ heading: `Annotation de l'analyste${v.validated_by ? ` (${v.validated_by})` : ''}`, body: v.notes, markdown: true })
                            if (v.patch_check_details) blocks.push({ heading: 'Résultat du contrôle technique', body: v.patch_check_details, markdown: false })
                            return (
                              <button onClick={() => setDetailModal({
                                vuln: v,
                                label: isFalsePositive ? 'Faux positif' : 'Correctif détecté',
                                color: badgeColor,
                                date: v.false_positive_at || v.patched_at,
                                blocks,
                                title: 'Justificatif de clôture',
                              })}
                                className="text-xs px-2.5 py-1.5 rounded-lg transition-colors active:scale-[0.97]"
                                style={{ background: `${badgeColor}1a`, color: badgeColor, border: `1px solid ${badgeColor}40` }}
                                title="Voir pourquoi cette vulnérabilité a été clôturée"
                              >📋 Justificatif</button>
                            )
                          })()}
                          <button onClick={() => { if (!patchLoading[v.id]) handlePatchCheck(v) }}
                            className="text-xs px-2.5 py-1.5 rounded-lg transition-colors font-medium"
                            style={patchLoading[v.id]
                              ? { background: 'var(--accent-blue)', color: '#fff', border: 'none' }
                              : { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }
                            }
                          >{patchLoading[v.id] ? '⏳ Vérif…' : '🔍 Patch check'}</button>
                          <button onClick={() => handleReopen(v)}
                            className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
                            onMouseEnter={e => { e.currentTarget.style.background = 'var(--border)'; e.currentTarget.style.color = '#fb8f44' }}
                            onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-secondary)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                          >↩ Réouvrir</button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
        </Widget>
      </div>

      {analysisModal && <AnalysisModal data={analysisModal} onClose={() => setAnalysisModal(null)} />}

      {awaitingModal && (
        <AnnotationModal
          title={awaitingModal.cve?.cve_id}
          detail={awaitingModal.asset?.name}
          color="#d29922"
          subtitle="Marquer en attente d'un patch correctif"
          helpText={'Annotation obligatoire — justifie pourquoi cette vulnérabilité ne peut pas être traitée pour l\'instant (ex : "aucun correctif publié par Debian pour bookworm à ce jour").'}
          placeholder="Raison du blocage…"
          confirmLabel="⏳ Marquer en attente"
          onClose={() => setAwaitingModal(null)}
          onConfirm={(note, validator) => handleMarkAwaitingFix(awaitingModal, note, validator)}
        />
      )}

      {falsePositiveModal && (
        <AnnotationModal
          title={falsePositiveModal.cve?.cve_id}
          detail={falsePositiveModal.asset?.name}
          color="#a371f7"
          subtitle="Marquer comme faux positif"
          helpText="Annotation obligatoire — justifie pourquoi cette CVE ne concerne pas réellement cet actif (ex : erreur de matching CPE/mots-clés)."
          placeholder="Raison du faux positif…"
          confirmLabel="🚫 Marquer faux positif"
          onClose={() => setFalsePositiveModal(null)}
          onConfirm={(note, validator) => handleMarkFalsePositive(falsePositiveModal, note, validator)}
        />
      )}

      {patchedModal && (
        <AnnotationModal
          title={patchedModal.cve?.cve_id}
          detail={patchedModal.asset?.name}
          color="#3fb950"
          subtitle="Marquer comme corrigé"
          helpText="Annotation facultative — précisez la preuve si utile (ex : build vérifié, KB4489899 installé)."
          placeholder="Ex : build vérifié, KB4489899 installé…"
          confirmLabel="✓ Marquer corrigé"
          noteRequired={false}
          initialNote={patchedModalPrefill}
          onClose={() => { setPatchedModal(null); setPatchedModalPrefill('') }}
          onConfirm={(note, validator) => handleMarkPatched(patchedModal, validator, note)}
        />
      )}

      {otherInstancesModal && (
        <OtherInstancesModal
          cveId={otherInstancesModal.cveId}
          entries={otherInstancesModal.entries}
          loading={otherInstancesModal.loading}
          targetAssetName={otherInstancesModal.vuln?.asset?.name}
          onClose={() => setOtherInstancesModal(null)}
          onReuse={note => handleReuseJustification(otherInstancesModal.vuln, note)}
        />
      )}

      {bulkPatchedModalOpen && (
        <AnnotationModal
          title={`${selectedIds.size} vulnérabilité${selectedIds.size > 1 ? 's' : ''} sélectionnée${selectedIds.size > 1 ? 's' : ''}`}
          color="#3fb950"
          subtitle="Marquer comme corrigées"
          helpText="Annotation facultative, appliquée à toute la sélection."
          placeholder="Ex : build vérifié, KB4489899 installé…"
          confirmLabel={`✓ Corrigé (${selectedIds.size})`}
          noteRequired={false}
          onClose={() => setBulkPatchedModalOpen(false)}
          onConfirm={(note, validator) => handleBulkMarkPatched(selectedIds, validator, note)}
        />
      )}

      {editNoteModal && (
        <AnnotationModal
          title={editNoteModal.cve?.cve_id}
          detail={editNoteModal.asset?.name}
          color="#d29922"
          subtitle="Modifier l'annotation — en attente d'un patch correctif"
          helpText="Annotation obligatoire — toujours justifier pourquoi cette vulnérabilité reste en attente."
          placeholder="Raison du blocage…"
          confirmLabel="💾 Enregistrer"
          initialNote={editNoteModal.notes || ''}
          initialValidator={editNoteModal.validated_by || ''}
          onClose={() => setEditNoteModal(null)}
          onConfirm={(note, validator) => handleUpdateNote(editNoteModal, note, validator)}
        />
      )}

      {detailModal && (
        <AnnotationDetailModal
          vuln={detailModal.vuln}
          label={detailModal.label}
          color={detailModal.color}
          date={detailModal.date}
          text={detailModal.text}
          blocks={detailModal.blocks}
          title={detailModal.title}
          emptyText={detailModal.emptyText}
          onClose={() => setDetailModal(null)}
        />
      )}

      {fpModalOpen && (
        <BulkQualifyModal
          items={fpCandidates.filter(v => selectedIds.has(v.id))}
          onClose={() => setFpModalOpen(false)}
          onConfirm={handleFpConfirm}
        />
      )}

      {patchModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={() => setPatchModal(null)}>
          <div className="max-w-2xl w-full max-h-[85vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
              <div>
                <h2 className="font-semibold font-mono" style={{ color: '#58a6ff' }}>{patchModal.vuln.cve?.cve_id}</h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Résultat du patch check — {patchModal.vuln.asset?.name}</p>
              </div>
              <button onClick={() => setPatchModal(null)} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
              {/* Chargement */}
              {!patchModal.result && (
                <div className="flex flex-col items-center gap-4 py-8">
                  <svg className="w-8 h-8 animate-spin" style={{ color: '#58a6ff' }} fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                  <div className="text-center">
                    <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                      Connexion {/windows/i.test(patchModal.vuln.asset?.os) ? 'WinRM' : 'SSH'} en cours…
                    </p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Interrogation de {patchModal.vuln.asset?.name} — peut prendre jusqu'à 30s</p>
                  </div>
                </div>
              )}

              {/* Erreur */}
              {patchModal.result?.error && (
                <div className="p-4 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)' }}>
                  <p className="font-semibold text-sm mb-1" style={{ color: '#f85149' }}>Erreur de connexion</p>
                  <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{patchModal.result.error}</p>
                </div>
              )}

              {/* Résultat */}
              {patchModal.result && !patchModal.result.error && (
                <>
                  <div className="flex items-center gap-3 p-4 rounded-xl" style={{
                    background: patchModal.result.not_applicable ? 'rgba(163,113,247,0.1)' : patchModal.result.patch_detected ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)',
                    border: `1px solid ${patchModal.result.not_applicable ? 'rgba(163,113,247,0.3)' : patchModal.result.patch_detected ? 'rgba(63,185,80,0.3)' : 'rgba(248,81,73,0.3)'}`,
                  }}>
                    <span className="text-2xl">{patchModal.result.not_applicable ? '🚫' : patchModal.result.patch_detected ? '✅' : '❌'}</span>
                    <div>
                      <p className="font-semibold text-sm" style={{ color: patchModal.result.not_applicable ? '#a371f7' : patchModal.result.patch_detected ? '#3fb950' : '#f85149' }}>
                        {patchModal.result.not_applicable ? 'CVE sans objet sur cet actif' : patchModal.result.patch_detected ? 'Patch détecté' : 'Patch non détecté'}
                        {patchModal.result.cached && (
                          <span className="ml-2 text-xs font-normal px-1.5 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.15)', color: '#58a6ff' }}>
                            en cache — il y a {patchModal.result.cached_age_seconds}s
                          </span>
                        )}
                      </p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{patchModal.result.note}</p>
                    </div>
                  </div>

                  {/* Build/révision OS — signal prioritaire sur le KB, insensible à la
                      supersession par mise à jour cumulative (cf. docs/MATCHING.md § Détection
                      Windows). */}
                  {patchModal.result.build_installed && (
                    <div className="flex items-center gap-2 p-3 rounded-xl text-xs flex-wrap" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Build installé :</span>
                      <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{patchModal.result.build_installed}</span>
                      {typeof patchModal.result.build_verdict === 'boolean' && (
                        <span className="ml-auto font-medium" style={{ color: patchModal.result.build_verdict ? '#3fb950' : '#f85149' }}>
                          {patchModal.result.build_verdict ? '✓ couvre le correctif NVD' : '✗ toujours dans la plage vulnérable'}
                        </span>
                      )}
                    </div>
                  )}



                  {/* Qualification déjà posée sur cette vuln (annotation d'analyste ou
                      bascule automatique). Sans ce bloc, ouvrir un patch check sur une
                      vuln déjà qualifiée n'affichait que le verdict technique, sans le
                      motif retenu — l'analyste ne retrouvait plus son propre
                      raisonnement, ni celui du système. */}
                  {(() => {
                    const st = patchModal.vuln.status
                    const QUALIF = {
                      false_positive: { label: 'Faux positif', couleur: '#a371f7' },
                      awaiting_fix:   { label: 'En attente d’un correctif', couleur: '#d29922' },
                      awaiting_fix_partial: { label: 'En attente d’un correctif (partiel)', couleur: '#d29922' },
                      patched:        { label: 'Corrigée', couleur: '#3fb950' },
                      accepted_risk:  { label: 'Risque accepté', couleur: '#8b949e' },
                    }[st]
                    if (!QUALIF || (!patchModal.vuln.notes && !patchModal.vuln.validated_by)) return null
                    return (
                      <div className="p-3 rounded-xl text-xs" style={{ background: `${QUALIF.couleur}14`, border: `1px solid ${QUALIF.couleur}59` }}>
                        <p className="font-semibold mb-1" style={{ color: QUALIF.couleur }}>
                          Déjà qualifiée : {QUALIF.label}
                          {patchModal.vuln.validated_by ? ` — ${patchModal.vuln.validated_by}` : ''}
                        </p>
                        {patchModal.vuln.notes
                          ? <MarkdownNote text={patchModal.vuln.notes} />
                          : <p style={{ color: 'var(--text-muted)' }}>Aucune annotation enregistrée.</p>}
                      </div>
                    )
                  })()}

                  {/* CVE sans objet : aucun paquet visé n'est installé sur la machine.
                      Violet (couleur du statut false_positive) et non vert/rouge — ce
                      n'est ni "corrigé" ni "vulnérable", c'est "ne s'applique pas". */}
                  {patchModal.result.not_applicable && (
                    <div className="p-3 rounded-xl text-xs" style={{ background: 'rgba(163,113,247,0.08)', border: '1px solid rgba(163,113,247,0.3)' }}>
                      <p className="font-semibold mb-1" style={{ color: '#a371f7' }}>
                        🚫 Produit non installé sur la machine
                      </p>
                      <p style={{ color: 'var(--text-muted)' }}>
                        {patchModal.result.not_applicable_reason}{' '}
                        Aucun correctif n'est en cause : le logiciel concerné n'est pas présent, la CVE
                        est donc sans objet sur cet actif — d'où une qualification en <strong>faux positif</strong>
                        {' '}et non en « corrigé ».
                      </p>
                    </div>
                  )}

                  {/* Application Windows tierce (PuTTY, Wireshark...) matchée via
                      WindowsAppMapping (03/08/2026) — version installée comparée à la plage
                      NVD, même esprit que le signal build OS ci-dessous mais pour un logiciel
                      tiers plutôt que l'OS lui-même. Même bloc que Vulnerabilities.jsx. */}
                  {patchModal.result.app_version_check?.map((m, i) => (
                    <div key={i} className="p-3 rounded-xl text-xs" style={{
                      background: m.verdict === true ? 'rgba(63,185,80,0.08)' : m.verdict === false ? 'rgba(248,81,73,0.08)' : 'rgba(88,166,255,0.08)',
                      border: `1px solid ${m.verdict === true ? 'rgba(63,185,80,0.25)' : m.verdict === false ? 'rgba(248,81,73,0.25)' : 'rgba(88,166,255,0.25)'}`,
                    }}>
                      <p className="font-semibold mb-1" style={{ color: m.verdict === true ? '#3fb950' : m.verdict === false ? '#f85149' : '#58a6ff' }}>
                        {m.verdict === true ? '✅ Version installée hors plage vulnérable' : m.verdict === false ? '❌ Version installée dans la plage vulnérable' : '➖ Comparaison indéterminée'} — {m.name}
                      </p>
                      <p style={{ color: 'var(--text-muted)' }}>
                        Version installée <span className="font-mono">{m.version}</span>
                        {m.range ? (
                          <> — plage vulnérable NVD pour <span className="font-mono">{m.product}</span> : <span className="font-mono">{m.range}</span></>
                        ) : (
                          <> — aucune plage de version exploitable dans NVD pour <span className="font-mono">{m.product}</span>, comparaison manuelle requise</>
                        )}
                      </p>
                    </div>
                  ))}

                  {/* Signal 2bis — seuil de build publié par Microsoft pour le KB de la CVE
                      (session 21/07/2026, cf. services/kb_build.py). Vert/rouge comme le signal
                      NVD, pas bleu comme l'heuristique de date : c'est un verdict ferme
                      (comparaison de version sur un KB ciblant bien la branche d'OS de l'actif),
                      pas un indice — il pilote patch_detected et l'auto-bascule. */}
                  {patchModal.result.msft_build && (
                    <div className="p-3 rounded-xl text-xs" style={{
                      background: patchModal.result.msft_build.patched ? 'rgba(63,185,80,0.08)' : 'rgba(248,81,73,0.08)',
                      border: `1px solid ${patchModal.result.msft_build.patched ? 'rgba(63,185,80,0.25)' : 'rgba(248,81,73,0.25)'}`,
                    }}>
                      <p className="font-semibold mb-1" style={{ color: patchModal.result.msft_build.patched ? '#3fb950' : '#f85149' }}>
                        {patchModal.result.msft_build.patched ? '✅ Correctif inclus' : '❌ Correctif absent'} — build Microsoft ({patchModal.result.msft_build.kb})
                      </p>
                      <p style={{ color: 'var(--text-muted)' }}>
                        Build installé <span className="font-mono">{patchModal.result.msft_build.installed_build}</span>{' '}
                        {patchModal.result.msft_build.patched ? '≥' : '<'}{' '}
                        <span className="font-mono">{patchModal.result.msft_build.fixed_build}</span>, build corrigé publié par
                        Microsoft pour ce KB. Les mises à jour Windows étant cumulatives, c'est une preuve et non une estimation
                        — NVD n'a pas de plage de version exploitable pour cette CVE.
                      </p>
                    </div>
                  )}

                  {/* Signal 3 — repli par date (session 20/07/2026), uniquement affiché quand
                      build_verdict est indéterminé. Purement indicatif — n'a jamais fait basculer
                      patch_detected/l'auto-bascule ; bleu "info" pour ne pas être confondu avec un
                      verdict définitif. */}
                  {typeof patchModal.result.date_heuristic === 'boolean' && (
                    <div className="p-3 rounded-xl text-xs" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.25)' }}>
                      <p className="font-semibold mb-1" style={{ color: '#58a6ff' }}>
                        📅 Signal indicatif — {patchModal.result.date_heuristic ? 'probablement déjà corrigée' : 'pas de garantie'}
                      </p>
                      <p style={{ color: 'var(--text-muted)' }}>
                        Dernière mise à jour installée le {patchModal.result.last_update_installed}, {patchModal.result.date_heuristic ? 'postérieure' : 'antérieure ou égale'} à
                        la {patchModal.result.date_heuristic_source === 'msrc_release' ? 'sortie du correctif (MSRC)' : 'publication de la CVE'} ({patchModal.result.date_heuristic_reference}).
                        Pas une preuve formelle — NVD n'a pas de numéro de build exploitable pour cette CVE, seul un contrôle manuel confirme.
                      </p>
                    </div>
                  )}

                  {patchModal.result.kb_checked?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>KBs vérifiés ({patchModal.result.kb_checked.length})</p>
                      <div className="space-y-1 max-h-48 overflow-y-auto">
                        {patchModal.result.kb_checked.map(kb => {
                          const installed = patchModal.result.kb_installed?.includes(kb)
                          const hint = patchModal.result.kb_os_hint?.find(h => h.kb === kb)
                          return (
                            <div key={kb} className="px-3 py-1.5 rounded-lg text-xs" style={{ background: 'var(--bg-secondary)' }}>
                              <div className="flex items-center justify-between">
                                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{kb}</span>
                                <span style={{ color: installed ? '#3fb950' : '#f85149' }}>{installed ? '✓ Installé' : '✗ Manquant'}</span>
                              </div>
                              {installed && hint && (
                                <p className="mt-1" style={{ color: hint.matches_asset_os === false ? '#fb8f44' : 'var(--text-muted)' }}>
                                  {hint.matches_asset_os === true && `✓ Correspond à l'OS déclaré (${hint.products.join(', ')})`}
                                  {hint.matches_asset_os === false && `⚠ Cible ${hint.products.join(', ')} — ne correspond pas à l'OS déclaré de l'actif (${patchModal.vuln.asset?.os})`}
                                  {hint.matches_asset_os === null && 'Correspondance OS indéterminée (info MSRC indisponible)'}
                                </p>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                  {patchModal.autoPatched ? (
                    // Deux issues automatiques possibles, à ne pas confondre dans le
                    // libellé : "corrigée" (correctif détecté) ou "faux positif"
                    // (produit absent — rien n'a été corrigé).
                    <div className="flex items-center gap-2 text-xs font-medium"
                      style={{ color: patchModal.result?.not_applicable ? '#a371f7' : '#3fb950' }}>
                      <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" /></svg>
                      {patchModal.result?.not_applicable
                        ? 'Qualifiée automatiquement en faux positif — sévérité non-critique, aucune validation requise.'
                        : 'Corrigée automatiquement — sévérité non-critique, aucune validation requise.'}
                    </div>
                  ) : (
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handlePatchCheck(patchModal.vuln, true)}
                          disabled={patchLoading[patchModal.vuln.id]}
                          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors disabled:opacity-40"
                          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                          title="Ignore le résultat en cache et relance un vrai contrôle WinRM/SSH"
                        >🔄 Relancer un scan</button>
                        {/* Absent sur un résultat en cache (07/08/2026) : les commandes
                            brutes ne sont jamais persistées en base (cf.
                            services/patch_checker.py::apply_patch_result), donc
                            indisponibles tant qu'on ne relance pas un vrai contrôle. */}
                        {patchModal.result.debug_commands && (
                          <button
                            onClick={() => setShowDebugCommands(s => !s)}
                            className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                            title="Commande(s) exécutée(s) et retour brut du contrôle SSH/WinRM"
                          >🔍 {showDebugCommands ? 'Masquer le détail' : 'Détail'}</button>
                        )}
                      </div>
                      {patchModal.result.patch_detected ? (
                        <button
                          onClick={() => { setPatchedModal(patchModal.vuln); setPatchedModalPrefill(patchModal.result.details || ''); setPatchModal(null) }}
                          className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-colors"
                          style={{ background: 'rgba(63,185,80,0.2)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.5)' }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(63,185,80,0.3)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'rgba(63,185,80,0.2)'}
                        >✓ Corrigé</button>
                      ) : (
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Applique le correctif sur le serveur, puis relance le patch check pour confirmer.</p>
                      )}
                    </div>
                  )}

                  {showDebugCommands && patchModal.result.debug_commands && (
                    <div className="space-y-2">
                      <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                        Commande(s) exécutée(s) — lecture seule
                      </p>
                      {patchModal.result.debug_commands.map((c, i) => (
                        <div key={i} className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                          <p className="px-3 pt-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Commande</p>
                          <pre className="px-3 pb-2 pt-1 text-xs font-mono whitespace-pre-wrap break-words overflow-y-auto" style={{ maxHeight: 140, color: 'var(--text-secondary)', margin: 0 }}>
                            {c.command}
                          </pre>
                          <p className="px-3 pt-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)', borderTop: '1px solid var(--border)' }}>Retour</p>
                          <pre className="px-3 pb-2 pt-1 text-xs font-mono whitespace-pre-wrap break-words overflow-y-auto" style={{ maxHeight: 220, color: 'var(--text-muted)', margin: 0, background: 'var(--bg-secondary)' }}>
                            {c.output || '(sortie vide)'}
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  )
}
