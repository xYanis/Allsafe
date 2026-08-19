import { useEffect, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { vulns as fetchVulns, assetNames as fetchAssetNames, updateVuln, analyzeIA, recommend, script, patchCheck, criticalReviewCandidates, falsePositiveCandidates, bulkFalsePositive, awaitingFixCandidates, bulkAwaitingFix, bulkAcceptedRisk, getVulnStatusHistory, getVulnOtherInstances } from '../api/client.js'
import PageHero from '../components/PageHero.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ExploitBadge from '../components/ExploitBadge.jsx'
import StatusBadge, { STATUS_LABELS } from '../components/StatusBadge.jsx'
import AnalysisModal from '../components/AnalysisModal.jsx'
import ValidateDropdown from '../components/ValidateDropdown.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import DeclareIncidentButton from '../components/DeclareIncidentButton.jsx'
import BulkValidateModal from '../components/BulkValidateModal.jsx'
import BulkQualifyModal from '../components/BulkQualifyModal.jsx'
import AnnotationModal from '../components/AnnotationModal.jsx'
import AnnotationDetailModal from '../components/AnnotationDetailModal.jsx'
import StatusHistoryModal from '../components/StatusHistoryModal.jsx'
import OtherInstancesModal from '../components/OtherInstancesModal.jsx'
import PageLoader from '../components/PageLoader.jsx'
import ConnectivityDot from '../components/ConnectivityDot.jsx'
import AssetDropdown from '../components/AssetDropdown.jsx'
import { tintedCard, CYBERVULN_CARD_TINT } from '../utils/cardStyle.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { MODULES } from '../constants/modules.js'
import {
  FAKE_VULNERABILITIES, anonymizeVuln, isFakeId, sortVulnList,
  fakePatchCheckResult, fakeAnalysis, fakeRecommendation, fakeScript,
} from '../utils/fakeData.js'

// Survol de ligne teinté à la couleur du module CyberVuln (11/08/2026, tour visuel — cohérence
// sidebar → page, cf. docs/FRONTEND.md § Tour visuel), pas les boutons d'action (`Btn` plus bas,
// variant `primary`) : le rouge de CyberVuln est déjà le code couleur "sévérité CRITICAL/statut
// open" sur cette page précise — l'appliquer aussi aux boutons d'action créerait une confusion
// entre "action principale" et "dangereux", contrairement à Incidents/Documentation/Audits où le
// rouge/l'ambre/le vert du module n'a pas ce double-sens.
const MODULE_HOVER = `${MODULES.cybervuln.color}0a`

const CARD = tintedCard(CYBERVULN_CARD_TINT)
const TOOLTIP_STYLE = { backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }

function Btn({ children, onClick, variant = 'primary', disabled, title }) {
  const styles = {
    primary:   { background: 'var(--accent-blue)', color: '#fff', border: 'none' },
    success:   { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)' },
    warning:   { background: 'rgba(210,153,34,0.1)',  color: '#d29922', border: '1px solid rgba(210,153,34,0.25)' },
    orange:    { background: 'rgba(251,143,68,0.1)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.25)' },
    danger:    { background: 'rgba(248,81,73,0.1)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' },
    secondary: { background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
  }
  const s = styles[variant] || styles.secondary
  return (
    <button onClick={onClick} disabled={disabled} title={title}
      className="text-xs px-2.5 py-1.5 rounded-lg font-medium transition-[color,background-color,border-color,transform] duration-150 disabled:opacity-40 active:scale-[0.97]"
      style={s}
    >
      {children}
    </button>
  )
}

const STATUSES = ['', 'open', 'in_progress', 'patched', 'accepted_risk', 'awaiting_fix', 'awaiting_fix_partial', 'false_positive']
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function SortHeader({ label, col, sort, onSort }) {
  const active = sort.by === col
  const arrow = active ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''
  return (
    <th
      onClick={() => onSort(col)}
      className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide cursor-pointer select-none"
      style={{ color: active ? '#58a6ff' : 'var(--text-muted)', userSelect: 'none' }}
    >
      {label}{arrow}
    </th>
  )
}

export default function Vulnerabilities() {
  const { isAnonymous } = usePresentation()
  const { names: ANALYSTS } = useAnalysts()
  const [data, setData] = useState({ items: [], total: 0 })
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState({ status: 'open', severity: '', validated_by: '', max_age_years: '', search: '', kev: false, msf_module: false })
  // Filtre par actif (18/08/2026, retour utilisateur — absent jusqu'ici sur cette page
  // alors que le backend le supporte déjà, cf. asset_id sur GET /vulnerabilities) :
  // même composant/pattern que Dashboard.jsx et Reports.jsx (AssetDropdown.jsx),
  // état séparé de `filters` (tableau, pas une simple valeur de <select>).
  const [selectedAssetIds, setSelectedAssetIds] = useState([])
  const [searchParams, setSearchParams] = useSearchParams()

  // Deep-link depuis le bandeau de rattrapage (Dashboard) : ?cve=CVE-XXXX ouvre
  // la page ciblée sur cette CVE exacte, tous statuts, sans filtre d'âge — pour
  // qu'on retrouve toujours ce que le bandeau annonce (une CVE LOW auto-patchée
  // est sinon hors des premières pages triées par score, cf. STATUS.md).
  useEffect(() => {
    const cve = searchParams.get('cve')
    if (cve) {
      setFilters({ status: '', severity: '', validated_by: '', max_age_years: '', search: cve })
      setPage(1)
      setSearchParams({}, { replace: true })   // consommé : ne pas re-appliquer au prochain rendu
    }
  }, [searchParams, setSearchParams])

  // Deep-link par actif (18/08/2026, ex. AgentHistory.jsx "Vulnérabilités ouvertes") :
  // ?asset_id=<uuid> filtre sur cet actif, tous statuts (le lien annonce un compte "ouvertes"
  // précis, pas la peine de re-filtrer aussi sur status='open' vu que c'est déjà implicite
  // dans ce que l'utilisateur vient de cliquer — le laisser voir aussi les autres statuts
  // de cet actif au passage plutôt que de re-imposer 'open' sans le dire).
  useEffect(() => {
    const assetId = searchParams.get('asset_id')
    if (assetId) {
      setSelectedAssetIds([assetId])
      setFilters(f => ({ ...f, status: '' }))
      setPage(1)
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, setSearchParams])
  const [sort, setSort] = useState({ by: 'score', dir: 'desc' })
  const [loading, setLoading] = useState(false)
  const [modal, setModal] = useState(null)
  const [analysisModal, setAnalysisModal] = useState(null)
  const [patchModal, setPatchModal] = useState(null)
  const [patchLoading, setPatchLoading] = useState({})
  // Bouton "Détail" (07/08/2026, demande explicite) — commandes SSH/WinRM et
  // retour brut du contrôle, repliés par défaut (surtout utile en dépannage,
  // pas à chaque lecture). Remis à false à chaque nouveau contrôle, cf.
  // handlePatchCheck — sinon un panneau ouvert sur une vuln resterait ouvert
  // en revenant sur une autre.
  const [showDebugCommands, setShowDebugCommands] = useState(false)
  const [detailModal, setDetailModal] = useState(null)   // justificatif de clôture
  const [historyModal, setHistoryModal] = useState(null) // { cveId, entries, loading }
  const [otherInstancesModal, setOtherInstancesModal] = useState(null) // { vulnId, cveId, entries, loading }
  // Justification récupérée sur un autre actif (04/08/2026, "↩ Réutiliser cette
  // justification") — pré-remplit l'annotation de la ligne concernée, tant
  // qu'elle n'a pas déjà un patch_check_details propre à elle. Simple mémoire
  // d'appoint côté client, jamais persistée telle quelle avant confirmation.
  const [reuseNotes, setReuseNotes] = useState({}) // { [vulnId]: note }
  const [actionMsg, setActionMsg] = useState({ text: '', type: 'info' })
  const [bulkCandidates, setBulkCandidates] = useState([])
  const [bulkModalOpen, setBulkModalOpen] = useState(false)
  const [fpCandidates, setFpCandidates] = useState([])
  const [fpModalOpen, setFpModalOpen] = useState(false)
  const [afCandidates, setAfCandidates] = useState([])
  const [afModalOpen, setAfModalOpen] = useState(false)
  const [arModalOpen, setArModalOpen] = useState(false)       // risque accepté groupé
  const [acceptRiskModal, setAcceptRiskModal] = useState(null) // risque accepté unitaire (vuln ciblée)
  const perPage = 50

  // Les 3 listes de candidats (awaiting-fix/false-positive/critical-review) restent
  // bornées par défaut par le backend aux CVE publiées il y a moins de 2 ans (cf.
  // routers/vulnerabilities.py, CANDIDATE_MAX_AGE_YEARS) — le sélecteur qui permettait
  // de lever cette fenêtre par actif a été retiré (18/08/2026, redondant/confus avec le
  // filtre par actif du tableau principal, cf. AssetDropdown ci-dessous).
  const [assetList, setAssetList] = useState([])

  useEffect(() => {
    if (isAnonymous) return
    fetchAssetNames().then(r => setAssetList(r.data || [])).catch(() => {})
  }, [isAnonymous])

  const loadBulkCandidates = useCallback(() => {
    if (isAnonymous) return
    criticalReviewCandidates('').then(r => setBulkCandidates(r.data.items || [])).catch(() => {})
  }, [isAnonymous])

  useEffect(() => { loadBulkCandidates() }, [loadBulkCandidates])

  const loadFpCandidates = useCallback(() => {
    if (isAnonymous) return
    falsePositiveCandidates('').then(r => setFpCandidates(r.data.items || [])).catch(() => {})
  }, [isAnonymous])

  useEffect(() => { loadFpCandidates() }, [loadFpCandidates])

  const loadAfCandidates = useCallback(() => {
    if (isAnonymous) return
    awaitingFixCandidates('').then(r => setAfCandidates(r.data.items || [])).catch(() => {})
  }, [isAnonymous])

  useEffect(() => { loadAfCandidates() }, [loadAfCandidates])

  // Les 3 modales BulkQualifyModal gèrent elles-mêmes l'appel API par lots
  // (barre de progression, cf. BulkQualifyModal.jsx, même principe que
  // BulkValidateModal.jsx) — ici on ne fait plus que réagir au résultat final.
  function handleAfConfirm(applied, validator) {
    flash(`${applied} vulnérabilité(s) passée(s) en attente de correctif — validé par ${validator}`, 'success')
    setAfModalOpen(false)
    loadAfCandidates()
    load()
  }

  function handleFpConfirm(applied, validator) {
    flash(`${applied} vulnérabilité(s) qualifiée(s) en faux positif — validé par ${validator}`, 'success')
    setFpModalOpen(false)
    loadFpCandidates()
    load()
  }

  function handleArConfirm(applied, validator) {
    flash(`${applied} vulnérabilité(s) passée(s) en risque accepté — validé par ${validator}`, 'success')
    setArModalOpen(false)
    load()
  }

  async function handleAcceptRiskConfirm(note, validator, reviewDate) {
    const vuln = acceptRiskModal
    if (!vuln) return
    const payload = { status: 'accepted_risk', notes: note, validated_by: validator, accepted_risk_until: new Date(reviewDate).toISOString() }
    if (isAnonymous) {
      patchVulnLocally(vuln.id, payload)
      flash(`${vuln.cve.cve_id} passé en risque accepté — validé par ${validator} (démo)`, 'info')
      setAcceptRiskModal(null)
      return
    }
    await updateVuln(vuln.id, payload)
    flash(`${vuln.cve.cve_id} passé en risque accepté — validé par ${validator}`, 'info')
    setAcceptRiskModal(null)
    load()
  }

  // La modale gère elle-même l'appel API par lots (barre de progression, cf.
  // BulkValidateModal.jsx) — ici on ne fait plus que réagir au résultat final.
  function handleBulkConfirm(applied, validator) {
    flash(`${applied} vulnérabilité(s) CRITICAL marquée(s) comme corrigée(s) — validé par ${validator}`, 'success')
    setBulkModalOpen(false)
    loadBulkCandidates()
    load()
  }

  const load = useCallback(() => {
    setLoading(true)
    if (isAnonymous) {
      // Mode Présentation : pagination/tri côté client sur réel (anonymisé,
      // récupéré en un seul appel) + fictif fusionnés — le backend ignore
      // les données de démonstration.
      const params = { page: 1, per_page: 200, sort_by: sort.by, sort_dir: sort.dir }
      if (filters.status)       params.status       = filters.status
      if (filters.severity)     params.severity     = filters.severity
      if (filters.validated_by) params.validated_by = filters.validated_by
      if (filters.search)       params.search       = filters.search
      if (filters.max_age_years) params.max_age_years = filters.max_age_years
      if (filters.kev) params.kev = true
      if (filters.msf_module) params.msf_module = true
      if (selectedAssetIds.length) params.asset_id = selectedAssetIds.join(',')
      const ageCutoff = filters.max_age_years ? Date.now() - filters.max_age_years * 365 * 86400000 : null
      fetchVulns(params).then(r => {
        const realItems = (r.data.items || []).map(anonymizeVuln)
        const fakeItems = FAKE_VULNERABILITIES.filter(v => {
          if (filters.status && v.status !== filters.status) return false
          if (filters.severity && v.cve?.severity !== filters.severity) return false
          if (filters.validated_by && v.validated_by !== filters.validated_by) return false
          if (filters.search && !v.cve?.cve_id?.toLowerCase().includes(filters.search.trim().toLowerCase())) return false
          if (ageCutoff && v.cve?.published && new Date(v.cve.published).getTime() < ageCutoff) return false
          if (filters.kev && !v.cve?.kev) return false
          if (filters.msf_module && !v.cve?.msf_module) return false
          if (selectedAssetIds.length && !selectedAssetIds.includes(v.asset?.id)) return false
          return true
        })
        const merged = sortVulnList([...realItems, ...fakeItems], sort)
        setData({ items: merged.slice((page - 1) * perPage, page * perPage), total: merged.length })
      }).finally(() => setLoading(false))
      return
    }
    const params = { page, per_page: perPage, sort_by: sort.by, sort_dir: sort.dir }
    if (filters.status)       params.status       = filters.status
    if (filters.severity)     params.severity     = filters.severity
    if (filters.validated_by) params.validated_by = filters.validated_by
    if (filters.search)       params.search       = filters.search
    if (filters.max_age_years) params.max_age_years = filters.max_age_years
    if (filters.kev) params.kev = true
    if (filters.msf_module) params.msf_module = true
    if (selectedAssetIds.length) params.asset_id = selectedAssetIds.join(',')
    fetchVulns(params).then(r => setData(r.data)).finally(() => setLoading(false))
  }, [page, filters, sort, isAnonymous, selectedAssetIds])

  useEffect(() => { load() }, [load])

  function setFilter(k, v) { setFilters(f => ({ ...f, [k]: v })); setPage(1) }

  function handleSort(col) {
    setSort(s => s.by === col ? { by: col, dir: s.dir === 'desc' ? 'asc' : 'desc' } : { by: col, dir: 'desc' })
    setPage(1)
  }

  function flash(text, type = 'info') {
    setActionMsg({ text, type })
    setTimeout(() => setActionMsg({ text: '', type: 'info' }), 4000)
  }

  // Le pool de vulnérabilités fictives est statique — un simple re-fetch via
  // load() ferait réapparaître leur statut d'origine. On met donc à jour la
  // liste affichée localement plutôt que de recharger. Utilisé pour tout id
  // en mode Présentation (pas seulement `demo-*`) : dès que le mode Anonyme
  // est actif, le valideur choisi est fictif (cf. ValidateDropdown/
  // AnnotationModal) — on ne l'écrit donc jamais dans la vraie base, y
  // compris pour une vulnérabilité réelle affichée sous un nom anonymisé.
  function patchVulnLocally(vulnId, patch) {
    setData(prev => ({
      ...prev,
      items: prev.items
        .map(v => v.id === vulnId ? { ...v, ...patch } : v)
        .filter(v => !filters.status || v.status === filters.status),
    }))
  }

  async function handleMarkPatched(vuln, validator, note) {
    if (isAnonymous) {
      patchVulnLocally(vuln.id, { status: 'patched', validated_by: validator, patched_at: new Date().toISOString(), ...(note ? { notes: note } : {}) })
      flash(`${vuln.cve.cve_id} marqué comme corrigé — validé par ${validator} (démo)`, 'success')
      return
    }
    await updateVuln(vuln.id, { status: 'patched', validated_by: validator, ...(note ? { notes: note } : {}) })
    flash(`${vuln.cve.cve_id} marqué comme corrigé — validé par ${validator}`, 'success')
    load()
  }

  async function handleStatus(vuln, status) {
    const labels = { open: 'réouvert', in_progress: 'en cours', accepted_risk: 'risque accepté' }
    if (isAnonymous) {
      patchVulnLocally(vuln.id, { status })
      flash(`${vuln.cve.cve_id} ${labels[status] || status} (démo)`, 'info')
      return
    }
    await updateVuln(vuln.id, { status })
    flash(`${vuln.cve.cve_id} ${labels[status] || status}`, 'info')
    load()
  }

  async function handleAnalyze(vuln) {
    if (isFakeId(vuln.id)) {
      setAnalysisModal({ analysis: fakeAnalysis(vuln), cve_id: vuln.cve.cve_id, description: vuln.cve.description })
      return
    }
    flash('Analyse IA en cours…')
    try {
      const result = await analyzeIA(vuln.cve.cve_id, vuln.asset.id)
      setActionMsg({ text: '', type: 'info' })
      setAnalysisModal({
        analysis: result.data.analysis,
        cve_id: vuln.cve.cve_id,
        description: vuln.cve.description,
      })
      load()
    } catch { flash('Erreur analyse IA.', 'error') }
  }

  async function handleShowHistory(vuln) {
    setHistoryModal({ cveId: vuln.cve.cve_id, entries: [], loading: true })
    if (isFakeId(vuln.id)) {
      // Historique prospectif introduit après le pool de démo — rien à simuler
      // de réaliste ici, l'état vide suffit à montrer le composant.
      setHistoryModal({ cveId: vuln.cve.cve_id, entries: [], loading: false })
      return
    }
    try {
      const r = await getVulnStatusHistory(vuln.id)
      setHistoryModal({ cveId: vuln.cve.cve_id, entries: r.data || [], loading: false })
    } catch {
      setHistoryModal({ cveId: vuln.cve.cve_id, entries: [], loading: false })
    }
  }

  async function handleShowOtherInstances(vuln) {
    setOtherInstancesModal({ vulnId: vuln.id, cveId: vuln.cve.cve_id, entries: [], loading: true })
    if (isFakeId(vuln.id)) {
      setOtherInstancesModal({ vulnId: vuln.id, cveId: vuln.cve.cve_id, entries: [], loading: false })
      return
    }
    try {
      const r = await getVulnOtherInstances(vuln.id)
      setOtherInstancesModal({ vulnId: vuln.id, cveId: vuln.cve.cve_id, entries: r.data || [], loading: false })
    } catch {
      setOtherInstancesModal({ vulnId: vuln.id, cveId: vuln.cve.cve_id, entries: [], loading: false })
    }
  }

  // Reprend une justification vue sur un autre actif pour CETTE ligne — ne
  // fait qu'alimenter l'annotation pré-remplie du bouton "✓ Corrigé", jamais
  // d'action sur l'autre actif ni sur celui-ci tant que l'analyste ne confirme
  // pas explicitement (cf. ValidateDropdown, reste éditable avant validation).
  function handleReuseJustification(vulnId, note) {
    setReuseNotes(prev => ({ ...prev, [vulnId]: note }))
    setOtherInstancesModal(null)
    flash('Justification reprise — vérifiez-la puis validez avec "✓ Marquer comme corrigé".', 'info')
  }

  async function handleRecommend(vuln) {
    if (isFakeId(vuln.id)) {
      setModal({ type: 'recommend', content: fakeRecommendation(vuln) })
      return
    }
    flash('Génération…')
    try {
      const r = await recommend(vuln.id)
      setModal({ type: 'recommend', content: r.data.recommendation })
      setActionMsg({ text: '', type: 'info' })
    } catch { flash('Erreur génération.', 'error') }
  }

  async function handlePatchCheck(vuln, force = false) {
    setPatchLoading(l => ({ ...l, [vuln.id]: true }))
    setPatchModal({ vuln, result: null })
    setShowDebugCommands(false)
    if (isFakeId(vuln.id)) {
      setTimeout(() => {
        setPatchModal({ vuln, result: fakePatchCheckResult(vuln) })
        setPatchLoading(l => ({ ...l, [vuln.id]: false }))
      }, 500)
      return
    }
    try {
      const r = await patchCheck(vuln.id, force)
      setPatchModal({ vuln, result: r.data.check_result })
    } catch (e) {
      const msg = e?.response?.data?.detail || 'Erreur lors du patch check'
      setPatchModal({ vuln, result: { patch_detected: null, error: msg, kb_checked: [] } })
    }
    finally { setPatchLoading(l => ({ ...l, [vuln.id]: false })) }
  }

  async function handleScript(vuln) {
    if (isFakeId(vuln.id)) {
      const r = fakeScript(vuln)
      setModal({ type: 'script', content: r.script, script_type: r.script_type })
      return
    }
    flash('Génération script…')
    try {
      const r = await script(vuln.id)
      setModal({ type: 'script', content: r.data.script, script_type: r.data.script_type })
      setActionMsg({ text: '', type: 'info' })
    } catch { flash('Erreur génération script.', 'error') }
  }

  const totalPages = Math.ceil(data.total / perPage)
  // Pas de critère technique objectif pour "risque accepté" (contrairement à
  // awaiting-fix/false-positive, basés sur un signal du patch check) — la
  // sélection porte sur ce qui est actuellement affiché, décision humaine pure.
  const arCandidates = data.items.filter(v => ['open', 'in_progress', 'awaiting_fix', 'awaiting_fix_partial'].includes(v.status))
    .map(v => ({ ...v, raison: 'Sélection manuelle' }))
  const showPatchedAt   = !filters.status || filters.status === 'patched'
  const showValidatedBy = !filters.status || filters.status === 'patched'

  const msgStyle = {
    info:    { background: 'rgba(88,166,255,0.1)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' },
    success: { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.2)' },
    error:   { background: 'rgba(248,81,73,0.1)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' },
  }

  const selectStyle = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-secondary)',
    padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
  }
  // Style "filtre actif" (17/08/2026, demande explicite — étendre à tous les menus déroulants
  // de l'app le comportement déjà posé sur Durcissement.jsx/Assets.jsx/Inventaire.jsx) — même
  // formule, couleur du module de cette page (CyberVuln).
  const activeSelectStyle = { background: `${MODULES.cybervuln.color}1f`, color: MODULES.cybervuln.color, border: `1px solid ${MODULES.cybervuln.color}59`, borderRadius: 8, padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer' }

  const hasFilters = filters.status || filters.severity || filters.validated_by || filters.max_age_years || filters.search || filters.kev || filters.msf_module || selectedAssetIds.length > 0

  // Badge "déjà résolu ailleurs" (04/08/2026) — `resolved_elsewhere_count` vient
  // du serveur (une seule requête groupée par page, cf. routers/vulnerabilities.py),
  // jamais recalculé ligne par ligne côté client. Le détail (qui, avec quelle
  // justification) n'est chargé qu'au clic, pas pour les 200 lignes d'un coup.
  // Même famille visuelle que "Correctif détecté ?"/"Faux positif ?" du
  // Dashboard (pastille en pointillés) — libellé "correctif déjà appliqué"
  // privilégié quand au moins une autre instance est réellement `patched`
  // (cas dominant en pratique), repli générique "déjà qualifié" sinon
  // (faux positif/risque accepté ailleurs — le compte exact par statut n'est
  // volontairement pas remonté ligne par ligne, cf. patched_elsewhere_count
  // ci-dessous, pour rester une seule requête groupée par page).
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
        className="text-xs px-1.5 py-0.5 rounded font-medium whitespace-nowrap"
        style={{ background: 'transparent', color, border: `1px dashed ${color}7a` }}
        title="Voir le diagnostic/la justification posés sur le(s) autre(s) actif(s) concerné(s) par cette CVE"
      >{isPatched ? '✅' : '🔁'} {label}</button>
    )
  }

  // Actions d'une ligne — extrait pour être partagé entre la table (desktop) et la vue
  // carte (mobile, cf. VulnCard ci-dessous) sans dupliquer la dizaine de boutons/conditions.
  function renderActions(v) {
    return (
      <div className="flex gap-1.5 flex-wrap">
        <Btn onClick={() => handleAnalyze(v)}>Analyser</Btn>
        <Btn variant={patchLoading[v.id] ? 'primary' : 'secondary'} onClick={() => { if (!patchLoading[v.id]) handlePatchCheck(v) }}>
          {patchLoading[v.id] ? '⏳ Vérif…' : '🔍 Patch check'}
        </Btn>
        <Btn variant="warning" onClick={() => handleRecommend(v)}>Recommandation</Btn>
        <Btn variant="orange" onClick={() => handleScript(v)}>Script</Btn>
        {v.status !== 'patched' && (
          <ValidateDropdown
            key={reuseNotes[v.id] ? `${v.id}-reuse` : v.id}
            detected={false}
            initialNote={reuseNotes[v.id] ?? v.patch_check_details ?? ''}
            onSelect={(name, note) => handleMarkPatched(v, name, note)}
          />
        )}
        {/* Justificatif de clôture — même bouton que le Dashboard :
            pourquoi cette ligne a été clôturée (annotation d'analyste
            et/ou résultat technique du patch check). N'apparaît que
            s'il y a réellement quelque chose à montrer. */}
        {(v.notes || v.patch_check_details) && (() => {
          const isFp = v.status === 'false_positive'
          const color = isFp ? '#a371f7' : '#3fb950'
          const blocks = []
          if (v.notes) blocks.push({ heading: `Annotation de l'analyste${v.validated_by ? ` (${v.validated_by})` : ''}`, body: v.notes, markdown: true })
          if (v.patch_check_details) blocks.push({ heading: 'Résultat du contrôle technique', body: v.patch_check_details, markdown: false })
          return (
            <button onClick={() => setDetailModal({
                vuln: v,
                label: isFp ? 'Faux positif' : v.status === 'awaiting_fix' ? "En attente d'un patch correctif" : v.status === 'awaiting_fix_partial' ? "En attente d'un patch correctif (partiel)" : 'Correctif détecté',
                color: (v.status === 'awaiting_fix' || v.status === 'awaiting_fix_partial') ? '#d29922' : color,
                date: v.false_positive_at || v.awaiting_fix_at || v.patched_at,
                blocks,
                title: 'Justificatif de clôture',
              })}
              className="text-xs px-2.5 py-1.5 rounded-lg transition-colors active:scale-[0.97]"
              style={{ background: `${color}1a`, color, border: `1px solid ${color}40` }}
              title="Voir pourquoi cette vulnérabilité a été clôturée"
            >📋 Justificatif</button>
          )
        })()}
        <button onClick={() => handleShowHistory(v)}
          className="text-xs px-2.5 py-1.5 rounded-lg transition-colors active:scale-[0.97]"
          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
          title="Historique des changements de statut (manuels et automatiques)"
        >🕒 Historique</button>
        {v.status === 'patched' && (
          <Btn variant="danger" onClick={() => handleStatus(v, 'open')} title="Annuler la correction">↩ Réouvrir</Btn>
        )}
        {['open', 'in_progress', 'awaiting_fix', 'awaiting_fix_partial'].includes(v.status) && (
          <Btn variant="secondary" onClick={() => setAcceptRiskModal(v)} title="Accepter le risque — justification, validateur et date de revue obligatoires">🛡 Risque accepté</Btn>
        )}
        <DeclareIncidentButton sourceType="vulnerability" sourceId={v.id} />
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        title="Vulnérabilités" color="#f85149"
        subtitle="Suivi et gestion des vulnérabilités par actif"
      />

      {!isAnonymous && (afCandidates.length > 0 || fpCandidates.length > 0 || bulkCandidates.length > 0 || arCandidates.length > 0) && (
        <div className="flex items-center flex-wrap gap-2">
          {afCandidates.length > 0 && (
            <button onClick={() => setAfModalOpen(true)}
              title="CVE pour lesquelles la distribution n'a publié aucun correctif — rien à appliquer, elles basculeront seules en corrigé dès publication"
              className="text-xs px-3 py-2 rounded-lg font-medium flex items-center gap-1.5 active:scale-[0.97]"
              style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' }}
            >
              ⏳ En attente de correctif ({afCandidates.length})
            </button>
          )}
          {fpCandidates.length > 0 && (
            <button onClick={() => setFpModalOpen(true)}
              title="CVE ne concernant pas réellement l'actif (rattachement erroné, ou produit non installé) — chacune reste à confirmer, rien n'est qualifié automatiquement"
              className="text-xs px-3 py-2 rounded-lg font-medium flex items-center gap-1.5 active:scale-[0.97]"
              style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }}
            >
              🚫 Faux positifs à qualifier ({fpCandidates.length})
            </button>
          )}
          {bulkCandidates.length > 0 && (
            <button onClick={() => setBulkModalOpen(true)}
              title="Vulnérabilités CRITICAL avec un signal de correctif positif, en attente de validation — chacune reste à confirmer individuellement, rien n'est basculé automatiquement"
              className="text-xs px-3 py-2 rounded-lg font-medium flex items-center gap-1.5"
              style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }}
            >
              🛡️ Validation groupée CRITICAL ({bulkCandidates.length})
            </button>
          )}
          {arCandidates.length > 0 && (
            <button onClick={() => setArModalOpen(true)}
              title="Accepter le risque en masse sur la page affichée — justification, validateur et date de revue obligatoires pour chacune"
              className="text-xs px-3 py-2 rounded-lg font-medium flex items-center gap-1.5 active:scale-[0.97]"
              style={{ background: 'rgba(227,179,65,0.1)', color: '#e3b341', border: '1px solid rgba(227,179,65,0.3)' }}
            >
              🛡 Accepter en masse ({arCandidates.length})
            </button>
          )}
        </div>
      )}

      {actionMsg.text && (
        <div className="text-sm px-4 py-3 rounded-xl flex items-center gap-2" style={msgStyle[actionMsg.type]}>
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            {actionMsg.type === 'success'
              ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              : actionMsg.type === 'error'
              ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            }
          </svg>
          {actionMsg.text}
        </div>
      )}

      {/* Filtres */}
      <div style={CARD} className="px-5 py-3.5 flex flex-wrap gap-3 items-center">
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Filtres</span>
        <input type="text" value={filters.search} onChange={e => setFilter('search', e.target.value)}
          placeholder="Rechercher une CVE…"
          className="font-mono"
          style={{ ...selectStyle, cursor: 'text', width: 190 }}
        />
        {assetList.length > 0 && (
          <AssetDropdown assetList={assetList} selected={selectedAssetIds} onChange={ids => { setSelectedAssetIds(ids); setPage(1) }} />
        )}
        <select value={filters.status} onChange={e => setFilter('status', e.target.value)} style={filters.status !== 'open' ? activeSelectStyle : selectStyle}>
          <option value="">Tous statuts</option>
          {STATUSES.slice(1).map(s => <option key={s} value={s}>{STATUS_LABELS[s] || s}</option>)}
        </select>
        <select value={filters.severity} onChange={e => setFilter('severity', e.target.value)} style={filters.severity ? activeSelectStyle : selectStyle}>
          <option value="">Toutes sévérités</option>
          {SEVERITIES.slice(1).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filters.validated_by} onChange={e => setFilter('validated_by', e.target.value)} style={filters.validated_by ? activeSelectStyle : selectStyle}>
          <option value="">Tous valideurs</option>
          {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
        </select>
        <label className="flex items-center gap-1.5 cursor-pointer select-none ml-1"
          title="Masque les CVE publiées il y a plus de 2 ans — affichage uniquement, ne supprime ni ne désactive rien en base"
        >
          <input type="checkbox" checked={!!filters.max_age_years}
            onChange={e => setFilter('max_age_years', e.target.checked ? 2 : '')}
            className="w-3.5 h-3.5 accent-blue-500"
          />
          <span className="text-xs font-medium" style={{ color: filters.max_age_years ? '#58a6ff' : 'var(--text-secondary)' }}>
            Masquer les CVE {'>'} 2 ans
          </span>
        </label>
        <label className="flex items-center gap-1.5 cursor-pointer select-none"
          title="CISA KEV — exploitation active confirmée dans la nature"
        >
          <input type="checkbox" checked={filters.kev}
            onChange={e => setFilter('kev', e.target.checked)}
            className="w-3.5 h-3.5"
            style={{ accentColor: '#f85149' }}
          />
          <span className="text-xs font-medium" style={{ color: filters.kev ? '#f85149' : 'var(--text-secondary)' }}>
            ⚠ KEV
          </span>
        </label>
        <label className="flex items-center gap-1.5 cursor-pointer select-none"
          title="Module Metasploit disponible"
        >
          <input type="checkbox" checked={filters.msf_module}
            onChange={e => setFilter('msf_module', e.target.checked)}
            className="w-3.5 h-3.5"
            style={{ accentColor: '#a371f7' }}
          />
          <span className="text-xs font-medium" style={{ color: filters.msf_module ? '#a371f7' : 'var(--text-secondary)' }}>
            Metasploit
          </span>
        </label>
        {hasFilters && (
          <button onClick={() => { setFilters({ status: '', severity: '', validated_by: '', max_age_years: '', search: '', kev: false, msf_module: false }); setSelectedAssetIds([]); setPage(1) }}
            className="text-xs px-2.5 py-1.5 rounded-lg transition-colors"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
          >Réinitialiser</button>
        )}
      </div>

      {/* Tableau (desktop) / cartes (mobile, < 640px) — la table en scroll horizontal est
          illisible sur un écran de téléphone vu le nombre de colonnes et d'actions par ligne. */}
      <div style={CARD} className="overflow-hidden">
        <div className="hidden sm:block overflow-x-auto" style={{ background: 'var(--bg-card)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                {['CVE', 'Actif', 'Statut'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                ))}
                <SortHeader label="Sévérité" col="severity" sort={sort} onSort={handleSort} />
                <SortHeader label="Score"    col="score"    sort={sort} onSort={handleSort} />
                <SortHeader label="Publié"   col="date"     sort={sort} onSort={handleSort} />
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Détecté</th>
                {showPatchedAt   && <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Date patch</th>}
                {showValidatedBy && <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Validé par</th>}
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Actions</th>
              </tr>
            </thead>
            <tbody className="stagger-rows">
              {loading && (
                <tr><td colSpan={10} className="px-4 py-12 text-center"><PageLoader size="sm" /></td></tr>
              )}
              {!loading && data.items.length === 0 && (
                <tr><td colSpan={10} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucune vulnérabilité</td></tr>
              )}
              {!loading && data.items.map(v => (
                <tr key={v.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = MODULE_HOVER}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve?.cve_id}`} target="_blank" rel="noopener noreferrer" className="hover:underline">{v.cve?.cve_id}</a>
                    {v.resolved_elsewhere_count > 0 && <span className="ml-2">{renderOtherInstancesBadge(v)}</span>}
                  </td>
                  <td className="px-4 py-3" style={{ color: 'var(--text-secondary)' }}>
                    <div className="flex items-center gap-2">
                      <ConnectivityDot assetType={v.asset?.asset_type} reachable={v.asset?.scan_reachable} error={v.asset?.scan_error} />
                      {v.asset?.name}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <StatusBadge value={v.status} />
                      {v.review_overdue && (
                        <span className="font-bold" style={{ color: '#f85149' }} title={`Revue de risque accepté en retard (échéance : ${v.accepted_risk_until ? new Date(v.accepted_risk_until).toLocaleDateString('fr-FR') : '?'})`}>⚠</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div style={{ display: 'inline-grid', justifyItems: 'start', gap: 4, position: 'relative' }}>
                      <SeverityBadge value={v.cve?.severity} />
                      <ExploitBadge kev={v.cve?.kev} kevRansomware={v.cve?.kev_ransomware} msfModule={v.cve?.msf_module} msfRank={v.cve?.msf_best_rank} compact spread />
                    </div>
                  </td>
                  <td className="px-4 py-3 font-semibold" style={{ color: 'var(--text-primary)' }}>{v.cve?.cvss_score ?? '—'}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {v.cve?.published ? new Date(v.cve.published).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {v.detected_at ? new Date(v.detected_at).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  {showPatchedAt && (
                    <td className="px-4 py-3 text-xs">
                      {v.patched_at
                        ? <span className="font-semibold" style={{ color: '#3fb950' }}>{new Date(v.patched_at).toLocaleDateString('fr-FR')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>—</span>
                      }
                    </td>
                  )}
                  {showValidatedBy && (
                    <td className="px-4 py-3 text-xs">
                      {v.validated_by
                        ? <span className="px-2 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{v.validated_by}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                  )}
                  <td className="px-4 py-3">
                    {renderActions(v)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Vue carte mobile — mêmes données/actions que la table, une carte par ligne
            plutôt qu'un scroll horizontal illisible sur un écran de téléphone. */}
        <div className="sm:hidden divide-y" style={{ borderColor: 'var(--border)' }}>
          {loading && (
            <div className="px-4 py-12 text-center"><PageLoader size="sm" /></div>
          )}
          {!loading && data.items.length === 0 && (
            <div className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucune vulnérabilité</div>
          )}
          {!loading && data.items.map(v => (
            <div key={v.id} className="p-4 space-y-2.5">
              <div className="flex items-start justify-between gap-2">
                <a href={`https://nvd.nist.gov/vuln/detail/${v.cve?.cve_id}`} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-sm font-semibold hover:underline" style={{ color: '#58a6ff' }}>{v.cve?.cve_id}</a>
                <div className="flex items-center gap-1.5 flex-wrap justify-end">
                  <SeverityBadge value={v.cve?.severity} />
                  <ExploitBadge kev={v.cve?.kev} kevRansomware={v.cve?.kev_ransomware} msfModule={v.cve?.msf_module} msfRank={v.cve?.msf_best_rank} />
                </div>
              </div>
              <p className="text-sm truncate flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
                <ConnectivityDot assetType={v.asset?.asset_type} reachable={v.asset?.scan_reachable} error={v.asset?.scan_error} />
                {v.asset?.name}
              </p>
              <div className="flex items-center gap-2 flex-wrap">
                <StatusBadge value={v.status} />
                {v.review_overdue && (
                  <span className="font-bold" style={{ color: '#f85149' }} title={`Revue de risque accepté en retard (échéance : ${v.accepted_risk_until ? new Date(v.accepted_risk_until).toLocaleDateString('fr-FR') : '?'})`}>⚠ Revue en retard</span>
                )}
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Score {v.cve?.cvss_score ?? '—'}</span>
                {v.resolved_elsewhere_count > 0 && renderOtherInstancesBadge(v)}
              </div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                <span>Publié : {v.cve?.published ? new Date(v.cve.published).toLocaleDateString('fr-FR') : '—'}</span>
                <span>Détecté : {v.detected_at ? new Date(v.detected_at).toLocaleDateString('fr-FR') : '—'}</span>
                {showPatchedAt && (
                  <span>Patché : {v.patched_at ? new Date(v.patched_at).toLocaleDateString('fr-FR') : '—'}</span>
                )}
                {showValidatedBy && (
                  <span>Validé par : {v.validated_by || '—'}</span>
                )}
              </div>
              {renderActions(v)}
            </div>
          ))}
        </div>

        {totalPages > 1 && (
          <div className="px-5 py-3.5 flex items-center justify-between text-sm" style={{ borderTop: '1px solid var(--border)' }}>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{data.total} résultats</span>
            <div className="flex items-center gap-2">
              <Btn variant="secondary" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Préc.</Btn>
              <span className="text-xs px-2" style={{ color: 'var(--text-muted)' }}>Page {page} / {totalPages}</span>
              <Btn variant="secondary" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Suiv. →</Btn>
            </div>
          </div>
        )}
      </div>

      {analysisModal && (
        <AnalysisModal data={analysisModal} onClose={() => setAnalysisModal(null)} />
      )}

      {detailModal && (
        <AnnotationDetailModal
          vuln={detailModal.vuln}
          label={detailModal.label}
          color={detailModal.color}
          date={detailModal.date}
          blocks={detailModal.blocks}
          title={detailModal.title}
          onClose={() => setDetailModal(null)}
        />
      )}

      {historyModal && (
        <StatusHistoryModal
          cveId={historyModal.cveId}
          entries={historyModal.entries}
          loading={historyModal.loading}
          onClose={() => setHistoryModal(null)}
        />
      )}

      {otherInstancesModal && (
        <OtherInstancesModal
          cveId={otherInstancesModal.cveId}
          entries={otherInstancesModal.entries}
          loading={otherInstancesModal.loading}
          onClose={() => setOtherInstancesModal(null)}
          onReuse={note => handleReuseJustification(otherInstancesModal.vulnId, note)}
        />
      )}

      {fpModalOpen && (
        <BulkQualifyModal
          items={fpCandidates}
          onClose={() => setFpModalOpen(false)}
          apiCall={bulkFalsePositive}
          onDone={handleFpConfirm}
          autoJustification
        />
      )}

      {afModalOpen && (
        <BulkQualifyModal
          items={afCandidates}
          onClose={() => setAfModalOpen(false)}
          apiCall={bulkAwaitingFix}
          onDone={handleAfConfirm}
          titre="Qualification groupée — en attente de correctif"
          sousTitre="CVE sans correctif publié par la distribution"
          couleur="#d29922"
          confirmLabel="⏳ Marquer en attente"
        />
      )}

      {bulkModalOpen && (
        <BulkValidateModal items={bulkCandidates} onClose={() => setBulkModalOpen(false)} onConfirm={handleBulkConfirm} />
      )}

      {arModalOpen && (
        <BulkQualifyModal
          items={arCandidates}
          onClose={() => setArModalOpen(false)}
          apiCall={bulkAcceptedRisk}
          onDone={handleArConfirm}
          titre="Risque accepté groupé"
          sousTitre="vulnérabilités sélectionnées sur la page affichée"
          couleur="#e3b341"
          confirmLabel="🛡 Accepter le risque"
          showReviewDate
        />
      )}

      {acceptRiskModal && (
        <AnnotationModal
          title="🛡 Accepter le risque"
          detail={acceptRiskModal.cve?.cve_id}
          subtitle={acceptRiskModal.asset?.name}
          color="#8b949e"
          helpText="Justification obligatoire — pourquoi ce risque est accepté plutôt que corrigé (versée à la piste d'audit NIS 2)."
          placeholder="Ex : correctif prévu au prochain fenêtre de maintenance, impact jugé acceptable au regard de l'exposition réelle de l'actif…"
          confirmLabel="Accepter le risque"
          noteRequired
          showReviewDate
          onConfirm={handleAcceptRiskConfirm}
          onClose={() => setAcceptRiskModal(null)}
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

              {patchModal.result?.error && (
                <div className="p-4 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)' }}>
                  <p className="font-semibold text-sm mb-1" style={{ color: '#f85149' }}>Erreur de connexion</p>
                  <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{patchModal.result.error}</p>
                </div>
              )}

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
                      Windows). Absent tant qu'aucune donnée build_installed n'est retournée
                      (actifs Linux, ou erreur WinRM en amont du calcul). */}
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
                          ? <p className="whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>{patchModal.vuln.notes}</p>
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
                      tiers plutôt que l'OS lui-même. Affiche explicitement la plage visée par
                      la CVE, pas seulement la version installée (demande utilisateur : le
                      verdict seul ne dit pas contre quoi la version a été comparée). */}
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

                  {/* Signal 3 — repli par date (session 20/07/2026) : uniquement affiché quand
                      build_verdict est indéterminé (pas de plage de version NVD/MSRC exploitable
                      pour cette CVE, cas fréquent pour les CVE anciennes). Purement indicatif —
                      n'a jamais fait basculer patch_detected, jamais d'auto-bascule non plus ;
                      couleur bleue "info" plutôt que vert/rouge pour ne pas être confondu avec un
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
                          return (
                            <div key={kb} className="flex items-center justify-between px-3 py-1.5 rounded-lg text-xs" style={{ background: 'var(--bg-secondary)' }}>
                              <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{kb}</span>
                              <span style={{ color: installed ? '#3fb950' : '#f85149' }}>{installed ? '✓ Installé' : '✗ Manquant'}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
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
                          services/patch_checker.py::apply_patch_result — dupliquer un
                          relevé identique sur chaque vuln de l'actif gonflerait la
                          base pour rien), donc indisponibles tant qu'on ne relance
                          pas un vrai contrôle. */}
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
                      <ValidateDropdown
                        detected={true}
                        label="✓ Marquer comme corrigé"
                        initialNote={patchModal.result.details || ''}
                        onSelect={(name, note) => { handleMarkPatched(patchModal.vuln, name, note); setPatchModal(null) }}
                      />
                    ) : (
                      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Applique le correctif sur le serveur, puis relance le patch check pour confirmer.</p>
                    )}
                  </div>

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

      {/* Modal recommandation / script */}
      {modal && (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={() => setModal(null)}>
          <div className="max-w-2xl w-full max-h-[80vh] flex flex-col rounded-2xl animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>
                {modal.type === 'recommend' ? 'Plan de remédiation' : `Script ${modal.script_type}`}
              </h2>
              <div className="flex items-center gap-3">
                {modal.type === 'script' && (
                  <span className="text-xs px-2.5 py-1 rounded-full font-medium" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                    Tester en recette avant production
                  </span>
                )}
                <button onClick={() => setModal(null)} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
            </div>
            <div className="overflow-y-auto p-6 flex-1">
              {modal.type === 'recommend' && typeof modal.content === 'object' && !modal.content.parse_error ? (
                <div className="space-y-4 text-sm">
                  <div className="p-4 rounded-xl" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                    <p className="font-semibold mb-2.5" style={{ color: 'var(--text-secondary)' }}>Étapes</p>
                    <ol className="list-decimal list-inside space-y-1.5" style={{ color: 'var(--text-muted)' }}>
                      {(modal.content.steps || []).map((s, i) => <li key={i}>{s}</li>)}
                    </ol>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    {modal.content.kb_or_package && (
                      <div className="p-3 rounded-xl" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.15)' }}>
                        <p className="text-xs font-semibold uppercase mb-1" style={{ color: '#58a6ff' }}>KB / Paquet</p>
                        <p style={{ color: 'var(--text-primary)' }}>{modal.content.kb_or_package}</p>
                      </div>
                    )}
                    <div className="p-3 rounded-xl" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                      <p className="text-xs font-semibold uppercase mb-1" style={{ color: 'var(--text-muted)' }}>Redémarrage requis</p>
                      <p className="font-medium" style={{ color: modal.content.reboot_required ? '#f85149' : '#3fb950' }}>
                        {modal.content.reboot_required ? '⚠ Oui' : '✓ Non'}
                      </p>
                    </div>
                    {modal.content.verification_cmd && (
                      <div className="p-3 rounded-xl col-span-2" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                        <p className="text-xs font-semibold uppercase mb-2" style={{ color: 'var(--text-muted)' }}>Commande de vérification</p>
                        <code className="text-xs block p-2 rounded-lg overflow-x-auto" style={{ background: 'var(--bg-app)', color: '#3fb950' }}>{modal.content.verification_cmd}</code>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <pre className="text-xs font-mono p-4 rounded-xl overflow-x-auto whitespace-pre-wrap leading-relaxed" style={{ background: 'var(--bg-app)', color: '#3fb950' }}>
                  {typeof modal.content === 'string' ? modal.content : JSON.stringify(modal.content, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
