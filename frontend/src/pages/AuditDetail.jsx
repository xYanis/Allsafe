import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  getAudit, updateAudit, deleteAudit, authorizeAudit, assets as fetchAssets,
  linkAuditAsset, unlinkAuditAsset, auditFindings, createAuditFinding, updateAuditFinding,
  deleteAuditFinding, auditAttachments, uploadAuditAttachment, auditAttachmentDownloadUrl,
  getAuditReport,
} from '../api/client.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'
import PageLoader from '../components/PageLoader.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ConfirmModal from '../components/ConfirmModal.jsx'
import DeclareIncidentButton from '../components/DeclareIncidentButton.jsx'
import AuditFindingModal, { FINDING_STATUSES } from '../components/AuditFindingModal.jsx'
import { AUDIT_TYPES, AUDIT_METHODOLOGIES, AUDIT_STATUSES } from '../components/AuditFormModal.jsx'
import { renderMd, exportPdf } from '../components/ReportMarkdown.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'
import { isSyntheticId, SYNTHETIC_AUDITS, SYNTHETIC_AUDIT_FINDINGS, anonymizeAudit, anonymizeAuditFinding, anonymizeAsset } from '../utils/syntheticData.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'

const MODULE_COLOR = MODULES.securite.color
const CARD = tintedCard(MODULE_COLOR)
const field = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }
const inputCls = 'w-full text-sm rounded-lg px-3 py-2 outline-none'

const FINDING_STATUS_LABELS = Object.fromEntries(FINDING_STATUSES.map(s => [s.value, s.label]))
const FINDING_STATUS_STYLES = {
  ouvert:                 { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' },
  remediation_planifiee:  { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  corrige:                { background: 'rgba(63,185,80,0.12)',  color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
  risque_accepte:         { background: 'rgba(163,113,247,0.12)',color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
  faux_positif:           { background: 'rgba(139,148,158,0.12)',color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
}
function FindingStatusBadge({ value }) {
  const s = FINDING_STATUS_STYLES[value] || FINDING_STATUS_STYLES.ouvert
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>{FINDING_STATUS_LABELS[value] || value}</span>
}

function AuthorizeForm({ audit, onAuthorized }) {
  const { names } = useAnalysts()
  const [scope, setScope] = useState('')
  const [roe, setRoe] = useState('')
  const [authorizedBy, setAuthorizedBy] = useState('')
  const [authorizedAt, setAuthorizedAt] = useState(new Date().toISOString().slice(0, 10))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const missing = !scope.trim() || !roe.trim() || !authorizedBy

  async function submit() {
    if (missing || saving) return
    setSaving(true)
    setError('')
    try {
      const { data } = await authorizeAudit(audit.id, {
        scope: scope.trim(), rules_of_engagement: roe.trim(),
        authorized_by: authorizedBy, authorized_at: new Date(authorizedAt).toISOString(),
      })
      onAuthorized(data)
    } catch (e) {
      setError(e?.response?.data?.detail || "Erreur lors de l'autorisation.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={CARD} className="p-6 space-y-3">
      <div>
        <h2 className="font-semibold" style={{ color: '#d29922' }}>⚠ Audit non autorisé</h2>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Aucun finding ne peut être saisi tant que le périmètre, les règles d'engagement et le mandataire ne sont pas posés.
          Ces champs deviennent immuables une fois enregistrés.
        </p>
      </div>
      <div>
        <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Périmètre technique</label>
        <textarea value={scope} onChange={e => setScope(e.target.value)} rows={2} className={`${inputCls} resize-none`} style={field} placeholder="Ce qui est dans le périmètre de l'audit…" />
      </div>
      <div>
        <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Règles d'engagement</label>
        <textarea value={roe} onChange={e => setRoe(e.target.value)} rows={2} className={`${inputCls} resize-none`} style={field} placeholder="Ce qui est permis et interdit (horaires, DoS, ingénierie sociale…)" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Mandaté par</label>
          <select value={authorizedBy} onChange={e => setAuthorizedBy(e.target.value)} className={inputCls} style={field}>
            <option value="">Sélectionner…</option>
            {names.map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Le</label>
          <input type="date" value={authorizedAt} onChange={e => setAuthorizedAt(e.target.value)} className={inputCls} style={field} />
        </div>
      </div>
      {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
      <div className="flex justify-end">
        <button onClick={submit} disabled={missing || saving}
          className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
          style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' }}>
          {saving ? 'Autorisation…' : "Autoriser l'audit"}
        </button>
      </div>
    </div>
  )
}

function MandateCard({ auditId, attachments, onUploaded }) {
  const { names } = useAnalysts()
  const [uploadedBy, setUploadedBy] = useState('')
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    if (!file || !uploadedBy) return
    setUploading(true)
    setError('')
    try {
      const { data } = await uploadAuditAttachment(auditId, file, uploadedBy)
      onUploaded(data)
    } catch (e2) {
      setError(e2?.response?.data?.detail || "Erreur lors de l'upload.")
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  return (
    <div className="mt-3 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
      <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Mandat écrit</p>
      <div className="space-y-1 mb-2">
        {attachments.length === 0 && <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun mandat joint.</p>}
        {attachments.map(a => (
          <a key={a.id} href={auditAttachmentDownloadUrl(auditId, a.id)} target="_blank" rel="noreferrer"
            className="flex items-center justify-between text-xs px-2.5 py-1.5 rounded-lg"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
            <span>{a.filename}</span><span style={{ color: 'var(--text-muted)' }}>{(a.size_bytes / 1024).toFixed(0)} Ko</span>
          </a>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <select value={uploadedBy} onChange={e => setUploadedBy(e.target.value)} className="text-xs rounded-lg px-2.5 py-1.5 outline-none" style={field}>
          <option value="">Analyste…</option>
          {names.map(n => <option key={n} value={n}>{n}</option>)}
        </select>
        <label className="text-xs px-2.5 py-1.5 rounded-lg font-medium cursor-pointer"
          style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', opacity: uploadedBy ? 1 : 0.5 }}>
          {uploading ? 'Envoi…' : '+ Joindre (PDF/PNG/JPEG)'}
          <input type="file" accept=".pdf,.png,.jpg,.jpeg" onChange={handleUpload} disabled={!uploadedBy || uploading} className="hidden" />
        </label>
      </div>
      {error && <p className="text-xs mt-1" style={{ color: '#f85149' }}>{error}</p>}
    </div>
  )
}

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Clé = id (route dynamique) pour ne jamais afficher un instant les données d'un autre
// audit en rouvrant une page déjà visitée pour un id différent. `fetchAssets()` a son
// propre cache simple (pas de clé, le parc d'actifs est le même pour tout le monde).
let auditDetailCache = {}
let auditDetailAssetsCache = null

export default function AuditDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { names } = useAnalysts()
  // Suppression (audit + finding) réservée admin côté serveur (03/08/2026, audit
  // sécurité) — masqué ici pour ne pas laisser un compte analyst se heurter à un 403
  // après confirmation.
  const { user } = useAuth()
  const { isAnonymous } = usePresentation()
  const isSynthetic = isSyntheticId(id)
  // Un audit RÉEL reste entièrement fonctionnel en mode Présentation (édition, findings,
  // mandat...) — seul l'AFFICHAGE est masqué (21/08/2026, retour utilisateur : cette page ne
  // gérait jusqu'ici que les audits de démonstration via isSyntheticId, un audit réel s'ouvrait en
  // clair). Les handlers de mutation (saveEdit, handleCreateFinding...) continuent de lire/écrire
  // sur `audit`/`findings` (les vraies données) — ne jamais leur passer les versions `display*`
  // ci-dessous sous peine d'écraser un vrai enregistrement avec du texte anonymisé/fictif.
  const maskReal = isAnonymous && !isSynthetic
  const canDelete = user?.role === 'admin' && !isSynthetic
  const cached = auditDetailCache[id]
  const [audit, setAudit] = useState(() => cached?.audit ?? null)
  const [findings, setFindings] = useState(() => cached?.findings ?? [])
  const [assetList, setAssetList] = useState(() => auditDetailAssetsCache ?? [])
  const [attachments, setAttachments] = useState(() => cached?.attachments ?? [])
  const [loading, setLoading] = useState(() => cached == null)
  const [error, setError] = useState('')

  const [editing, setEditing] = useState(false)
  const [editForm, setEditForm] = useState(null)
  const [findingModal, setFindingModal] = useState(false)   // false=fermé, null=création, objet=édition
  const [deleteFinding, setDeleteFinding] = useState(null)
  const [deleteAuditModal, setDeleteAuditModal] = useState(false)
  const [addAssetId, setAddAssetId] = useState('')
  const [summary, setSummary] = useState(() => cached?.audit?.executive_summary || '')
  const [summaryEdit, setSummaryEdit] = useState(false)
  const [summarySaving, setSummarySaving] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
  const [reportText, setReportText] = useState('')
  const [reportLoading, setReportLoading] = useState(false)

  const load = useCallback(() => {
    // Audit de démonstration (mode Présentation) : n'existe pas en base, résolu côté client.
    if (isSynthetic) {
      const a = SYNTHETIC_AUDITS.find(x => x.id === id)
      if (!a) { setError('Audit introuvable.'); setLoading(false); return }
      const findingsData = SYNTHETIC_AUDIT_FINDINGS[id] || []
      setAudit(a); setFindings(findingsData); setAttachments([])
      setSummary(a.executive_summary || '')
      setLoading(false)
      return
    }
    setLoading(true)
    Promise.all([getAudit(id), auditFindings(id), auditAttachments(id)])
      .then(([a, f, att]) => {
        const findingsData = f.data.items || []
        const attachmentsData = att.data.items || []
        setAudit(a.data)
        setFindings(findingsData)
        setAttachments(attachmentsData)
        setSummary(a.data.executive_summary || '')
        auditDetailCache[id] = { audit: a.data, findings: findingsData, attachments: attachmentsData }
      })
      .catch(() => setError('Audit introuvable.'))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    fetchAssets().then(r => {
      const sorted = [...(r.data || [])].sort((a, b) => a.name.localeCompare(b.name))
      setAssetList(sorted)
      auditDetailAssetsCache = sorted
    }).catch(() => {})
  }, [])

  function startEdit() {
    setEditForm({
      title: audit.title, type: audit.type, methodology: audit.methodology || '',
      referential: audit.referential || '', conducted_by: audit.conducted_by || '',
      started_at: audit.started_at ? audit.started_at.slice(0, 10) : '',
      ended_at: audit.ended_at ? audit.ended_at.slice(0, 10) : '',
    })
    setEditing(true)
  }

  async function saveEdit() {
    const { data } = await updateAudit(id, {
      title: editForm.title, type: editForm.type, methodology: editForm.methodology || null,
      referential: editForm.referential || null, conducted_by: editForm.conducted_by || null,
      started_at: editForm.started_at ? new Date(editForm.started_at).toISOString() : null,
      ended_at: editForm.ended_at ? new Date(editForm.ended_at).toISOString() : null,
    })
    setAudit(a => ({ ...a, ...data }))
    setEditing(false)
  }

  async function changeStatus(newStatus) {
    const { data } = await updateAudit(id, { status: newStatus })
    setAudit(a => ({ ...a, ...data }))
  }

  async function handleDeleteAudit() {
    await deleteAudit(id)
    navigate('/audits')
  }

  async function handleAddAsset() {
    if (!addAssetId) return
    await linkAuditAsset(id, addAssetId)
    setAddAssetId('')
    load()
  }
  async function handleRemoveAsset(assetId) {
    await unlinkAuditAsset(id, assetId)
    load()
  }

  async function handleCreateFinding(payload) {
    await createAuditFinding(id, payload)
    setFindingModal(false)
    load()
  }
  async function handleUpdateFinding(payload) {
    if (payload) await updateAuditFinding(id, findingModal.id, payload)
    setFindingModal(false)
    load()
  }
  async function handleDeleteFinding() {
    await deleteAuditFinding(id, deleteFinding.id)
    setDeleteFinding(null)
    load()
  }

  async function saveSummary() {
    setSummarySaving(true)
    try {
      const { data } = await updateAudit(id, { executive_summary: summary })
      setAudit(a => ({ ...a, ...data }))
      setSummaryEdit(false)
    } finally {
      setSummarySaving(false)
    }
  }

  function handleOpenReport() {
    if (reportOpen) { setReportOpen(false); return }
    // Audit de démonstration OU audit réel en mode Présentation (21/08/2026, retour
    // utilisateur — le 2e cas appelait jusqu'ici le vrai `getAuditReport`, renvoyant le rapport
    // en clair) : rapport reconstruit côté client depuis les données déjà masquées à l'affichage
    // (mêmes ingrédients que services/audit_report.py — titre, périmètre, synthèse, findings —
    // pas d'appel API).
    if (isSynthetic || maskReal) {
      const lines = [
        `# ${displayAudit.title}`, '',
        `**Type** : ${AUDIT_TYPES.find(t => t.value === displayAudit.type)?.label || displayAudit.type} — **Référentiel** : ${displayAudit.referential || 'non précisé'}`, '',
        '## Périmètre', displayAudit.scope || 'Non précisé.', '',
        '## Synthèse exécutive', displayAudit.executive_summary || 'Non rédigée.', '',
        '## Findings',
        ...displayFindings.map(f => `- **[${f.severity}]** ${f.title} — ${FINDING_STATUS_LABELS[f.status] || f.status}`),
      ]
      setReportText(lines.join('\n'))
      setReportOpen(true)
      return
    }
    setReportLoading(true)
    getAuditReport(id).then(r => { setReportText(r.data.summary || ''); setReportOpen(true) }).finally(() => setReportLoading(false))
  }

  if (loading && !audit) return <PageLoader />
  if (error || !audit) {
    return (
      <div className="p-6">
        <p className="text-sm" style={{ color: '#f85149' }}>{error || 'Audit introuvable.'}</p>
        <Link to="/audits" className="text-xs mt-2 inline-block" style={{ color: MODULE_COLOR }}>← Retour aux audits</Link>
      </div>
    )
  }

  const isAuthorized = !!audit.authorized_by
  // `display*` : copies purement pour l'affichage (texte libre/noms redigés via redactText/
  // anonymizeValidator, cf. utils/syntheticData.js) — mêmes ids/statuts/dates que les vraies données,
  // jamais utilisées pour construire un payload de mutation (cf. note plus haut).
  const displayAudit = maskReal ? anonymizeAudit(audit, assetList) : audit
  const displayFindings = maskReal ? findings.map(f => anonymizeAuditFinding(f, assetList)) : findings
  const displayAssetList = isAnonymous ? assetList.map(anonymizeAsset) : assetList
  const displayAttachments = maskReal ? attachments.map(a => ({ ...a, filename: 'mandat.pdf' })) : attachments
  const unavailableAssetList = displayAssetList.filter(a => !audit.asset_ids.includes(a.id))
  const flagged = audit.status === 'termine' && findings.some(f => (f.status === 'ouvert') || (['corrige', 'risque_accepte'].includes(f.status) && !f.retested_at))

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
        <Link to="/audits" style={{ color: MODULE_COLOR }}>Audits</Link> / {displayAudit.title}
      </div>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{displayAudit.title}</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {AUDIT_TYPES.find(t => t.value === audit.type)?.label} · {audit.referential || 'Référentiel non précisé'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isAuthorized && !isSynthetic && (
            <select value={audit.status} onChange={e => changeStatus(e.target.value)}
              className="text-xs px-2.5 py-1.5 rounded-lg outline-none" style={field}>
              {AUDIT_STATUSES.filter(s => s.value !== 'cadrage' && s.value !== 'autorise').map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              {audit.status === 'autorise' && <option value="autorise">Autorisé</option>}
            </select>
          )}
          {isAuthorized && isSynthetic && (
            <span className="text-xs px-2.5 py-1 rounded-lg font-medium" style={field}>{AUDIT_STATUSES.find(s => s.value === audit.status)?.label || audit.status}</span>
          )}
          {!isSynthetic && (
            <button onClick={startEdit} className="text-xs px-3 py-1.5 rounded-lg font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>Modifier</button>
          )}
          {canDelete && (
            <button onClick={() => setDeleteAuditModal(true)} className="text-xs px-3 py-1.5 rounded-lg font-medium" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>Supprimer</button>
          )}
        </div>
      </div>

      {flagged && (
        <div className="px-4 py-3 rounded-xl text-sm" style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' }}>
          ⚠ Audit terminé avec des findings ouverts ou clos jamais retestés — la contre-vérification n'est pas complète.
        </div>
      )}

      {editing && (
        <div style={CARD} className="p-6 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Titre</label>
              <input value={editForm.title} onChange={e => setEditForm(f => ({ ...f, title: e.target.value }))} className={inputCls} style={field} />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Type</label>
              <select value={editForm.type} onChange={e => setEditForm(f => ({ ...f, type: e.target.value }))} className={inputCls} style={field}>
                {AUDIT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Méthodologie</label>
              <select value={editForm.methodology} onChange={e => setEditForm(f => ({ ...f, methodology: e.target.value }))} className={inputCls} style={field}>
                <option value="">—</option>
                {AUDIT_METHODOLOGIES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Référentiel</label>
              <input value={editForm.referential} onChange={e => setEditForm(f => ({ ...f, referential: e.target.value }))} className={inputCls} style={field} />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Conduit par</label>
              <select value={editForm.conducted_by} onChange={e => setEditForm(f => ({ ...f, conducted_by: e.target.value }))} className={inputCls} style={field}>
                <option value="">—</option>
                {names.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Début</label>
              <input type="date" value={editForm.started_at} onChange={e => setEditForm(f => ({ ...f, started_at: e.target.value }))} className={inputCls} style={field} />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Fin</label>
              <input type="date" value={editForm.ended_at} onChange={e => setEditForm(f => ({ ...f, ended_at: e.target.value }))} className={inputCls} style={field} />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={() => setEditing(false)} className="text-xs px-3 py-2 rounded-lg font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Annuler</button>
            <button onClick={saveEdit} className="text-xs px-3 py-2 rounded-lg font-medium" style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' }}>Enregistrer</button>
          </div>
        </div>
      )}

      {!isAuthorized ? (
        <AuthorizeForm audit={audit} onAuthorized={data => setAudit(a => ({ ...a, ...data }))} />
      ) : (
        <div style={CARD} className="p-6">
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Cadrage et autorisation</h2>
          <div className="mt-3 space-y-2 text-sm">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-muted)' }}>Périmètre</p>
              <p style={{ color: 'var(--text-secondary)' }}>{displayAudit.scope}</p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-muted)' }}>Règles d'engagement</p>
              <p style={{ color: 'var(--text-secondary)' }}>{displayAudit.rules_of_engagement}</p>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Autorisé par <strong style={{ color: 'var(--text-secondary)' }}>{displayAudit.authorized_by}</strong> le {new Date(audit.authorized_at).toLocaleDateString('fr-FR')} — champs verrouillés.
            </p>
          </div>
          {!isSynthetic && <MandateCard auditId={id} attachments={displayAttachments} onUploaded={a => setAttachments(x => [...x, a])} />}
        </div>
      )}

      <div style={CARD} className="p-6">
        <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Actifs ciblés</h2>
        <div className="flex flex-wrap gap-1.5 mt-3">
          {displayAudit.asset_names.length === 0 && <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun actif rattaché.</p>}
          {audit.asset_ids.map((aid, i) => (
            <span key={aid} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
              {displayAudit.asset_names[i]}
              {!isSynthetic && <button onClick={() => handleRemoveAsset(aid)} style={{ color: 'var(--text-muted)' }}>×</button>}
            </span>
          ))}
        </div>
        {!isSynthetic && (
          <div className="flex items-center gap-2 mt-3">
            <select value={addAssetId} onChange={e => setAddAssetId(e.target.value)} className="text-xs rounded-lg px-2.5 py-1.5 outline-none" style={field}>
              <option value="">Ajouter un actif…</option>
              {unavailableAssetList.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <button onClick={handleAddAsset} disabled={!addAssetId} className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-50" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>Ajouter</button>
          </div>
        )}
      </div>

      <div style={CARD} className="overflow-hidden">
        <div className="px-6 py-4 flex items-center justify-between flex-wrap gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Findings ({displayFindings.length})</h2>
          {!isSynthetic && (
            <button onClick={() => setFindingModal(null)} disabled={!isAuthorized}
              title={!isAuthorized ? "Autoriser l'audit avant de saisir un finding" : undefined}
              className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-40"
              style={{ background: MODULE_COLOR, color: MODULES.securite.dark }}>
              + Ajouter un finding
            </button>
          )}
        </div>
        {displayFindings.length === 0 ? (
          <p className="px-6 py-8 text-sm text-center" style={{ color: 'var(--text-muted)' }}>
            {isAuthorized ? 'Aucun finding saisi.' : 'Findings verrouillés tant que l’audit n’est pas autorisé.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Sévérité', 'Titre', 'Actif', 'CVE', 'Statut', 'Retest', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {/* `f` = finding déjà anonymisé pour l'affichage. `realFinding` = objet réel
                    correspondant (même id) passé aux actions d'édition — jamais `f` directement,
                    sous peine d'enregistrer du texte anonymisé/fictif comme vraie valeur au
                    prochain "Enregistrer" (cf. note maskReal en tête de fichier). */}
                {displayFindings.map(f => {
                  const realFinding = maskReal ? findings.find(rf => rf.id === f.id) : f
                  return (
                  <tr key={f.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td className="px-4 py-3"><SeverityBadge value={f.severity} /></td>
                    <td className={`px-4 py-3 font-medium ${isSynthetic ? '' : 'cursor-pointer'}`} style={{ color: 'var(--text-primary)' }} onClick={() => !isSynthetic && setFindingModal(realFinding)}>{f.title}</td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{f.affected_asset_name || '—'}</td>
                    <td className="px-4 py-3 text-xs">
                      {f.cve_id ? <Link to={`/vulnerabilities?cve=${f.cve_id}`} style={{ color: MODULE_COLOR }}>{f.cve_id}</Link> : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td className="px-4 py-3"><FindingStatusBadge value={f.status} /></td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {f.retested_at ? new Date(f.retested_at).toLocaleDateString('fr-FR') : (['corrige', 'risque_accepte'].includes(f.status) ? '⚠ non retesté' : '—')}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {!isSynthetic && (
                          <>
                            <button onClick={() => setFindingModal(realFinding)} className="text-xs px-2 py-1 rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>Modifier</button>
                            <DeclareIncidentButton sourceType="audit_finding" sourceId={f.id} label="Déclarer un incident" />
                          </>
                        )}
                        {canDelete && (
                          <button onClick={() => setDeleteFinding(realFinding)} className="text-xs px-2 py-1 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>Suppr.</button>
                        )}
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

      <div style={CARD} className="p-6">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Synthèse exécutive</h2>
          {!summaryEdit && !isSynthetic && <button onClick={() => setSummaryEdit(true)} className="text-xs" style={{ color: MODULE_COLOR }}>Modifier</button>}
        </div>
        {summaryEdit ? (
          <div className="mt-3 space-y-2">
            <textarea value={summary} onChange={e => setSummary(e.target.value)} rows={5} className={`${inputCls} resize-none`} style={field} />
            <div className="flex justify-end gap-2">
              <button onClick={() => { setSummary(audit.executive_summary || ''); setSummaryEdit(false) }} className="text-xs px-3 py-1.5 rounded-lg font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Annuler</button>
              <button onClick={saveSummary} disabled={summarySaving} className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-50" style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' }}>{summarySaving ? '…' : 'Enregistrer'}</button>
            </div>
          </div>
        ) : (
          <p className="text-sm mt-2" style={{ color: audit.executive_summary ? 'var(--text-secondary)' : 'var(--text-muted)' }}>{displayAudit.executive_summary || 'Non rédigée.'}</p>
        )}
      </div>

      <div style={CARD} className="overflow-hidden">
        <div className="px-6 py-4 flex items-center justify-between flex-wrap gap-2" style={{ borderBottom: reportOpen ? '1px solid var(--border)' : 'none' }}>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Rapport</h2>
          <div className="flex items-center gap-2">
            {reportOpen && (
              <button onClick={() => { const ok = exportPdf(reportText); if (!ok) setError('Export PDF bloqué par le navigateur.') }}
                className="px-3 py-1.5 text-xs font-medium rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>Exporter PDF</button>
            )}
            <button onClick={handleOpenReport} disabled={reportLoading}
              className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}1a`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}40` }}>
              {reportLoading ? '…' : reportOpen ? 'Fermer' : '👁 Consulter le rapport'}
            </button>
          </div>
        </div>
        {reportOpen && <div className="p-6 space-y-0.5">{renderMd(reportText)}</div>}
      </div>

      {findingModal !== false && (
        <AuditFindingModal
          auditId={id}
          finding={findingModal}
          assetList={displayAssetList}
          onClose={() => setFindingModal(false)}
          onSaved={findingModal ? handleUpdateFinding : handleCreateFinding}
        />
      )}
      {deleteFinding && (
        <ConfirmModal title="Supprimer ce finding ?" message={`« ${deleteFinding.title} » sera définitivement supprimé, avec son historique et ses pièces jointes.`}
          onConfirm={handleDeleteFinding} onClose={() => setDeleteFinding(null)} />
      )}
      {deleteAuditModal && (
        <ConfirmModal title="Supprimer cet audit ?" message="L'audit, ses findings, son historique et ses pièces jointes seront définitivement supprimés."
          onConfirm={handleDeleteAudit} onClose={() => setDeleteAuditModal(false)} />
      )}
    </div>
  )
}
