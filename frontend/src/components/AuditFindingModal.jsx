import { useEffect, useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { findingAttachments, uploadFindingAttachment, auditAttachmentDownloadUrl, retestAuditFinding } from '../api/client.js'
import SeverityBadge from './SeverityBadge.jsx'

export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
export const FINDING_STATUSES = [
  { value: 'ouvert', label: 'Ouvert' },
  { value: 'remediation_planifiee', label: 'Remédiation planifiée' },
  { value: 'corrige', label: 'Corrigé' },
  { value: 'risque_accepte', label: 'Risque accepté' },
  { value: 'faux_positif', label: 'Faux positif' },
]
export const RETEST_RESULTS = [
  { value: 'corrige', label: 'Corrigé' },
  { value: 'partiellement_corrige', label: 'Partiellement corrigé' },
  { value: 'non_corrige', label: 'Non corrigé' },
]

const field = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }
const inputCls = 'w-full text-sm rounded-lg px-3 py-2 outline-none'
const labelCls = 'text-xs font-semibold uppercase tracking-wide block mb-1.5'

// Formulaire finding complet (cf. docs/AUDITS.md §4/§8) — création si `finding` est null,
// édition sinon. Les preuves (captures d'écran) et le retest ne sont proposés qu'en édition
// (un finding doit exister en base avant qu'on puisse y attacher un fichier).
export default function AuditFindingModal({ auditId, finding, assetList, onClose, onSaved }) {
  const { names } = useAnalysts()
  const isEdit = !!finding

  const [title, setTitle] = useState(finding?.title || '')
  const [description, setDescription] = useState(finding?.description || '')
  const [severity, setSeverity] = useState(finding?.severity || 'MEDIUM')
  const [cvssVector, setCvssVector] = useState(finding?.cvss_vector || '')
  const [cvssScore, setCvssScore] = useState(finding?.cvss_score ?? '')
  const [cweId, setCweId] = useState(finding?.cwe_id || '')
  const [owaspRef, setOwaspRef] = useState(finding?.owasp_ref || '')
  const [affectedAssetId, setAffectedAssetId] = useState(finding?.affected_asset_id || '')
  const [affectedComponent, setAffectedComponent] = useState(finding?.affected_component || '')
  const [cveId, setCveId] = useState(finding?.cve_id || '')
  const [proofOfConcept, setProofOfConcept] = useState(finding?.proof_of_concept || '')
  const [impact, setImpact] = useState(finding?.impact || '')
  const [recommendation, setRecommendation] = useState(finding?.recommendation || '')
  const [status, setStatus] = useState(finding?.status || 'ouvert')
  const [mitre, setMitre] = useState((finding?.mitre_techniques || []).join(', '))
  const [author, setAuthor] = useState('')

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [attachments, setAttachments] = useState([])
  const [uploading, setUploading] = useState(false)
  const [retestResult, setRetestResult] = useState('')
  const [retestBy, setRetestBy] = useState('')
  const [retesting, setRetesting] = useState(false)

  useEffect(() => {
    if (isEdit) {
      findingAttachments(auditId, finding.id).then(r => setAttachments(r.data.items || [])).catch(() => {})
    }
  }, [isEdit, auditId, finding?.id])

  const missing = !title.trim() || !severity || !author

  async function handleSubmit() {
    if (missing || saving) return
    setSaving(true)
    setError('')
    try {
      await onSaved({
        author,
        title: title.trim(),
        description: description.trim() || null,
        severity,
        cvss_vector: cvssVector.trim() || null,
        cvss_score: cvssScore === '' ? null : Number(cvssScore),
        cwe_id: cweId.trim() || null,
        owasp_ref: owaspRef.trim() || null,
        affected_asset_id: affectedAssetId || null,
        affected_component: affectedComponent.trim() || null,
        cve_id: cveId.trim() || null,
        proof_of_concept: proofOfConcept.trim() || null,
        impact: impact.trim() || null,
        recommendation: recommendation.trim() || null,
        status,
        mitre_techniques: mitre.split(',').map(t => t.trim()).filter(Boolean),
      })
    } catch (e) {
      setError(e?.response?.data?.detail || "Erreur lors de l'enregistrement.")
    } finally {
      setSaving(false)
    }
  }

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    if (!file || !author) return
    setUploading(true)
    try {
      const { data } = await uploadFindingAttachment(auditId, finding.id, file, author)
      setAttachments(a => [...a, data])
    } catch (e2) {
      setError(e2?.response?.data?.detail || "Erreur lors de l'upload.")
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  async function handleRetest() {
    if (!retestResult || !retestBy || retesting) return
    setRetesting(true)
    try {
      await retestAuditFinding(auditId, finding.id, { retest_result: retestResult, retested_by: retestBy })
      onSaved(null)  // recharge la liste des findings côté parent
      onClose()
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors du retest.')
    } finally {
      setRetesting(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[88vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2">
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{isEdit ? 'Modifier le finding' : 'Nouveau finding'}</h2>
            {isEdit && <SeverityBadge value={severity} />}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 space-y-3 overflow-y-auto">
          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Titre</label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} className={inputCls} style={field} />
          </div>
          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={3} className={`${inputCls} resize-none`} style={field} />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Sévérité</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className={inputCls} style={field}>
                {FINDING_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Score CVSS</label>
              <input type="number" min="0" max="10" step="0.1" value={cvssScore} onChange={e => setCvssScore(e.target.value)} className={inputCls} style={field} />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Vecteur CVSS</label>
              <input value={cvssVector} onChange={e => setCvssVector(e.target.value)} placeholder="CVSS:3.1/AV:N/…" className={inputCls} style={field} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>CWE</label>
              <input value={cweId} onChange={e => setCweId(e.target.value)} placeholder="CWE-89" className={inputCls} style={field} />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Référence OWASP</label>
              <input value={owaspRef} onChange={e => setOwaspRef(e.target.value)} placeholder="A03:2021" className={inputCls} style={field} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Actif affecté</label>
              <select value={affectedAssetId} onChange={e => setAffectedAssetId(e.target.value)} className={inputCls} style={field}>
                <option value="">—</option>
                {(assetList || []).map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Composant affecté</label>
              <input value={affectedComponent} onChange={e => setAffectedComponent(e.target.value)} placeholder="URL, endpoint, fichier:ligne…" className={inputCls} style={field} />
            </div>
          </div>

          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>CVE liée</label>
            <input value={cveId} onChange={e => setCveId(e.target.value.toUpperCase())} placeholder="CVE-2024-XXXXX" className={inputCls} style={field} />
          </div>

          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Preuve de concept</label>
            <textarea value={proofOfConcept} onChange={e => setProofOfConcept(e.target.value)} rows={2} className={`${inputCls} resize-none`} style={field} />
          </div>
          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Impact</label>
            <textarea value={impact} onChange={e => setImpact(e.target.value)} rows={2} className={`${inputCls} resize-none`} style={field} />
          </div>
          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Recommandation</label>
            <textarea value={recommendation} onChange={e => setRecommendation(e.target.value)} rows={2} className={`${inputCls} resize-none`} style={field} />
          </div>
          <div>
            <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Techniques MITRE ATT&CK</label>
            <input value={mitre} onChange={e => setMitre(e.target.value)} placeholder="T1078, T1021.001…" className={inputCls} style={field} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Statut</label>
              <select value={status} onChange={e => setStatus(e.target.value)} className={inputCls} style={field}>
                {FINDING_STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--text-muted)' }}>Analyste</label>
              <select value={author} onChange={e => setAuthor(e.target.value)} className={inputCls} style={field}>
                <option value="">Sélectionner…</option>
                {names.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>

          {isEdit && (
            <div className="pt-2" style={{ borderTop: '1px solid var(--border)' }}>
              <p className={labelCls} style={{ color: 'var(--text-muted)' }}>Captures d'écran / preuves</p>
              <div className="space-y-1 mb-2">
                {attachments.length === 0 && <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucune pièce jointe.</p>}
                {attachments.map(a => (
                  <a key={a.id} href={auditAttachmentDownloadUrl(auditId, a.id)} target="_blank" rel="noreferrer"
                    className="flex items-center justify-between text-xs px-2.5 py-1.5 rounded-lg"
                    style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                    <span>{a.filename}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{(a.size_bytes / 1024).toFixed(0)} Ko</span>
                  </a>
                ))}
              </div>
              <label className="text-xs px-2.5 py-1.5 rounded-lg font-medium inline-block cursor-pointer"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)', opacity: author ? 1 : 0.5 }}>
                {uploading ? 'Envoi…' : '+ Ajouter une preuve (PDF/PNG/JPEG)'}
                <input type="file" accept=".pdf,.png,.jpg,.jpeg" onChange={handleUpload} disabled={!author || uploading} className="hidden" />
              </label>
              {!author && <p className="text-xs mt-1" style={{ color: 'var(--text-faint, var(--text-muted))' }}>Sélectionner un analyste pour joindre un fichier.</p>}

              <div className="mt-4 pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                <p className={labelCls} style={{ color: 'var(--text-muted)' }}>Retest</p>
                {finding.retested_at ? (
                  <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {RETEST_RESULTS.find(r => r.value === finding.retest_result)?.label || finding.retest_result} — le{' '}
                    {new Date(finding.retested_at).toLocaleDateString('fr-FR')} par {finding.retested_by}
                  </p>
                ) : (
                  <div className="flex items-center gap-2">
                    <select value={retestResult} onChange={e => setRetestResult(e.target.value)} className="text-xs rounded-lg px-2.5 py-1.5 outline-none" style={field}>
                      <option value="">Résultat…</option>
                      {RETEST_RESULTS.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                    </select>
                    <select value={retestBy} onChange={e => setRetestBy(e.target.value)} className="text-xs rounded-lg px-2.5 py-1.5 outline-none" style={field}>
                      <option value="">Retesté par…</option>
                      {names.map(n => <option key={n} value={n}>{n}</option>)}
                    </select>
                    <button onClick={handleRetest} disabled={!retestResult || !retestBy || retesting}
                      className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-50"
                      style={{ background: 'rgba(88,166,255,0.15)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.4)' }}>
                      {retesting ? '…' : 'Consigner'}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
        </div>

        <div className="px-6 py-4 flex justify-end gap-2 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
          <button onClick={onClose} className="text-xs px-3 py-2 rounded-lg font-medium" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Fermer</button>
          <button onClick={handleSubmit} disabled={missing || saving}
            className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
            style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' }}>
            {saving ? 'Enregistrement…' : isEdit ? 'Enregistrer' : 'Créer le finding'}
          </button>
        </div>
      </div>
    </div>
  )
}
