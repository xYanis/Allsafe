import axios from 'axios'

const api = axios.create({ baseURL: '/api', withCredentials: true })

// 401 = pas de session valide (cookie absent/expiré) — redirige vers /login, sauf pour
// les appels d'auth eux-mêmes (évite une boucle sur un login qui échoue légitimement,
// ou sur le GET /auth/me de bootstrap d'AuthContext au chargement de l'app).
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = error?.config?.url || ''
    const onLoginPage = window.location.pathname === '/login'
    if (error?.response?.status === 401 && !url.includes('/auth/') && !onLoginPage) {
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const stats      = (params) => api.get('/stats', { params })
export const cves       = (params) => api.get('/cves', { params })
export const assets     = () => api.get('/assets')
// Id + nom seulement (19/08/2026) — pour les filtres/dropdowns (AssetDropdown.jsx) qui
// n'ont pas besoin des compteurs de vulns/mises à jour/état réseau que assets() calcule
// pour tout le parc à chaque appel. Cf. routers/assets.py::list_asset_names.
export const assetNames  = () => api.get('/assets/names')
export const getAsset    = (id) => api.get(`/assets/${id}`)
export const createAsset = (data) => api.post('/assets', data)
export const updateAsset = (id, data) => api.put(`/assets/${id}`, data)
export const deleteAsset = (id) => api.delete(`/assets/${id}`)
export const scanAsset   = (id, creds) => api.post(`/assets/${id}/scan`, creds || {})
export const runWebHardeningCheck = () => api.post('/assets/web-hardening/run')
export const getAssetPackages = (id) => api.get(`/assets/${id}/packages`)
export const getAssetPendingUpdates = (id) => api.get(`/assets/${id}/pending-updates`)
export const vulns      = (params) => api.get('/vulnerabilities', { params })
export const updateVuln = (id, data) => api.patch(`/vulnerabilities/${id}`, data)
export const analyzeIA  = (cve_id, asset_id) => api.post('/analysis/cve', { cve_id, asset_id })
export const recommend  = (vuln_id) => api.post('/remediation/recommend', { vuln_id })
export const script     = (vuln_id) => api.post('/remediation/script', { vuln_id })
export const exportCsv  = (params) => api.get('/reports/csv', { params, responseType: 'blob' })
export const exportInventoryPdf = () => api.get('/reports/inventory/pdf', { responseType: 'blob' })
// Rapports hebdomadaires figés (archives) — cf. backend/services/weekly_report.py
export const weeklyReports   = (kind = 'cve', asset_id) => api.get('/reports/weekly', { params: { kind, asset_id } })
export const weeklyReport    = (id) => api.get(`/reports/weekly/${id}`)
export const generateWeekly  = (params = {}) => api.post('/reports/weekly/generate', null, { params: { kind: 'cve', ...params } })
export const weeklyReportCsv = (id) => api.get(`/reports/weekly/${id}/csv`, { responseType: 'blob' })
export const syncNvd    = (days = 7) => api.post(`/sync/nvd?days=${days}`)
export const syncTaskStatus = (taskId) => api.get(`/sync/status/${taskId}`)
export const syncMatch       = () => api.post('/sync/match')
export const syncMatchStatus = () => api.get('/sync/match-status')
export const getVulnStatusHistory = (vuln_id) => api.get(`/vulnerabilities/${vuln_id}/status-history`)
export const getVulnOtherInstances = (vuln_id) => api.get(`/vulnerabilities/${vuln_id}/other-instances`)
export const patchCheck      = (vuln_id, force = false) => api.post(`/patch-check/${vuln_id}`, null, { params: force ? { force: true } : {} })
// `configured_only` (07/08/2026) : seul consommateur = le dashboard (polling
// "Analyse en cours") — affichait "0/261344" sur tout le parc alors que le
// reste du dashboard ne compte que les 3 actifs configurés, incohérent et
// trompeur ("ça tourne dans le vide" pour les 69 autres). Le cycle réel
// derrière n'est pas affecté, seul ce compteur d'affichage l'est.
export const patchCheckStatus = () => api.get('/patch-check/status', { params: { configured_only: true } })
export const patchCheckRun    = (force = false, assetIds = []) => api.post('/patch-check/run', null, {
  params: {
    ...(force ? { force: true } : {}),
    ...(assetIds.length ? { asset_id: assetIds.join(',') } : {}),
  },
})
// `assetId` : scope l'analyse à un actif et lève la fenêtre par défaut des 2 ans
// (cf. backend/routers/vulnerabilities.py, CANDIDATE_MAX_AGE_YEARS) — bouton
// "voir aussi les CVE anciennes" côté UI, toujours par actif, jamais global.
export const criticalReviewCandidates = (assetId) => api.get('/vulnerabilities/critical-review-candidates', { params: assetId ? { asset_id: assetId } : {} })
export const bulkValidate    = (vuln_ids, validated_by) => api.post('/vulnerabilities/bulk-validate', { vuln_ids, validated_by })
export const falsePositiveCandidates = (assetId, configuredOnly) => api.get('/vulnerabilities/false-positive-candidates', { params: assetId ? { asset_id: assetId } : (configuredOnly ? { configured_only: true } : {}) })
export const bulkFalsePositive = (vuln_ids, validated_by, notes) => api.post('/vulnerabilities/bulk-false-positive', { vuln_ids, validated_by, notes })
export const awaitingFixCandidates = (assetId) => api.get('/vulnerabilities/awaiting-fix-candidates', { params: assetId ? { asset_id: assetId } : {} })
export const bulkAwaitingFix = (vuln_ids, validated_by, notes) => api.post('/vulnerabilities/bulk-awaiting-fix', { vuln_ids, validated_by, notes })
export const bulkPatch       = (vuln_ids, validated_by, notes) => api.post('/vulnerabilities/bulk-patch', { vuln_ids, validated_by, notes })
export const bulkAcceptedRisk = (vuln_ids, validated_by, notes, accepted_risk_until) =>
  api.post('/vulnerabilities/bulk-accepted-risk', { vuln_ids, validated_by, notes, accepted_risk_until })
// Rattrapage des bascules automatiques depuis la dernière visite (bandeau Dashboard)
export const autoBasculeSummary = (since, limit) => api.get('/vulnerabilities/auto-bascule-summary', { params: { since, limit } })
// Rattrapage — nouvelles vulnérabilités détectées depuis la dernière visite (bandeau Dashboard)
export const newVulnsSinceCount = (since, limit) => api.get('/vulnerabilities/new-since-count', { params: { since, limit } })
// Rattrapage — actifs ajoutés/supprimés depuis la dernière visite (bandeau Dashboard)
export const assetsLifecycleSince = (since, limit) => api.get('/assets/lifecycle-since', { params: { since, limit } })
// Pendant "actif terminé" (11/08/2026) — endpoint séparé plutôt que fusionné dans
// auto-bascule-summary, cf. sa docstring backend (bandeau + WelcomeOverlay déjà écrits
// pour un format CVE, y mélanger un autre format les aurait cassés).
export const assetCompletionSummary = (since, limit) => api.get('/patch-check/asset-completions', { params: { since, limit } })
export const logConnection      = () => api.post('/connections')
export const getConnections     = () => api.get('/connections')
export const getUserConnections = () => api.get('/connections/users')

export const watchItems  = (params) => api.get('/watch', { params })
export const updateWatch = (id, data) => api.patch(`/watch/${id}`, data)
export const watchStats  = (days = 30, extra = {}) => api.get('/watch/stats', { params: { days, ...extra } })
export const syncWatch       = () => api.post('/watch/sync')
export const watchSyncStatus = () => api.get('/watch/sync-status')
export const exportWatch     = (params) => api.get('/watch/export', { params, responseType: 'blob' })

// Profil de veille (OS/logiciels du parc) — met en avant, ne filtre jamais la collecte
export const watchProfile      = () => api.get('/watch/profile')
export const saveWatchProfile  = (items) => api.put('/watch/profile', { items })
export const previewProfileTerm = (term) => api.get('/watch/profile/preview-term', { params: { term } })
export const watchLeakSources  = () => api.get('/watch/leak-sources')
export const watchSources      = (params) => api.get('/watch/sources', { params })
export const createWatchSource = (data) => api.post('/watch/sources', data)
export const updateWatchSource = (id, data) => api.patch(`/watch/sources/${id}`, data)
export const deleteWatchSource = (id) => api.delete(`/watch/sources/${id}`)

export const watchedIdentities = () => api.get('/identities')
export const createIdentity    = (data) => api.post('/identities', data)
export const deleteIdentity    = (id) => api.delete(`/identities/${id}`)
export const identityMatches   = () => api.get('/identities/matches')

// Déception / sécurité (honeypots DB) — bannière d'alerte du Dashboard
export const securityEventsCount = () => api.get('/security/events/count')
export const securityEvents      = (params) => api.get('/security/events', { params })
export const ackSecurityEvent    = (id, ack_by) => api.post(`/security/events/${id}/ack`, { ack_by })
export const ackAllSecurityEvents = (ack_by) => api.post('/security/events/ack-all', { ack_by })

// Incidents — registre + délais légaux de notification NIS 2 (cf. backend/routers/incidents.py)
export const incidents           = (params) => api.get('/incidents', { params })
export const getIncident         = (id) => api.get(`/incidents/${id}`)
export const createIncident      = (data) => api.post('/incidents', data)
export const updateIncident      = (id, data) => api.patch(`/incidents/${id}`, data)
export const deleteIncident       = (id) => api.delete(`/incidents/${id}`)
export const incidentTimeline    = (id) => api.get(`/incidents/${id}/timeline`)
export const addIncidentNote     = (id, author, notes) => api.post(`/incidents/${id}/notes`, { author, notes })
export const qualifyIncidentNotification   = (id, analyst, justification) => api.post(`/incidents/${id}/qualify-notification`, { analyst, justification })
export const unqualifyIncidentNotification = (id, analyst, reason) => api.post(`/incidents/${id}/unqualify-notification`, { analyst, reason })
export const setIncidentAwareAt  = (id, new_aware_at, analyst, recompute = false) => api.post(`/incidents/${id}/aware-at`, { new_aware_at, analyst, recompute })
export const markIncidentMilestoneSent = (id, milestone, sent_by, note) => api.post(`/incidents/${id}/milestones/${milestone}/mark-sent`, { sent_by, note })
export const prefillIncident     = (source_type, source_id) => api.get('/incidents/prefill', { params: { source_type, source_id } })
export const exportIncidents     = () => api.get('/incidents/export', { responseType: 'blob' })
export const incidentsPendingCount = () => api.get('/incidents/nis2/pending-count')
export const getIncidentReport   = (id) => api.get(`/incidents/${id}/report`)
export const incidentAttachments = (id) => api.get(`/incidents/${id}/attachments`)
export const uploadIncidentAttachment = (id, file, uploadedBy, milestone = 'final_report') => {
  const form = new FormData()
  form.append('file', file)
  form.append('uploaded_by', uploadedBy)
  form.append('milestone', milestone)
  return api.post(`/incidents/${id}/attachments`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
}
export const deleteIncidentAttachment = (id, attachmentId) => api.delete(`/incidents/${id}/attachments/${attachmentId}`)
export const incidentAttachmentDownloadUrl = (id, attachmentId) => `/api/incidents/${id}/attachments/${attachmentId}/download`
export const notificationContacts        = () => api.get('/incidents/notification-contacts')
export const createNotificationContact    = (data) => api.post('/incidents/notification-contacts', data)
export const updateNotificationContact    = (id, data) => api.patch(`/incidents/notification-contacts/${id}`, data)
export const deleteNotificationContact    = (id) => api.delete(`/incidents/notification-contacts/${id}`)

// Gestion de crise (cf. backend/routers/crises.py) — escalade d'un ou plusieurs incidents en
// crise : cellule de crise (rôles nommés), journal de décisions/communications internes/externes.
export const crises              = (params) => api.get('/crises', { params })
export const getCrisis           = (id) => api.get(`/crises/${id}`)
export const createCrisis        = (data) => api.post('/crises', data)
export const updateCrisis        = (id, data) => api.patch(`/crises/${id}`, data)
export const deleteCrisis        = (id) => api.delete(`/crises/${id}`)
export const crisisTimeline      = (id) => api.get(`/crises/${id}/timeline`)
export const standDownCrisis     = (id, analyst, justification) => api.post(`/crises/${id}/stand-down`, { analyst, justification })
export const assignCrisisRole    = (id, role, analyst_name, by) => api.post(`/crises/${id}/roles`, { role, analyst_name, by })
export const removeCrisisRole    = (id, role, by) => api.delete(`/crises/${id}/roles/${encodeURIComponent(role)}`, { params: { by } })
export const linkCrisisIncident   = (id, incident_id, by) => api.post(`/crises/${id}/incidents`, { incident_id, by })
export const unlinkCrisisIncident = (id, incidentId, by) => api.delete(`/crises/${id}/incidents/${incidentId}`, { params: { by } })
export const addCrisisDecision      = (id, author, content) => api.post(`/crises/${id}/decisions`, { author, content })
export const addCrisisCommunication = (id, author, content, audience) => api.post(`/crises/${id}/communications`, { author, content, audience })
export const crisisContacts        = () => api.get('/crises/contacts')
export const createCrisisContact   = (data) => api.post('/crises/contacts', data)
export const updateCrisisContact   = (id, data) => api.patch(`/crises/contacts/${id}`, data)
export const deleteCrisisContact   = (id) => api.delete(`/crises/contacts/${id}`)

// Agents postes (cf. backend/routers/agents.py) — module Sécurité > Agents. Jetons
// d'enrôlement à usage unique (admin) + liste/révocation des agents enrôlés.
export const listAgents            = () => api.get('/agents')
export const agentLatestVersion    = () => api.get('/agents/latest/version')
export const createEnrollmentToken = (data) => api.post('/agents/enrollment-tokens', data)
export const listEnrollmentTokens  = () => api.get('/agents/enrollment-tokens')
export const deleteEnrollmentToken = (id) => api.delete(`/agents/enrollment-tokens/${id}`)
export const revokeAgent           = (id) => api.post(`/agents/${id}/revoke`)
export const deleteAgent           = (id) => api.delete(`/agents/${id}`)
export const requestAgentScan      = (id) => api.post(`/agents/${id}/request-scan`)
// Historique des contacts (18/08/2026) — page dédiée par agent.
export const getAgent              = (id) => api.get(`/agents/${id}`)
export const agentCheckins         = (id, limit) => api.get(`/agents/${id}/checkins`, { params: { limit } })

// Analystes (cf. backend/routers/analysts.py) — remplace la liste ANALYSTS codée en dur,
// alimente les menus déroulants d'attribution (validé par, déclaré par...). Registre
// distinct des comptes de connexion ci-dessous (cf. STATUS.md, pas de fusion pour l'instant).
export const analysts       = () => api.get('/analysts')
export const createAnalyst  = (data) => api.post('/analysts', data)
export const updateAnalyst  = (id, data) => api.patch(`/analysts/${id}`, data)
export const deleteAnalyst  = (id) => api.delete(`/analysts/${id}`)

// Registre « Rôles » (organigramme, cf. backend/routers/organization_roles.py) — poste -> personne
// -> email, utilisé par la Gestion de crise et les Incidents pour savoir à qui se référer.
export const organizationRoles       = () => api.get('/organization-roles')
export const createOrganizationRole  = (data) => api.post('/organization-roles', data)
export const updateOrganizationRole  = (id, data) => api.patch(`/organization-roles/${id}`, data)
export const deleteOrganizationRole  = (id) => api.delete(`/organization-roles/${id}`)

// Services/départements (cf. backend/routers/services.py) — regroupent les postes du registre
// Rôles, avec un code couleur pour la grille de cartes d'Administration.
export const services       = () => api.get('/services')
export const createService  = (data) => api.post('/services', data)
export const updateService  = (id, data) => api.patch(`/services/${id}`, data)
export const deleteService  = (id) => api.delete(`/services/${id}`)

// Module Documentation (cf. backend/routers/documents.py) — documents de gouvernance NIS 2
// (PSSI, chartes, organigramme...), groupés par type, historique des versions conservé.
export const documentTypes       = () => api.get('/document-types')
export const createDocumentType  = (data) => api.post('/document-types', data)
export const updateDocumentType  = (id, data) => api.patch(`/document-types/${id}`, data)
export const deleteDocumentType  = (id) => api.delete(`/document-types/${id}`)

// Notes — prise de notes personnelle structurée (Thème > Sujet en Markdown, cf.
// backend/routers/notes.py, docs/Notes.md), sous-page "Notes" du module Documentation,
// distincte des documents de gouvernance ci-dessus.
export const noteThemes       = () => api.get('/notes/themes')
export const createNoteTheme  = (data) => api.post('/notes/themes', data)
export const updateNoteTheme  = (id, data) => api.patch(`/notes/themes/${id}`, data)
export const deleteNoteTheme  = (id) => api.delete(`/notes/themes/${id}`)

export const noteSubjects       = (themeId) => api.get('/notes/subjects', { params: themeId ? { theme_id: themeId } : {} })
export const noteSubject        = (id) => api.get(`/notes/subjects/${id}`)
export const createNoteSubject  = (data) => api.post('/notes/subjects', data)
export const updateNoteSubject  = (id, data) => api.patch(`/notes/subjects/${id}`, data)
export const deleteNoteSubject  = (id) => api.delete(`/notes/subjects/${id}`)

export const uploadNoteImage = (file, subjectId) => {
  const form = new FormData()
  form.append('file', file)
  if (subjectId) form.append('subject_id', subjectId)
  return api.post('/notes/images', form, { headers: { 'Content-Type': 'multipart/form-data' } })
}

export const documents = (params) => api.get('/documents', { params })
export const uploadDocument = (file, documentTypeId, uploadedBy, notes) => {
  const form = new FormData()
  form.append('file', file)
  form.append('document_type_id', documentTypeId)
  form.append('uploaded_by', uploadedBy)
  if (notes) form.append('notes', notes)
  return api.post('/documents', form, { headers: { 'Content-Type': 'multipart/form-data' } })
}
export const deleteDocument = (id) => api.delete(`/documents/${id}`)
export const documentDownloadUrl = (id) => `/api/documents/${id}/download`

// Correspondances nom d'application Windows -> produit CPE (cf.
// backend/routers/windows_app_mappings.py) — alimente services/cpe_matcher.py côté
// Windows, là où les paquets Linux se dérivent par convention de nommage.
export const windowsAppMappings       = () => api.get('/windows-app-mappings')
export const createWindowsAppMapping  = (data) => api.post('/windows-app-mappings', data)
export const updateWindowsAppMapping  = (id, data) => api.patch(`/windows-app-mappings/${id}`, data)
export const deleteWindowsAppMapping  = (id) => api.delete(`/windows-app-mappings/${id}`)

// Authentification (cf. backend/routers/auth.py) — session par cookie HttpOnly, posé/effacé
// automatiquement par le navigateur (withCredentials ci-dessus), jamais lu par ce fichier.
export const login          = (email, password) => api.post('/auth/login', { email, password })
export const logout         = () => api.post('/auth/logout')
export const me             = () => api.get('/auth/me')
export const changePassword = (current_password, new_password) => api.post('/auth/change-password', { current_password, new_password })
export const changeEmail    = (current_password, new_email) => api.patch('/auth/change-email', { current_password, new_email })
export const mySessions     = () => api.get('/auth/sessions')
export const revokeMySession = (id) => api.delete(`/auth/sessions/${id}`)
// « Mot de passe oublié » (18/08/2026) — public, appelable avant authentification. Réponse
// toujours générique côté serveur (pas d'énumération de comptes), cf. Login.jsx.
export const requestPasswordReset = (email, message) => api.post('/auth/forgot-password', { email, message })

// Statut agrégé des intégrations externes (cf. backend/routers/integrations.py).
export const integrationsStatus = () => api.get('/integrations/status')

// Politiques de scan planifié par criticité (17/08/2026, cf. backend/routers/scan_policies.py) —
// lecture ouverte à tout connecté, écriture (update/runNow) réservée admin côté serveur.
export const releaseNotes       = (scope) => api.get('/release-notes', { params: { scope } })
export const createReleaseNote  = (data) => api.post('/release-notes', data)
export const updateReleaseNote  = (id, data) => api.patch(`/release-notes/${id}`, data)
export const deleteReleaseNote  = (id) => api.delete(`/release-notes/${id}`)

export const scanPolicies       = () => api.get('/scan-policies')
export const updateScanPolicy   = (criticite, data) => api.patch(`/scan-policies/${criticite}`, data)
export const runScanPolicyNow   = (criticite) => api.post(`/scan-policies/${criticite}/run-now`)

// Comptes utilisateurs (cf. backend/routers/users.py) — réservé au rôle admin côté serveur.
export const users               = () => api.get('/users')
export const createUser          = (data) => api.post('/users', data)
export const updateUser          = (id, data) => api.patch(`/users/${id}`, data)
export const deleteUser          = (id) => api.delete(`/users/${id}`)
export const revokeUserSessions  = (id) => api.post(`/users/${id}/revoke-sessions`)
// Demandes « mot de passe oublié » (18/08/2026) — créées publiquement depuis Login.jsx
// (requestPasswordReset ci-dessus), traitées ici par un admin (Administration > Utilisateurs).
export const passwordResetRequests       = () => api.get('/users/password-reset-requests')
export const passwordResetRequestsCount  = () => api.get('/users/password-reset-requests/count')
export const resolvePasswordResetRequest = (id, new_password) => api.post(`/users/password-reset-requests/${id}/resolve`, { new_password })
export const dismissPasswordResetRequest = (id) => api.post(`/users/password-reset-requests/${id}/dismiss`)

// Module Audits (cf. backend/routers/audits.py) — hub de suivi des audits techniques.
// Aucun scan/outil offensif ne transite ici : uniquement du cadrage, des findings rédigés
// à la main et des pièces jointes (mandat, captures d'écran de preuve).
export const audits           = (params) => api.get('/audits', { params })
export const getAudit         = (id) => api.get(`/audits/${id}`)
export const createAudit      = (data) => api.post('/audits', data)
export const updateAudit      = (id, data) => api.patch(`/audits/${id}`, data)
export const deleteAudit      = (id) => api.delete(`/audits/${id}`)
export const authorizeAudit   = (id, data) => api.post(`/audits/${id}/authorize`, data)
export const linkAuditAsset   = (id, assetId) => api.post(`/audits/${id}/assets/${assetId}`)
export const unlinkAuditAsset = (id, assetId) => api.delete(`/audits/${id}/assets/${assetId}`)
export const getAuditReport   = (id) => api.get(`/audits/${id}/report`)

export const auditFindings        = (id) => api.get(`/audits/${id}/findings`)
export const findingsByAsset      = (assetId) => api.get('/audits/findings', { params: { asset_id: assetId } })
export const openUnretestedFindingsCount = () => api.get('/audits/findings/open-unretested-count')
export const createAuditFinding   = (id, data) => api.post(`/audits/${id}/findings`, data)
export const updateAuditFinding   = (id, findingId, data) => api.patch(`/audits/${id}/findings/${findingId}`, data)
export const deleteAuditFinding   = (id, findingId) => api.delete(`/audits/${id}/findings/${findingId}`)
export const retestAuditFinding   = (id, findingId, data) => api.post(`/audits/${id}/findings/${findingId}/retest`, data)
export const auditFindingHistory  = (id, findingId) => api.get(`/audits/${id}/findings/${findingId}/history`)

export const prtgSslCertificates  = () => api.get('/prtg/ssl-certificates')

export const auditAttachments       = (id) => api.get(`/audits/${id}/attachments`)
export const uploadAuditAttachment  = (id, file, uploadedBy) => {
  const form = new FormData()
  form.append('file', file)
  form.append('uploaded_by', uploadedBy)
  return api.post(`/audits/${id}/attachments`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
}
export const deleteAuditAttachment       = (id, attachmentId) => api.delete(`/audits/${id}/attachments/${attachmentId}`)
export const auditAttachmentDownloadUrl  = (id, attachmentId) => `/api/audits/${id}/attachments/${attachmentId}/download`
export const findingAttachments     = (id, findingId) => api.get(`/audits/${id}/findings/${findingId}/attachments`)
export const uploadFindingAttachment = (id, findingId, file, uploadedBy) => {
  const form = new FormData()
  form.append('file', file)
  form.append('uploaded_by', uploadedBy)
  return api.post(`/audits/${id}/findings/${findingId}/attachments`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
}

export default api
