import { useEffect, useState } from 'react'
import { assets as fetchAssets, createAsset, updateAsset, deleteAsset, scanAsset, getAssetPackages, findingsByAsset } from '../api/client.js'
import { Link } from 'react-router-dom'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { FAKE_ASSETS, anonymizeAsset, isFakeId, fakeScanResult } from '../utils/fakeData.js'
import CriticiteBadge from '../components/CriticiteBadge.jsx'
import NetworkStatusBadge, { NETWORK_STATUS_LABELS } from '../components/NetworkStatusBadge.jsx'
import PendingUpdatesBadge from '../components/PendingUpdatesBadge.jsx'
import PendingUpdatesModal from '../components/PendingUpdatesModal.jsx'
import NetworkComplianceBadge from '../components/NetworkComplianceBadge.jsx'
import ConnectivityDot from '../components/ConnectivityDot.jsx'
import OsLogo from '../components/OsLogo.jsx'
import CategoryIcon from '../components/CategoryIcon.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import PageLoader from '../components/PageLoader.jsx'
import PageHero from '../components/PageHero.jsx'
import { CRITICITE_LABELS } from '../constants/criticite.js'
import { TYPE_LABELS, merakiModelLabel, assetCategory, categoryStyle } from '../utils/assetCategory.js'
import { MODULES } from '../constants/modules.js'

// Couleur du module Inventaire (11/08/2026, tour visuel — cohérence sidebar → page, cf.
// docs/FRONTEND.md § Tour visuel) : CTA principal + survol de ligne, même patron que
// Incidents.jsx/Documentation.jsx/Audits.jsx. Les autres boutons (scan groupé, actions par
// ligne) restent en --accent-blue, réservé aux actions secondaires.
const MODULE_COLOR = MODULES.inventaire.color
const MODULE_HOVER = `${MODULE_COLOR}0a`
// Style "filtre actif" (17/08/2026, retour utilisateur — incohérence avec Durcissement.jsx,
// qui teinte déjà ses menus déroulants dès qu'un filtre est posé) — même formule exacte que
// Durcissement.jsx::activeFilterStyle, même module (Inventaire), même couleur.
const activeFilterStyle = { background: `${MODULE_COLOR}1f`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
const filterSelectStyle = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
  color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none', cursor: 'pointer',
}

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }
const SOURCE_STYLES = {
  active_directory: { background: 'rgba(88,166,255,0.1)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' },
  ssh:              { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.2)' },
  csv:              { background: 'rgba(139,148,158,0.1)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.2)' },
  manual:           { background: 'rgba(163,113,247,0.1)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.2)' },
  meraki:           { background: 'rgba(29,161,242,0.1)',  color: '#1da1f2', border: '1px solid rgba(29,161,242,0.2)' },
  prtg:             { background: 'rgba(219,109,40,0.1)',  color: '#db6d28', border: '1px solid rgba(219,109,40,0.2)' },
  // Actif créé/enrôlé via un agent posé sur un poste (12/08/2026, module Sécurité > Agents)
  // — vert Sécurité (MODULES.securite.color), distinct du vert SSH pour ne pas les confondre.
  agent:            { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' },
  // Hôte ESXi importé/enrichi via vCenter (13/08/2026, intégration vSphere) — cyan Inventaire
  // (MODULES.inventaire.color), même module que le durcissement/patrimoine.
  vsphere:          { background: 'rgba(57,197,207,0.1)',  color: '#39c5cf', border: '1px solid rgba(57,197,207,0.35)' },
}
const SOURCE_LABELS = { active_directory: 'Active Directory', ssh: 'SSH', csv: 'CSV', manual: 'Ajout manuel', meraki: 'Meraki', prtg: 'PRTG', agent: 'Agent', vsphere: 'vSphere' }

// Badge "Nouveau" (13/08/2026, demande utilisateur) : affiché 24h après création
// (Asset.created_at, cf. docs/ARCHITECTURE.md) — actifs déjà en base avant l'ajout de cette
// colonne rétrodatés à 2020, ne l'affichent donc jamais (comportement voulu, cf. schema_patches.sql).
const NEW_ASSET_WINDOW_MS = 24 * 60 * 60 * 1000
function isNewAsset(createdAt) {
  if (!createdAt) return false
  return Date.now() - new Date(createdAt).getTime() < NEW_ASSET_WINDOW_MS
}

// Méthode de collecte active (12/08/2026, module Agents) — distinct de `source` ci-dessus
// (comment l'actif a été découvert) : comment il est ACTIVEMENT scanné aujourd'hui.
const COLLECTION_METHOD_STYLES = {
  service_account: { background: 'rgba(139,148,158,0.1)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.2)' },
  agent:            { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
}
const COLLECTION_METHOD_LABELS = { service_account: 'Compte de service (SSH/WinRM)', agent: 'Agent posé sur le poste' }

// Icône seule plutôt qu'un badge texte (12/08/2026, demande utilisateur — tableau qui
// débordait) : le libellé complet part dans le `title` au survol, même compromis que
// NetworkStatusBadge.jsx/NetworkComplianceBadge.jsx en mode compact ci-dessus. Icône
// "agent" identique à celle du module Sécurité > Agents (Layout.jsx ICONS.agents) pour
// rester reconnaissable d'un endroit à l'autre de l'app.
function CollectionMethodIcon({ method }) {
  const key = method === 'agent' ? 'agent' : 'service_account'
  const color = (COLLECTION_METHOD_STYLES[key] || COLLECTION_METHOD_STYLES.service_account).color
  const label = COLLECTION_METHOD_LABELS[key] || COLLECTION_METHOD_LABELS.service_account
  return (
    <span title={label} style={{ color, display: 'inline-flex' }}>
      {key === 'agent' ? (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" /></svg>
      ) : (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z" /></svg>
      )}
    </span>
  )
}

// Colonne OS, uniquement pour un serveur (asset_type != network) : couleur par
// famille plutôt que par valeur exacte (trop de variantes possibles — "Windows
// Server 2019 build 17763"...) pour rester lisible. Nouvelle famille observée
// plus tard = une entrée ici, pas une refonte.
const OS_FAMILY_PATTERNS = [
  { test: /^windows/i, family: 'Windows', style: { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' } },
  { test: /^(debian|ubuntu|linux)/i, family: 'Linux', style: { background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' } },
]
function osFamilyStyle(os) {
  return OS_FAMILY_PATTERNS.find(p => p.test.test(os || ''))?.style
}

// Colonne OS : "Borne Wi-Fi (MR36)" plutôt que le code brut seul pour un actif
// Meraki catégorisable — inchangé pour le reste (serveurs, PRTG sans os). Renvoie
// aussi le style de badge à appliquer (même couleur que la catégorie pour un actif
// réseau, couleur de famille OS pour un serveur, pas de badge sinon).
function osCell(asset) {
  const category = asset.source === 'meraki' ? merakiModelLabel(asset.os) : null
  if (category) return { label: `${category} (${asset.os})`, style: categoryStyle(category) }
  const label = [asset.os, asset.os_version].filter(Boolean).join(' ')
  if (!label) return { label: '—', style: null }
  return { label, style: osFamilyStyle(asset.os) || null }
}

const EMPTY_FORM = { name: '', hostname: '', ip_address: '', os: '', os_version: '', asset_type: 'server', url: '', criticite: 'moyenne', scan_username: '', scan_password: '', collection_method: 'service_account' }

const inputStyle = {
  width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 8, padding: '8px 10px', fontSize: 13, color: 'var(--text-primary)', outline: 'none',
}
const labelStyle = { fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }

// Cache module (pas du state React) qui survit au démontage/remontage du composant —
// cette page est entièrement redémontée à chaque navigation (pas de keep-alive de route),
// donc y revenir relançait le fetch et l'écran de chargement plein écran à CHAQUE fois.
// Permet de réafficher instantanément les dernières données connues au remontage pendant
// qu'un rafraîchissement silencieux les met à jour en fond. Réponse BRUTE de fetchAssets()
// (avant tri/filtrage local), pas les listes déjà filtrées par l'utilisateur.
let assetsPageCache = null

function AssetFormModal({ asset, onClose, onSaved }) {
  const isEdit = !!asset
  const [form, setForm] = useState(asset ? {
    name: asset.name || '', hostname: asset.hostname || '', ip_address: asset.ip_address || '',
    os: asset.os || '', os_version: asset.os_version || '', asset_type: asset.asset_type || 'server',
    url: asset.url || '',
    criticite: asset.tags?.criticite || 'moyenne',
    scan_username: asset.scan_username || '', scan_password: '',
    collection_method: asset.collection_method || 'service_account',
  } : EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function set(field, value) { setForm(f => ({ ...f, [field]: value })) }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!form.name.trim()) { setError('Le nom est obligatoire.'); return }
    // Site web (17/08/2026) : ni hostname/IP ni scan SSH/WinRM, seule l'URL est requise
    // (cf. services/web_hardening.py, checks 100% passifs — pas de connexion à l'actif).
    if (form.asset_type === 'website') {
      if (!form.url.trim()) { setError("L'URL est obligatoire pour un site web.") ; return }
    } else if (!form.hostname.trim() && !form.ip_address.trim()) {
      setError('Renseigne au moins un hostname ou une adresse IP.')
      return
    }
    setSaving(true)
    try {
      const payload = {
        name: form.name.trim(),
        hostname: form.hostname.trim() || null,
        ip_address: form.ip_address.trim() || null,
        os: form.os.trim() || null,
        os_version: form.os_version.trim() || null,
        asset_type: form.asset_type,
        url: form.url.trim() || null,
        collection_method: form.collection_method,
        // Merge, pas d'écrasement : ne remplace que la clé criticite, préserve
        // d'éventuels autres tags déjà présents sur l'actif.
        tags: { ...(asset?.tags || {}), criticite: form.criticite },
        scan_username: form.scan_username.trim() || null,
        scan_password: form.scan_password || null, // vide = ne pas changer (write-only côté API)
      }
      const { data } = isEdit ? await updateAsset(asset.id, payload) : await createAsset(payload)
      onSaved(data, isEdit)
    } catch (e) {
      setError(e?.response?.data?.detail || `Erreur lors de ${isEdit ? 'la modification' : 'la création'} de l'actif.`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>{isEdit ? "Modifier l'actif" : 'Ajouter un actif'}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Collecte lecture seule uniquement</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4" autoComplete="off">
          <div>
            <label style={labelStyle}>Nom *</label>
            <input style={inputStyle} value={form.name} onChange={e => set('name', e.target.value)} placeholder="srv-prod-01" autoFocus autoComplete="off" />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label style={labelStyle}>Type d'actif</label>
              <select style={inputStyle} value={form.asset_type} onChange={e => set('asset_type', e.target.value)}>
                <option value="server">Serveur</option>
                <option value="workstation">Poste de travail</option>
                <option value="network">Réseau</option>
                <option value="website">Site web</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>Criticité métier</label>
              <select style={inputStyle} value={form.criticite} onChange={e => set('criticite', e.target.value)}>
                {Object.entries(CRITICITE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </div>
          </div>
          <p className="text-xs -mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
            Pondère le score de risque des vulnérabilités de cet actif (×1.5 / ×1.0 / ×0.7).
          </p>

          {form.asset_type === 'website' ? (
            // Site web (17/08/2026) : ni hostname/IP ni scan SSH/WinRM — juste l'URL, checks
            // 100% passifs (en-têtes HTTP, protocole TLS — cf. services/web_hardening.py).
            <div>
              <label style={labelStyle}>URL *</label>
              <input style={inputStyle} value={form.url} onChange={e => set('url', e.target.value)} placeholder="https://exemple.fr" autoComplete="off" />
              <p className="text-xs mt-1" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
                Checks passifs uniquement (en-têtes de sécurité HTTP, protocole TLS) — aucune tentative d'injection.
              </p>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label style={labelStyle}>Hostname (FQDN)</label>
                  <input style={inputStyle} value={form.hostname} onChange={e => set('hostname', e.target.value)} placeholder="srv-prod-01.domaine.local" autoComplete="off" />
                </div>
                <div>
                  <label style={labelStyle}>Adresse IP</label>
                  <input style={inputStyle} value={form.ip_address} onChange={e => set('ip_address', e.target.value)} placeholder="10.0.1.50" autoComplete="off" />
                </div>
              </div>
              <p className="text-xs -mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>Au moins un des deux, nécessaire pour la connexion WinRM/SSH.</p>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label style={labelStyle}>OS</label>
                  <input style={inputStyle} value={form.os} onChange={e => set('os', e.target.value)} placeholder="Windows Server" autoComplete="off" />
                </div>
                <div>
                  <label style={labelStyle}>Version OS</label>
                  <input style={inputStyle} value={form.os_version} onChange={e => set('os_version', e.target.value)} placeholder="2019" autoComplete="off" />
                </div>
              </div>

              <div>
                <label style={labelStyle}>Méthode de collecte</label>
                <select style={inputStyle} value={form.collection_method} onChange={e => set('collection_method', e.target.value)}>
                  <option value="service_account">Compte de service (SSH/WinRM)</option>
                  <option value="agent">Agent posé sur le poste</option>
                </select>
              </div>
              {form.collection_method === 'agent' && (
                <p className="text-xs -mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
                  {isEdit
                    ? <>Générez un jeton d'enrôlement pour cet actif depuis <Link to="/agents" className="hover:underline" style={{ color: MODULE_COLOR }}>Sécurité &gt; Agents</Link>.</>
                    : "Une fois l'actif créé, générez un jeton d'enrôlement depuis Sécurité > Agents pour l'installer sur le poste."}
                </p>
              )}

              {/* Champs SSH uniquement : ignorés côté Windows (compte de service WinRM partagé,
                  cf. services/asset_scanner.py::_scan_windows qui ne prend même pas ces paramètres)
                  — masqués plutôt que juste étiquetés "SSH" dès que l'OS ressemble à du Windows
                  (même détection que le backend, `_scan_windows` vs `_scan_linux`), pour ne pas
                  laisser croire qu'ils changent quoi que ce soit sur un actif Windows (10/08/2026,
                  confusion réelle constatée : modifier ces champs sur un actif Windows n'avait
                  aucun effet, remonté par l'utilisateur). */}
              {/windows/i.test(form.os) ? (
                <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(88,166,255,0.08)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                  Actif Windows : le scan utilise toujours le compte de service WinRM partagé
                  (<code>WINRM_USER</code>/<code>WINRM_PASSWORD</code> dans <code>.env</code>) —
                  pas d'identifiants par actif possible ici.
                </div>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label style={labelStyle}>Utilisateur SSH (optionnel, Linux uniquement)</label>
                      <input style={inputStyle} value={form.scan_username} onChange={e => set('scan_username', e.target.value)} placeholder="compte partagé par défaut" autoComplete="off" />
                    </div>
                    <div>
                      <label style={labelStyle}>Mot de passe SSH (optionnel, Linux uniquement)</label>
                      <input type="password" style={inputStyle} value={form.scan_password} onChange={e => set('scan_password', e.target.value)}
                        placeholder={isEdit && asset.has_scan_password ? '•••••• (laisser vide pour conserver)' : 'clé SSH partagée par défaut'}
                        autoComplete="new-password" />
                    </div>
                  </div>
                  <p className="text-xs -mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
                    Phase de test — identifiants stockés chiffrés en base, prioritaires sur la clé SSH partagée du parc. À terme : clé SSH par machine.
                    Sans effet sur un actif Windows (WinRM utilise toujours le compte de service partagé).
                  </p>
                </>
              )}
            </>
          )}

          {error && (
            <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button type="submit" disabled={saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-60"
              style={{ background: 'var(--accent-blue)', color: '#fff' }}
            >{saving ? 'Enregistrement…' : isEdit ? 'Enregistrer' : 'Ajouter'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

function DeleteAssetModal({ asset, onClose, onDeleted }) {
  const [confirmText, setConfirmText] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState('')

  const hasVulns = (asset.vuln_count || 0) > 0
  const canDelete = confirmText.trim() === asset.name

  async function handleDelete() {
    if (!canDelete) return
    setDeleting(true)
    setError('')
    try {
      await deleteAsset(asset.id)
      onDeleted(asset.id)
    } catch (e) {
      setError(e?.response?.data?.detail || "Erreur lors de la suppression de l'actif.")
      setDeleting(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid rgba(248,81,73,0.3)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2.5">
            <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="#f85149" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <h2 className="font-semibold" style={{ color: '#f85149' }}>Supprimer cet actif ?</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 space-y-4">
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Cette action est <span className="font-semibold">définitive et irréversible</span>. L'actif
            <span className="font-semibold" style={{ color: 'var(--text-primary)' }}> {asset.name}</span> sera
            supprimé, ainsi que l'historique de scan lié.
          </p>

          {hasVulns && (
            <div className="text-sm px-3 py-2.5 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              ⚠️ {asset.vuln_count} vulnérabilité{asset.vuln_count !== 1 ? 's' : ''} liée{asset.vuln_count !== 1 ? 's' : ''} à cet actif
              {asset.vuln_count !== 1 ? ' seront supprimées' : ' sera supprimée'} en même temps (y compris les corrections déjà validées).
            </div>
          )}

          <div>
            <label style={labelStyle}>
              Tape <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{asset.name}</span> pour confirmer
            </label>
            <input style={inputStyle} value={confirmText} onChange={e => setConfirmText(e.target.value)} placeholder={asset.name} autoFocus />
          </div>

          {error && (
            <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button type="button" onClick={handleDelete} disabled={!canDelete || deleting}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-40"
              style={{ background: '#f85149', color: '#fff' }}
            >{deleting ? 'Suppression…' : 'Supprimer définitivement'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function BulkDeleteAssetsModal({ assets, onClose, onDeleted }) {
  const [confirmText, setConfirmText] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [progress, setProgress] = useState(0)
  const [errors, setErrors] = useState([])

  const totalVulns = assets.reduce((sum, a) => sum + (a.vuln_count || 0), 0)
  const canDelete = confirmText.trim().toUpperCase() === 'SUPPRIMER'

  async function handleDelete() {
    if (!canDelete) return
    setDeleting(true)
    const failed = []
    const deletedIds = []
    for (let i = 0; i < assets.length; i++) {
      setProgress(i + 1)
      // Actifs de démonstration (mode Présentation) : jamais de vrai appel réseau,
      // même logique que la suppression unitaire et le scan en masse.
      if (isFakeId(assets[i].id)) {
        deletedIds.push(assets[i].id)
        continue
      }
      try {
        await deleteAsset(assets[i].id)
        deletedIds.push(assets[i].id)
      } catch (e) {
        failed.push(assets[i].name)
      }
    }
    setErrors(failed)
    onDeleted(deletedIds)
    if (failed.length === 0) onClose()
    setDeleting(false)
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={deleting ? undefined : onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid rgba(248,81,73,0.3)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2.5">
            <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="#f85149" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <h2 className="font-semibold" style={{ color: '#f85149' }}>Supprimer {assets.length} actif{assets.length !== 1 ? 's' : ''} ?</h2>
          </div>
          {!deleting && (
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          )}
        </div>

        <div className="p-6 space-y-4">
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Cette action est <span className="font-semibold">définitive et irréversible</span>. Les {assets.length} actifs
            sélectionnés seront supprimés, ainsi que leur historique de scan lié.
          </p>

          <div className="max-h-32 overflow-y-auto text-xs rounded-lg px-3 py-2 space-y-0.5" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
            {assets.map(a => <div key={a.id}>{a.name}</div>)}
          </div>

          {totalVulns > 0 && (
            <div className="text-sm px-3 py-2.5 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              ⚠️ {totalVulns} vulnérabilité{totalVulns !== 1 ? 's' : ''} liée{totalVulns !== 1 ? 's' : ''} à ces actifs
              {totalVulns !== 1 ? ' seront supprimées' : ' sera supprimée'} en même temps (y compris les corrections déjà validées).
            </div>
          )}

          <div>
            <label style={labelStyle}>
              Tape <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>SUPPRIMER</span> pour confirmer
            </label>
            <input style={inputStyle} value={confirmText} onChange={e => setConfirmText(e.target.value)} placeholder="SUPPRIMER" autoFocus disabled={deleting} />
          </div>

          {errors.length > 0 && (
            <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}>
              Échec de suppression pour : {errors.join(', ')}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} disabled={deleting}
              className="text-xs px-3 py-2 rounded-lg disabled:opacity-40"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button type="button" onClick={handleDelete} disabled={!canDelete || deleting}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-40"
              style={{ background: '#f85149', color: '#fff' }}
            >{deleting ? `Suppression… ${progress}/${assets.length}` : 'Supprimer définitivement'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function MatchRow({ label, declared, detected, match }) {
  const icon = match === true ? '✓' : match === false ? '⚠' : '—'
  const color = match === true ? '#3fb950' : match === false ? '#fb8f44' : 'var(--text-muted)'
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs" style={{ background: 'var(--bg-secondary)' }}>
      <span className="w-16 flex-shrink-0 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span className="flex-1" style={{ color: 'var(--text-secondary)' }}>
        <span style={{ color: 'var(--text-muted)' }}>Déclaré :</span> {declared || '—'}
      </span>
      <span className="flex-1" style={{ color: 'var(--text-secondary)' }}>
        <span style={{ color: 'var(--text-muted)' }}>Détecté :</span> {detected || '—'}
      </span>
      <span className="font-bold flex-shrink-0" style={{ color }}>{icon}</span>
    </div>
  )
}

function formatDisks(disks) {
  if (!disks || disks.length === 0) return '—'
  return disks.map(d => `${d.name} ${d.total_gb ?? '?'} Go`).join(', ')
}

function ScanResultModal({ asset, result, onClose, onRescan, rescanning }) {
  const [search, setSearch] = useState('')
  const [auditFindings, setAuditFindings] = useState([])
  useEffect(() => {
    if (isFakeId(asset.id)) return
    findingsByAsset(asset.id).then(r => setAuditFindings(r.data.items || [])).catch(() => {})
  }, [asset.id])
  const packages = result?.packages || []
  const hardware = result?.hardware || {}
  const hasHardware = Object.keys(hardware).length > 0
  const filtered = search.trim()
    ? packages.filter(p => (p.name || '').toLowerCase().includes(search.toLowerCase()))
    : packages

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[85vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Résultat du scan — {asset.name}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {result?.last_scan ? `Dernier scan : ${new Date(result.last_scan).toLocaleString('fr-FR')}` : 'Lecture seule — aucune modification sur le serveur'}
            </p>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {onRescan && (
              <button onClick={onRescan} disabled={rescanning}
                className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-60"
                style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                title="Relance une connexion SSH/WinRM en lecture seule pour rafraîchir ces données"
              >
                <svg className={`w-3.5 h-3.5 ${rescanning ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                {rescanning ? 'Scan…' : 'Relancer un scan'}
              </button>
            )}
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>

        <div className="p-6 space-y-4 overflow-y-auto">
          {result?.error && (
            <div className="p-4 rounded-xl" style={{ background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)' }}>
              <p className="font-semibold text-sm mb-1" style={{ color: '#f85149' }}>Actif injoignable</p>
              <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{result.error}</p>
            </div>
          )}

          {/* Agent (17/08/2026) : contrairement au SSH/WinRM, ce scan est asynchrone — pas
              de résultat immédiat, juste un flag posé côté serveur que l'agent ramasse à son
              prochain sondage (≤60s en mode service persistant, cf. CLAUDE.md §1 — jamais
              Allsafe qui se connecte au poste). Ne marche pas si l'agent tourne en
              planification externe (cron/tâche planifiée) plutôt qu'en service, cf.
              docs/AGENTS.md. */}
          {result?.agent_scan_requested && (
            <div className="p-4 rounded-xl" style={{ background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.3)' }}>
              <p className="font-semibold text-sm mb-1" style={{ color: '#58a6ff' }}>Scan demandé à l'agent</p>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                Cet actif est collecté par agent, pas par SSH/WinRM — la collecte se fera au
                prochain sondage de l'agent (moins d'une minute s'il tourne en service
                persistant). Recharge la page dans un instant pour voir le résultat.
              </p>
            </div>
          )}

          {/* Confirmation explicite (07/08/2026, demande explicite) : jusqu'ici seule
              la date "Dernier scan" dans le tableau signalait un scan réussi — miroir
              positif du bloc "Actif injoignable" ci-dessus, même condition symétrique
              (reachable/error), pas de distinction scan live vs vue en cache : dans les
              deux cas c'est une information vraie sur le dernier scan enregistré. */}
          {!result?.error && result?.reachable && (
            <div className="p-4 rounded-xl" style={{ background: 'rgba(63,185,80,0.1)', border: '1px solid rgba(63,185,80,0.3)' }}>
              <p className="font-semibold text-sm" style={{ color: '#3fb950' }}>✅ Scan réussi</p>
            </div>
          )}

          {result?.name_corrected && (
            <div className="p-4 rounded-xl" style={{ background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.3)' }}>
              <p className="font-semibold text-sm mb-1" style={{ color: '#58a6ff' }}>Nom corrigé automatiquement</p>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                "{result.name_corrected.from}" ne correspondait pas au hostname réel détecté — l'actif
                s'appelle désormais <span className="font-mono">{result.name_corrected.to}</span>.
              </p>
            </div>
          )}

          {result?.name_correction_error && (
            <div className="p-4 rounded-xl" style={{ background: 'rgba(251,143,68,0.1)', border: '1px solid rgba(251,143,68,0.3)' }}>
              <p className="font-semibold text-sm mb-1" style={{ color: '#fb8f44' }}>Correction du nom impossible</p>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{result.name_correction_error}</p>
            </div>
          )}

          {result?.declared && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Fiabilité des infos déclarées</p>
              <div className="space-y-1.5">
                <MatchRow label="Hostname" declared={result.declared.hostname} detected={result.detected?.hostname} match={result.hostname_match} />
                <MatchRow label="IP" declared={result.declared.ip_address} detected={result.detected?.ip_address} match={result.ip_match} />
                <MatchRow label="OS" declared={result.declared.os} detected={result.detected?.os} match={result.os_match} />
                <MatchRow label="Version" declared={result.declared.os_version} detected={result.detected?.os_version} match={result.os_version_match} />
              </div>
            </div>
          )}

          {/* Durcissement/conformité déplacé dans son propre module (12/08/2026, demande
              utilisateur) — cf. page Inventaire > Durcissement, plus adapté pour comparer
              l'état de tout le parc que noyé dans cette modale par-actif. */}
          <Link to={`/durcissement?asset=${asset.id}`} className="text-xs hover:underline inline-block" style={{ color: 'var(--accent-blue)' }}>
            Voir le durcissement/conformité de cet actif →
          </Link>

          {auditFindings.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>
                Findings d'audit ({auditFindings.length})
              </p>
              <div className="space-y-1.5">
                {auditFindings.map(f => (
                  <Link key={f.id} to={`/audits/${f.audit_id}`}
                    className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg text-xs"
                    style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                    <span className="flex items-center gap-2">
                      <SeverityBadge value={f.severity} />
                      {f.title}
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>{f.audit_title}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {hasHardware && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)' }}>Specs matérielles</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>CPU : </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{hardware.cpu || '—'}{hardware.cores ? ` (${hardware.cores} cœurs)` : ''}</span>
                </div>
                <div className="px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>RAM : </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{hardware.ram_gb ? `${hardware.ram_gb} Go` : '—'}</span>
                </div>
                <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Architecture : </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{hardware.arch || '—'}</span>
                </div>
                <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Disques : </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{formatDisks(hardware.disks)}</span>
                </div>
                <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Adresse MAC : </span>
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{hardware.mac || '—'}</span>
                </div>
                <div className="px-3 py-2 rounded-lg col-span-2" style={{ background: 'var(--bg-secondary)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Ports ouverts : </span>
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                    {hardware.open_ports?.length > 0 ? hardware.open_ports.join(', ') : '—'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {packages.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
                  Applications installées ({packages.length})
                </p>
                <input
                  value={search} onChange={e => setSearch(e.target.value)}
                  placeholder="Rechercher…"
                  className="text-xs px-2.5 py-1 rounded-lg"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', width: 160 }}
                />
              </div>
              <div className="max-h-64 overflow-y-auto rounded-lg" style={{ border: '1px solid var(--border)' }}>
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ background: 'var(--bg-secondary)' }}>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Nom</th>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Version</th>
                      <th className="text-left px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>MAJ disponible</th>
                      <th className="text-right px-3 py-1.5 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Vulnérabilités</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 && (
                      <tr><td colSpan={4} className="px-3 py-4 text-center" style={{ color: 'var(--text-muted)' }}>Aucun résultat</td></tr>
                    )}
                    {filtered.map((p, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td className="px-3 py-1.5" style={{ color: 'var(--text-secondary)' }}>{p.name}</td>
                        {/* Code couleur (07/08/2026, demande explicite) : gris = pas de MAJ
                            connue (à jour ou indéterminé, cf. note sous le tableau) ; dès
                            qu'une MAJ est disponible, la version installée passe en rouge
                            (obsolète) et la version candidate en vert (cible) — mêmes teintes
                            que SeverityBadge/StatusBadge (#f85149/#3fb950) pour rester
                            cohérent avec le reste de l'app plutôt que d'introduire une
                            nouvelle paire de couleurs. */}
                        <td className="px-3 py-1.5 font-mono" style={{ color: p.available_version ? '#f85149' : 'var(--text-muted)' }}>
                          {p.version || '—'}
                        </td>
                        <td className="px-3 py-1.5 font-mono" style={{ color: p.available_version ? '#3fb950' : 'var(--text-muted)' }}
                            title={p.available_version ? 'Version candidate détectée dans le cache apt local du serveur (lecture seule, jamais "apt update" depuis Allsafe)' : undefined}
                        >
                          {p.available_version || '—'}
                        </td>
                        <td className="px-3 py-1.5 text-right">
                          {p.vuln_count > 0 ? (
                            <span title={p.cve_ids?.join(', ')} className="inline-flex items-center gap-1 cursor-help">
                              <SeverityBadge value={p.severity} />
                              <span style={{ color: 'var(--text-muted)' }}>×{p.vuln_count}</span>
                            </span>
                          ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs mt-2" style={{ color: 'var(--text-faint, var(--text-muted))' }}>
                Vulnérabilités : déjà connues et non résolues pour cet actif (indépendant de la colonne MAJ).
                MAJ disponible : Linux/apt uniquement pour l'instant, "—" = à jour ou indéterminé (Windows,
                paquet RPM, cache apt du serveur non rafraîchi — Allsafe ne lance jamais "apt update" lui-même).
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Assets() {
  const { isAnonymous } = usePresentation()
  const [assetList, setAssetList] = useState(() => {
    if (assetsPageCache == null) return []
    return isAnonymous ? [...assetsPageCache.map(anonymizeAsset), ...FAKE_ASSETS] : assetsPageCache
  })
  const [loading, setLoading] = useState(() => assetsPageCache == null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [editTarget, setEditTarget] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [scanLoading, setScanLoading] = useState({})
  const [scanModal, setScanModal] = useState(null)
  const [pendingUpdatesModal, setPendingUpdatesModal] = useState(null)
  const [filterOs, setFilterOs] = useState('')
  const [filterCriticite, setFilterCriticite] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterNetworkStatus, setFilterNetworkStatus] = useState('')
  const [searchName, setSearchName] = useState('')
  // 'all' | 'configured' | 'unconfigured' — même définition que get_configured_asset_ids
  // (services/stats.py) : au moins un scan SSH/WinRM réussi (package_count > 0), pas un
  // actif réseau (Meraki/PRTG, jamais de paquets installés par construction).
  const [configFilter, setConfigFilter] = useState('all')
  const [selectedAssetIds, setSelectedAssetIds] = useState(new Set())
  const [bulkScanProgress, setBulkScanProgress] = useState(null)
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false)

  // Bug réel corrigé (11/08/2026, gravité critique — cf. STATUS.md) : la colonne
  // "Vulnérabilités ouvertes" recalculait ces comptes côté client depuis une liste
  // plafonnée à 200 lignes triées par score sur *tout le parc* (`fetchVulns({status:
  // 'open', per_page: 200})`) — seuls les actifs dont les CVE figuraient dans ce top
  // 200 global avaient un compte juste, tous les autres affichaient 0 ou très
  // inférieur à la réalité. `open_vuln_count` est maintenant calculé server-side sur
  // TOUT le parc en une seule requête groupée (`routers/assets.py::list_assets`),
  // déjà porté par chaque actif de `fetchAssets()` — plus besoin d'un second appel ici.
  useEffect(() => {
    fetchAssets().then(a => {
      const raw = a.data || []
      assetsPageCache = raw   // alimente le cache module pour le prochain remontage
      let list = raw
      if (isAnonymous) list = [...list.map(anonymizeAsset), ...FAKE_ASSETS]
      setAssetList(list)
    }).finally(() => setLoading(false))
  }, [isAnonymous])

  const maxVulns = Math.max(1, ...assetList.map(a => a.open_vuln_count || 0))

  // Liste pilotée par les actifs importés (pas de valeurs codées en dur) — reflète
  // toujours les OS réellement présents dans le parc, sans maintenance manuelle.
  const osOptions = [...new Set(assetList.map(a => a.os).filter(Boolean))].sort()
  const categoryOptions = [...new Set(assetList.map(assetCategory).filter(Boolean))].sort()
  const isConfigured = a => a.asset_type !== 'network' && a.package_count > 0
  const filteredAssets = assetList.filter(a => {
    if (filterOs && a.os !== filterOs) return false
    if (filterCriticite && (a.tags?.criticite || 'moyenne') !== filterCriticite) return false
    if (filterCategory && assetCategory(a) !== filterCategory) return false
    if (filterNetworkStatus && a.network_status?.status !== filterNetworkStatus) return false
    if (searchName && !a.name?.toLowerCase().includes(searchName.trim().toLowerCase())) return false
    if (configFilter === 'configured' && !isConfigured(a)) return false
    if (configFilter === 'unconfigured' && isConfigured(a)) return false
    return true
  })
  const allVisibleSelected = filteredAssets.length > 0 && filteredAssets.every(a => selectedAssetIds.has(a.id))

  function toggleSelectAllVisible() {
    setSelectedAssetIds(prev => {
      if (allVisibleSelected) {
        const next = new Set(prev)
        filteredAssets.forEach(a => next.delete(a.id))
        return next
      }
      const next = new Set(prev)
      filteredAssets.forEach(a => next.add(a.id))
      return next
    })
  }

  function toggleSelectAsset(id) {
    setSelectedAssetIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function handleBulkScan() {
    const idArr = [...selectedAssetIds]
    for (let i = 0; i < idArr.length; i++) {
      const asset = assetList.find(a => a.id === idArr[i])
      if (!asset) continue
      setBulkScanProgress(`Scan ${i + 1}/${idArr.length}…`)
      setScanLoading(l => ({ ...l, [asset.id]: true }))
      try {
        if (isFakeId(asset.id)) {
          await new Promise(r => setTimeout(r, 200))
        } else {
          const { data } = await scanAsset(asset.id)
          if (data.reachable) {
            const renamed = data.name_corrected
              ? { name: data.name_corrected.to, hostname: data.name_corrected.to }
              : {}
            setAssetList(prev => prev.map(a => a.id === asset.id
              ? {
                  ...a, package_count: data.package_count, last_scan: new Date().toISOString(),
                  // Bug réel corrigé (11/08/2026) : le badge "MAJ dispo" gardait sa valeur
                  // périmée du chargement de page après un rescan — recalculé ici depuis
                  // `data.packages`, même logique que `available_updates_count` côté
                  // backend (routers/assets.py::_asset_dict).
                  available_updates_count: (data.packages || []).filter(p => p.available_version).length,
                  ...renamed,
                }
              : a
            ))
          }
        }
      } catch {
        // Un échec individuel ne bloque pas le reste du lot — même logique que le
        // scan unitaire (l'erreur reste consultable via un scan à la ligne ensuite).
      } finally {
        setScanLoading(l => ({ ...l, [asset.id]: false }))
      }
    }
    setBulkScanProgress(null)
    setSelectedAssetIds(new Set())
  }

  function handleCreated(newAsset) {
    setAssetList(prev => [...prev, newAsset].sort((a, b) => a.name.localeCompare(b.name)))
    setShowAddModal(false)
  }

  function handleSaved(updatedAsset, isEdit) {
    if (isEdit) {
      setAssetList(prev => prev.map(a => a.id === updatedAsset.id ? { ...a, ...updatedAsset } : a))
      setEditTarget(null)
    } else {
      handleCreated(updatedAsset)
    }
  }

  function handleDeleted(assetId) {
    setAssetList(prev => prev.filter(a => a.id !== assetId))
    setDeleteTarget(null)
  }

  function handleBulkDeleted(deletedIds) {
    const deletedSet = new Set(deletedIds)
    setAssetList(prev => prev.filter(a => !deletedSet.has(a.id)))
    setSelectedAssetIds(prev => {
      const next = new Set(prev)
      deletedIds.forEach(id => next.delete(id))
      return next
    })
  }

  async function handleScan(asset) {
    if (isFakeId(asset.id)) {
      setScanModal({ asset, result: fakeScanResult(asset) })
      return
    }
    setScanLoading(l => ({ ...l, [asset.id]: true }))
    try {
      const { data } = await scanAsset(asset.id)
      // Le scan peut corriger le nom/hostname déclarés (cf. routers/assets.py) —
      // répercute la correction dans la modale et la liste sans recharger la page.
      const renamed = data.name_corrected
        ? { name: data.name_corrected.to, hostname: data.name_corrected.to }
        : {}
      setScanModal({ asset: { ...asset, ...renamed }, result: data })
      if (data.reachable) {
        setAssetList(prev => prev.map(a => a.id === asset.id
          ? {
              ...a, package_count: data.package_count, last_scan: new Date().toISOString(),
              available_updates_count: (data.packages || []).filter(p => p.available_version).length,
              ...renamed,
            }
          : a
        ))
      }
    } catch (e) {
      setScanModal({ asset, result: { error: e?.response?.data?.detail || 'Erreur lors du scan.' } })
    } finally {
      setScanLoading(l => ({ ...l, [asset.id]: false }))
    }
  }

  // Le bouton "Scanner" de la ligne privilégie le résultat déjà en base (rapide,
  // GET simple) plutôt que de relancer systématiquement une connexion SSH/WinRM —
  // un scan live reste possible via "Relancer un scan" dans la modale elle-même.
  // Seul un actif jamais scanné (rien en cache) déclenche un scan live d'emblée.
  function handleRowScanClick(asset) {
    if (asset.last_scan) {
      handleViewPackages(asset)
    } else if (!scanLoading[asset.id]) {
      handleScan(asset)
    }
  }

  async function handleViewPackages(asset) {
    if (isFakeId(asset.id)) {
      setScanModal({ asset, result: { packages: asset.installed_packages, hardware: asset.hardware, last_scan: asset.last_scan } })
      return
    }
    try {
      const { data } = await getAssetPackages(asset.id)
      setScanModal({ asset, result: { ...data.last_scan_result, packages: data.packages, last_scan: data.last_scan } })
    } catch {
      setScanModal({ asset, result: { error: 'Erreur lors du chargement des applications.' } })
    }
  }

  if (loading) return <PageLoader />

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"
        title="Actifs"
        color="#39c5cf"
        subtitle="Inventaire des serveurs et postes de travail"
      >
        <div className="flex items-center gap-2 flex-wrap">
          <input
            value={searchName}
            onChange={e => setSearchName(e.target.value)}
            placeholder="Rechercher un actif…"
            className="text-sm"
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
              color: 'var(--text-primary)', padding: '6px 12px', outline: 'none', width: 180,
            }}
          />
          <select
            value={filterOs}
            onChange={e => setFilterOs(e.target.value)}
            style={filterOs ? activeFilterStyle : filterSelectStyle}
          >
            <option value="">Tous les OS</option>
            {osOptions.map(os => {
              const category = merakiModelLabel(os)
              return <option key={os} value={os}>{category ? `${category} (${os})` : os}</option>
            })}
          </select>
          <select
            value={filterCriticite}
            onChange={e => setFilterCriticite(e.target.value)}
            style={filterCriticite ? activeFilterStyle : filterSelectStyle}
          >
            <option value="">Toutes criticités</option>
            {Object.entries(CRITICITE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <select
            value={filterCategory}
            onChange={e => setFilterCategory(e.target.value)}
            style={filterCategory ? activeFilterStyle : filterSelectStyle}
          >
            <option value="">Toutes catégories</option>
            {categoryOptions.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select
            value={filterNetworkStatus}
            onChange={e => setFilterNetworkStatus(e.target.value)}
            style={filterNetworkStatus ? activeFilterStyle : filterSelectStyle}
          >
            <option value="">Tout statut réseau</option>
            {Object.entries(NETWORK_STATUS_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <select
            value={configFilter}
            onChange={e => setConfigFilter(e.target.value)}
            style={configFilter !== 'all' ? activeFilterStyle : filterSelectStyle}
          >
            <option value="all">Configurés et non configurés</option>
            <option value="configured">Configurés uniquement</option>
            <option value="unconfigured">Non configurés uniquement</option>
          </select>
          <button onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg transition-colors flex-shrink-0"
            style={{ background: MODULE_COLOR, color: MODULES.inventaire.dark }}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Ajouter un actif
          </button>
        </div>
      </PageHero>

      {selectedAssetIds.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.25)' }}>
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            {selectedAssetIds.size} actif{selectedAssetIds.size !== 1 ? 's' : ''} sélectionné{selectedAssetIds.size !== 1 ? 's' : ''}
          </span>
          <button
            onClick={handleBulkScan}
            disabled={!!bulkScanProgress}
            className="px-3 py-1.5 text-xs font-medium rounded-lg"
            style={{ background: 'var(--accent-blue)', color: '#fff', opacity: bulkScanProgress ? 0.6 : 1, cursor: bulkScanProgress ? 'default' : 'pointer' }}
          >
            {bulkScanProgress || `🔍 Scanner la sélection (${selectedAssetIds.size})`}
          </button>
          <button
            onClick={() => setBulkDeleteModal(true)}
            disabled={!!bulkScanProgress}
            className="px-3 py-1.5 text-xs font-medium rounded-lg disabled:opacity-40"
            style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' }}
          >
            🗑 Supprimer la sélection ({selectedAssetIds.size})
          </button>
          {!bulkScanProgress && (
            <button onClick={() => setSelectedAssetIds(new Set())} className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Annuler la sélection
            </button>
          )}
        </div>
      )}

      <div style={CARD} className="overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
              <th className="px-4 py-3">
                <input type="checkbox" checked={allVisibleSelected} onChange={toggleSelectAllVisible} title="Tout sélectionner (actifs visibles)" />
              </th>
              {['Nom', 'OS', 'Catégorie', 'Criticité', 'Réseau', 'Source', 'Méthode', 'Dernier scan', 'Apps', 'Vulnérabilités ouvertes', 'Mises à jour', 'Actions'].map(h => (
                <th key={h}
                  className={`px-4 py-3 text-xs font-semibold uppercase tracking-wide ${['Catégorie', 'Réseau', 'Méthode'].includes(h) ? 'text-center' : 'text-left'}`}
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assetList.length === 0 && (
              <tr><td colSpan={13} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif importé</td></tr>
            )}
            {assetList.length > 0 && filteredAssets.length === 0 && (
              <tr><td colSpan={13} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun actif ne correspond à ces filtres</td></tr>
            )}
            {filteredAssets.map(a => {
              const count = a.open_vuln_count || 0
              const pct = Math.round((count / maxVulns) * 100)
              const barColor = count === 0 ? '#3fb950' : count > 10 ? '#f85149' : '#fb8f44'
              const countColor = count === 0 ? '#3fb950' : count > 10 ? '#f85149' : '#fb8f44'
              const sourceStyle = SOURCE_STYLES[a.source] || SOURCE_STYLES.csv
              return (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onMouseEnter={e => e.currentTarget.style.background = MODULE_HOVER}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="px-4 py-3">
                    <input type="checkbox" checked={selectedAssetIds.has(a.id)} onChange={() => toggleSelectAsset(a.id)} />
                  </td>
                  <td className="px-4 py-3 font-semibold">
                    <div className="flex items-center gap-2">
                      <ConnectivityDot assetType={a.asset_type} reachable={a.last_scan_result?.reachable} error={a.last_scan_result?.error} />
                      <button onClick={() => handleViewPackages(a)}
                        className="hover:underline text-left"
                        style={{ color: 'var(--text-primary)' }}
                        title="Voir les infos détaillées (OS, specs matérielles, applications)"
                      >{a.name}</button>
                      {isNewAsset(a.created_at) && (
                        <span className="text-[9px] px-1 py-px rounded font-bold uppercase tracking-wide flex-shrink-0 leading-none"
                          style={{ background: 'rgba(163,113,247,0.15)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }}
                          title={`Ajouté le ${new Date(a.created_at).toLocaleString('fr-FR')}`}>
                          New
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {(() => {
                      const { label, style } = osCell(a)
                      return (
                        <span className="inline-flex items-center gap-1.5">
                          <OsLogo os={a.os} />
                          {style
                            ? <span className="px-2 py-0.5 rounded-md font-medium whitespace-nowrap" style={style}>{label}</span>
                            : <span style={{ color: 'var(--text-muted)' }}>{label}</span>}
                        </span>
                      )
                    })()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-center" title={assetCategory(a)}>
                      <CategoryIcon category={assetCategory(a)} style={{ color: categoryStyle(assetCategory(a)).color }} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <CriticiteBadge value={a.tags?.criticite} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-center gap-1.5">
                      <NetworkStatusBadge networkStatus={a.network_status} compact />
                      <NetworkComplianceBadge networkCompliance={a.network_compliance} compact />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs px-2 py-0.5 rounded-md font-medium whitespace-nowrap" style={sourceStyle}>
                      {SOURCE_LABELS[a.source] || a.source || '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-center">
                      <CollectionMethodIcon method={a.collection_method} />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {a.last_scan ? new Date(a.last_scan).toLocaleDateString('fr-FR') : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {a.package_count > 0 ? (
                        <button onClick={() => handleViewPackages(a)}
                          className="px-2 py-0.5 rounded-md font-medium"
                          style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)' }}
                        >{a.package_count} app{a.package_count !== 1 ? 's' : ''}</button>
                      ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      {/* MAJ dispo indépendamment d'une CVE connue (10/08/2026, `apt list --upgradable`
                          côté serveur, jamais `apt update` déclenché par CBR) — Linux uniquement, aucun
                          équivalent Windows possible avec le compte de service read-only (cf. backend). */}
                      {a.available_updates_count > 0 && (
                        <button onClick={() => handleViewPackages(a)}
                          className="px-2 py-0.5 rounded-md font-medium"
                          style={{ background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px solid rgba(210,153,34,0.25)' }}
                          title={`${a.available_updates_count} paquet${a.available_updates_count !== 1 ? 's' : ''} avec une version plus récente dans le cache apt local du serveur — indépendamment de toute CVE connue`}
                        >{a.available_updates_count} MAJ dispo</button>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--bg-secondary)' }}>
                        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: barColor }} />
                      </div>
                      <span className="text-xs font-semibold w-5 text-right" style={{ color: countColor }}>{count}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <PendingUpdatesBadge
                      pendingUpdates={a.pending_updates}
                      onClick={isFakeId(a.id) ? undefined : () => setPendingUpdatesModal(a)}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <button onClick={() => handleRowScanClick(a)}
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: scanLoading[a.id] ? '#58a6ff' : 'var(--text-muted)' }}
                        onMouseEnter={e => { if (!scanLoading[a.id]) { e.currentTarget.style.background = 'rgba(88,166,255,0.1)'; e.currentTarget.style.color = '#58a6ff' } }}
                        onMouseLeave={e => { if (!scanLoading[a.id]) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' } }}
                        title={a.last_scan ? "Voir le dernier scan (bouton “Relancer un scan” dans la fenêtre pour rescanner)" : "Scanner (vérifie la fiabilité des infos + liste les applications)"}
                      >
                        {scanLoading[a.id] ? (
                          <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                        ) : (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0z" />
                          </svg>
                        )}
                      </button>
                      <button onClick={() => { if (!isFakeId(a.id)) setEditTarget(a) }}
                        disabled={isFakeId(a.id)}
                        className="p-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        style={{ color: 'var(--text-muted)' }}
                        onMouseEnter={e => { if (!isFakeId(a.id)) { e.currentTarget.style.background = 'var(--border)'; e.currentTarget.style.color = 'var(--text-primary)' } }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' }}
                        title={isFakeId(a.id) ? 'Actif de démonstration — non modifiable' : 'Modifier cet actif'}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button onClick={() => { if (!isFakeId(a.id)) setDeleteTarget(a) }}
                        disabled={isFakeId(a.id)}
                        className="p-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        style={{ color: 'var(--text-muted)' }}
                        onMouseEnter={e => { if (!isFakeId(a.id)) { e.currentTarget.style.background = 'rgba(248,81,73,0.1)'; e.currentTarget.style.color = '#f85149' } }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' }}
                        title={isFakeId(a.id) ? 'Actif de démonstration — non supprimable' : 'Supprimer cet actif'}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        </div>
      </div>

      {showAddModal && (
        <AssetFormModal onClose={() => setShowAddModal(false)} onSaved={handleSaved} />
      )}
      {editTarget && (
        <AssetFormModal asset={editTarget} onClose={() => setEditTarget(null)} onSaved={handleSaved} />
      )}
      {deleteTarget && (
        <DeleteAssetModal asset={deleteTarget} onClose={() => setDeleteTarget(null)} onDeleted={handleDeleted} />
      )}
      {bulkDeleteModal && (
        <BulkDeleteAssetsModal
          assets={assetList.filter(a => selectedAssetIds.has(a.id))}
          onClose={() => setBulkDeleteModal(false)}
          onDeleted={handleBulkDeleted}
        />
      )}
      {scanModal && (
        <ScanResultModal asset={scanModal.asset} result={scanModal.result} onClose={() => setScanModal(null)}
          onRescan={isFakeId(scanModal.asset.id) ? undefined : () => handleScan(scanModal.asset)}
          rescanning={!!scanLoading[scanModal.asset.id]}
        />
      )}
      {pendingUpdatesModal && (
        <PendingUpdatesModal asset={pendingUpdatesModal} onClose={() => setPendingUpdatesModal(null)} />
      )}
    </div>
  )
}
