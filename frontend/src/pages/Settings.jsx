import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTheme } from '../contexts/ThemeContext.jsx'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import { useAuth } from '../contexts/AuthContext.jsx'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { useAnalystPreference } from '../contexts/AnalystPreferenceContext.jsx'
import { useGuidePreference } from '../contexts/GuidePreferenceContext.jsx'
import { changeEmail, changePassword, integrationsStatus, mySessions, revokeMySession, scanPolicies, updateScanPolicy, runScanPolicyNow } from '../api/client.js'
import PageHero from '../components/PageHero.jsx'
import PasswordInput from '../components/PasswordInput.jsx'
import PasswordStrengthHint, { passwordMeetsPolicy } from '../components/PasswordStrengthHint.jsx'
import ScanPolicyFormModal, { SCAN_POLICY_CRITICITE_LABELS, SCAN_POLICY_WEEKDAY_LABELS } from '../components/ScanPolicyFormModal.jsx'
import { MODULES } from '../constants/modules.js'
import { tintedCard } from '../utils/cardStyle.js'

const CARD = tintedCard(MODULES.parametres.color)
const TEXT_INPUT = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR') + ' ' + new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Même utilitaire que ConnectionsTab (AdministrationSecurity.jsx) — dupliqué plutôt que
// partagé pour un one-liner sans état, cf. principe déjà appliqué ailleurs dans ce fichier.
function shortUserAgent(ua) {
  return ua ? ua.replace(/\(.*?\)/g, '').trim().split(' ').slice(0, 3).join(' ') : '—'
}

// Icônes de section — même famille (Heroicons outline) que le reste de l'app
// (cf. ICONS dans Layout.jsx), dupliquées localement pour les mêmes raisons que
// dans AdministrationSecurity.jsx.
const SECTION_ICON_PATHS = {
  presentation: 'M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z|M15 12a3 3 0 11-6 0 3 3 0 016 0z',
  appearance: 'M21.752 15.002A9.72 9.72 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z',
  account: 'M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z',
  security: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  sessions: 'M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25',
  integrations: 'M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244',
}

function SectionIcon({ name }) {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      {SECTION_ICON_PATHS[name].split('|').map((d, i) => (
        <path key={i} strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={d} />
      ))}
    </svg>
  )
}

function Switch({ checked, onChange, ariaLabel }) {
  return (
    <button
      onClick={onChange}
      aria-label={ariaLabel}
      style={{
        width: 44, height: 24, borderRadius: 12, padding: 2, border: 'none', cursor: 'pointer',
        background: checked ? 'var(--accent-blue)' : '#d0d7de',
        boxShadow: checked ? '0 0 0 3px color-mix(in srgb, var(--accent-blue) 20%, transparent)' : 'none',
        transition: 'background 0.2s, box-shadow 0.2s',
        display: 'flex', alignItems: 'center',
      }}
    >
      <span style={{
        width: 20, height: 20, borderRadius: '50%', background: '#fff', display: 'block',
        transform: checked ? 'translateX(20px)' : 'translateX(0)', transition: 'transform 0.2s',
        boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </button>
  )
}

// Mise en page à deux volets (14/08/2026, demande explicite — même schéma que
// Notes.jsx : nav à icônes sans bordure à gauche, panneau de contenu à droite),
// mais sans tuile par ligne à l'intérieur du panneau — un seul bloc de contenu,
// pas une carte par réglage comme l'ancienne version empilée.
export default function Settings() {
  const navigate = useNavigate()
  const { isDark, toggle } = useTheme()
  const { isAnonymous, toggle: toggleAnonymous } = usePresentation()
  const { user, logout, refresh } = useAuth()
  const { names: analystNames } = useAnalysts()
  const { preferredAnalyst, setPreferredAnalyst } = useAnalystPreference()
  const { guidesHidden, setGuidesHidden } = useGuidePreference()
  const [section, setSection] = useState('presentation')

  // Modification du compte (14/08/2026, demande utilisateur) — jusqu'ici seule la
  // déconnexion était possible depuis cette section. Deux formulaires indépendants
  // (email / mot de passe), chacun son propre état de soumission/erreur : pas de
  // raison de faire échouer l'un si l'autre est invalide.
  const [editingAccount, setEditingAccount] = useState(false)
  const [newEmail, setNewEmail] = useState('')
  const [emailPassword, setEmailPassword] = useState('')
  const [emailBusy, setEmailBusy] = useState(false)
  const [emailMsg, setEmailMsg] = useState(null) // { ok: bool, text }

  const [pwCurrent, setPwCurrent] = useState('')
  const [pwNext, setPwNext] = useState('')
  const [pwBusy, setPwBusy] = useState(false)
  const [pwMsg, setPwMsg] = useState(null)

  // Sessions actives de son propre compte (14/08/2026, demande utilisateur) — chargées à
  // la demande (au premier passage sur la section), pas au montage de la page : la plupart
  // des visites sur Paramètres ne vont jamais y regarder.
  const [sessions, setSessions] = useState(null) // null = pas encore chargé
  const [sessionsError, setSessionsError] = useState('')
  const [revokingId, setRevokingId] = useState(null)

  const [integrations, setIntegrations] = useState(null)
  const [integrationsError, setIntegrationsError] = useState('')

  // Politiques de scan planifié par criticité (17/08/2026) — même section que les intégrations,
  // rechargées à chaque succès (edit/run-now) plutôt qu'un état optimiste, la liste ne fait que
  // 4 lignes.
  const [scanPoliciesList, setScanPoliciesList] = useState(null)
  const [scanPoliciesError, setScanPoliciesError] = useState('')
  const [editingPolicy, setEditingPolicy] = useState(null)
  const [runningNow, setRunningNow] = useState(null)

  function loadScanPolicies() {
    scanPolicies().then(r => setScanPoliciesList(r.data.items))
      .catch(() => setScanPoliciesError('Impossible de charger les politiques de scan.'))
  }

  useEffect(() => {
    if (section === 'sessions' && sessions === null) {
      mySessions().then(r => setSessions(r.data.items))
        .catch(() => setSessionsError('Impossible de charger les sessions actives.'))
    }
    if (section === 'integrations' && integrations === null) {
      integrationsStatus().then(r => setIntegrations(r.data.items))
        .catch(() => setIntegrationsError('Impossible de charger le statut des intégrations.'))
    }
    if (section === 'integrations' && scanPoliciesList === null) {
      loadScanPolicies()
    }
  }, [section, sessions, integrations, scanPoliciesList])

  async function handleSavePolicy(criticite, data) {
    await updateScanPolicy(criticite, data)
    setEditingPolicy(null)
    loadScanPolicies()
  }

  async function handleRunPolicyNow(criticite) {
    if (runningNow) return
    setRunningNow(criticite)
    try {
      await runScanPolicyNow(criticite)
      loadScanPolicies()
    } catch (err) {
      setScanPoliciesError(err?.response?.data?.detail || 'Impossible de lancer ce scan.')
    } finally {
      setRunningNow(null)
    }
  }

  async function handleRevokeSession(id) {
    if (revokingId) return
    setRevokingId(id)
    try {
      await revokeMySession(id)
      setSessions(list => list.filter(s => s.id !== id))
    } catch (err) {
      setSessionsError(err?.response?.data?.detail || 'Impossible de révoquer cette session.')
    } finally {
      setRevokingId(null)
    }
  }

  async function handleEmailSubmit(e) {
    e.preventDefault()
    if (emailBusy) return
    setEmailBusy(true); setEmailMsg(null)
    try {
      await changeEmail(emailPassword, newEmail)
      await refresh()
      setEmailMsg({ ok: true, text: 'Email mis à jour.' })
      setNewEmail(''); setEmailPassword('')
    } catch (err) {
      setEmailMsg({ ok: false, text: err?.response?.data?.detail || "Impossible de modifier l'email." })
    } finally {
      setEmailBusy(false)
    }
  }

  async function handlePasswordSubmit(e) {
    e.preventDefault()
    if (pwBusy) return
    setPwBusy(true); setPwMsg(null)
    try {
      await changePassword(pwCurrent, pwNext)
      setPwMsg({ ok: true, text: 'Mot de passe mis à jour.' })
      setPwCurrent(''); setPwNext('')
    } catch (err) {
      setPwMsg({ ok: false, text: err?.response?.data?.detail || 'Impossible de changer le mot de passe.' })
    } finally {
      setPwBusy(false)
    }
  }
  // #f85149 sur un fond clair tombe sous le seuil WCAG AA (~3:1) — repéré en tour UX
  // (03/08/2026). Rouge assombri en mode clair uniquement (même convention rouge
  // "danger" que le reste de l'app, juste recalibrée pour rester lisible sur blanc ;
  // #f85149 inchangé en mode sombre, où il reste conforme).
  const dangerColor = isDark ? '#f85149' : '#cf222e'
  const dangerBg     = isDark ? 'rgba(248,81,73,0.1)'  : 'rgba(207,34,46,0.08)'
  const dangerBorder = isDark ? 'rgba(248,81,73,0.2)'  : 'rgba(207,34,46,0.25)'

  const SECTIONS = [
    { key: 'presentation', label: 'Présentation', desc: isAnonymous ? 'Anonyme activé' : 'Données réelles', icon: 'presentation' },
    { key: 'appearance',   label: 'Apparence',    desc: isDark ? 'Mode sombre' : 'Mode clair', icon: 'appearance' },
    ...(user ? [{ key: 'account', label: 'Compte', desc: user.full_name, icon: 'account' }] : []),
    ...(user ? [{ key: 'sessions', label: 'Sessions', desc: 'Appareils connectés', icon: 'sessions' }] : []),
    { key: 'integrations', label: 'Intégrations', desc: 'Sources externes', icon: 'integrations' },
    // Pas de contenu propre — navigue directement vers la page dédiée (réservée admin),
    // comme un lien plutôt qu'un onglet ; cf. onClick spécifique ci-dessous.
    ...(user?.role === 'admin' ? [{ key: 'security', label: 'Sécurité', desc: 'Administration', icon: 'security', link: '/settings/administration' }] : []),
  ]

  return (
    <div className="p-6 space-y-5">
      <PageHero
        icon="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z"
        title="Paramètres" color="#8b949e"
        subtitle="Configuration d'Allsafe"
      />

      <div className="flex flex-col lg:flex-row gap-5 items-start">
        <nav className="w-full lg:w-64 flex-shrink-0 flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible pb-1">
          {SECTIONS.map(s => {
            const active = s.key === section
            return (
              <button key={s.key} onClick={() => s.link ? navigate(s.link) : setSection(s.key)}
                className="flex-shrink-0 w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors"
                style={{
                  // Gris du module Paramètres (18/08/2026, demande explicite — uniforme, pas le
                  // bleu accent générique repris par erreur d'un autre pattern de l'app).
                  background: active ? `color-mix(in srgb, ${MODULES.parametres.color} 12%, transparent)` : 'transparent',
                  boxShadow: active ? `inset 3px 0 0 0 ${MODULES.parametres.color}` : 'none',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg-secondary)' }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
              >
                <span className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{
                  background: active ? `color-mix(in srgb, ${MODULES.parametres.color} 20%, transparent)` : 'var(--bg-secondary)',
                  color: active ? MODULES.parametres.color : 'var(--text-muted)',
                }}>
                  <SectionIcon name={s.icon} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium truncate" style={{ color: active ? MODULES.parametres.color : 'var(--text-primary)' }}>{s.label}</span>
                  <span className="hidden lg:block text-xs truncate" style={{ color: 'var(--text-muted)' }}>{s.desc}</span>
                </span>
                {s.link && (
                  <svg className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                )}
              </button>
            )
          })}
        </nav>

        <div style={CARD} className="flex-1 min-w-0 p-6">
          {section === 'presentation' && (
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Anonyme</p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  {isAnonymous
                    ? 'Activé — noms d\'actifs, IP et analystes remplacés par des données fictives, parc complété par des actifs de démonstration'
                    : 'Désactivé — données réelles affichées'}
                </p>
              </div>
              <Switch checked={isAnonymous} onChange={toggleAnonymous} ariaLabel="Basculer le mode Anonyme" />
            </div>
          )}

          {section === 'appearance' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Thème</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {isDark ? 'Mode sombre' : 'Mode clair'}
                  </p>
                </div>
                <Switch checked={isDark} onChange={toggle} ariaLabel="Basculer le thème" />
              </div>
              <div className="flex items-center justify-between gap-4 pt-5" style={{ borderTop: '1px solid var(--border)' }}>
                <div>
                  <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Guides d'aide</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {guidesHidden
                      ? "Masqués — le bouton d'aide « ? » n'apparaît sur aucune page"
                      : "Affichés — un bouton d'aide « ? » en bas à droite de chaque page"}
                  </p>
                </div>
                <Switch checked={!guidesHidden} onChange={() => setGuidesHidden(v => !v)} ariaLabel="Afficher ou masquer les guides d'aide" />
              </div>
            </div>
          )}

          {section === 'account' && user && (
            <div>
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{user.full_name}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{user.email}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button onClick={() => setEditingAccount(v => !v)}
                    className="text-sm px-4 py-2 rounded-lg font-medium transition-colors"
                    style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                  >{editingAccount ? 'Fermer' : 'Modifier'}</button>
                  <button onClick={logout}
                    className="text-sm px-4 py-2 rounded-lg font-medium transition-colors"
                    style={{ background: dangerBg, color: dangerColor, border: `1px solid ${dangerBorder}` }}
                    onMouseEnter={e => e.currentTarget.style.background = isDark ? 'rgba(248,81,73,0.18)' : 'rgba(207,34,46,0.14)'}
                    onMouseLeave={e => e.currentTarget.style.background = dangerBg}
                  >Se déconnecter</button>
                </div>
              </div>

              <div className="mt-5 pt-5 flex items-center justify-between gap-4" style={{ borderTop: '1px solid var(--border)' }}>
                <div>
                  <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Nom d'analyste par défaut</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Pré-sélectionné/mis en avant dans les dropdowns "Validé par" — Dashboard, Vulnérabilités, Veille.
                  </p>
                </div>
                <select value={preferredAnalyst} onChange={e => setPreferredAnalyst(e.target.value)}
                  className="text-sm rounded-lg px-3 py-2 outline-none flex-shrink-0" style={TEXT_INPUT}>
                  <option value="">Aucun</option>
                  {analystNames.map(name => <option key={name} value={name}>{name}</option>)}
                </select>
              </div>

              {editingAccount && (
                <div className="mt-5 pt-5 space-y-6" style={{ borderTop: '1px solid var(--border)' }}>
                  <form onSubmit={handleEmailSubmit} className="space-y-2">
                    <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Changer l'email</p>
                    <div className="flex flex-wrap items-start gap-2">
                      <input type="email" required placeholder="Nouvel email" value={newEmail}
                        onChange={e => setNewEmail(e.target.value)}
                        className="flex-1 min-w-[180px] text-sm rounded-lg px-3 py-2 outline-none" style={TEXT_INPUT} />
                      <div className="flex-1 min-w-[180px]">
                        <PasswordInput placeholder="Mot de passe actuel" value={emailPassword} onChange={e => setEmailPassword(e.target.value)} />
                      </div>
                      <button type="submit" disabled={emailBusy || !newEmail || !emailPassword}
                        className="text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-50 flex-shrink-0"
                        style={{ background: 'var(--accent-blue)', color: '#fff' }}
                      >{emailBusy ? 'Enregistrement…' : 'Enregistrer'}</button>
                    </div>
                    {emailMsg && <p className="text-xs" style={{ color: emailMsg.ok ? '#3fb950' : '#f85149' }}>{emailMsg.text}</p>}
                  </form>

                  <form onSubmit={handlePasswordSubmit} className="space-y-2">
                    <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Changer le mot de passe</p>
                    <div className="grid sm:grid-cols-2 gap-2">
                      <PasswordInput placeholder="Mot de passe actuel" value={pwCurrent} onChange={e => setPwCurrent(e.target.value)} />
                      <PasswordInput placeholder="Nouveau mot de passe" minLength={16} value={pwNext} onChange={e => setPwNext(e.target.value)} />
                    </div>
                    {pwNext && <PasswordStrengthHint password={pwNext} />}
                    {pwMsg && <p className="text-xs" style={{ color: pwMsg.ok ? '#3fb950' : '#f85149' }}>{pwMsg.text}</p>}
                    <button type="submit" disabled={pwBusy || !pwCurrent || !passwordMeetsPolicy(pwNext)}
                      className="text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-50"
                      style={{ background: 'var(--accent-blue)', color: '#fff' }}
                    >{pwBusy ? 'Enregistrement…' : 'Enregistrer le mot de passe'}</button>
                  </form>
                </div>
              )}
            </div>
          )}

          {section === 'sessions' && (
            <div>
              <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                Appareils actuellement connectés à votre compte — révoquez ceux que vous ne reconnaissez pas.
              </p>
              {sessionsError && <p className="text-xs mb-2" style={{ color: '#f85149' }}>{sessionsError}</p>}
              {sessions === null ? (
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
              ) : sessions.length === 0 ? (
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucune session active.</p>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {sessions.map(s => (
                    <div key={s.id} className="py-3 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                          {shortUserAgent(s.user_agent)}
                          {s.is_current && (
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md" style={{ background: 'color-mix(in srgb, #3fb950 18%, transparent)', color: '#3fb950' }}>
                              Cet appareil
                            </span>
                          )}
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                          {s.ip_address || '—'} · Connecté le {fmtDate(s.created_at)}
                        </p>
                      </div>
                      {!s.is_current && (
                        <button onClick={() => handleRevokeSession(s.id)} disabled={revokingId === s.id}
                          className="text-xs px-3 py-1.5 rounded-lg font-medium disabled:opacity-50 flex-shrink-0"
                          style={{ background: dangerBg, color: dangerColor, border: `1px solid ${dangerBorder}` }}
                        >{revokingId === s.id ? 'Révocation…' : 'Révoquer'}</button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {section === 'integrations' && (
            <div>
              <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                Sources externes configurées côté serveur (<code>.env</code>) — vue d'ensemble en lecture seule, aucun secret n'est affiché ici.
              </p>
              {integrationsError && <p className="text-xs mb-2" style={{ color: '#f85149' }}>{integrationsError}</p>}
              {integrations === null ? (
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {integrations.map(i => (
                    <div key={i.key} className="py-3 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.label}</p>
                        {i.configured && i.last_synced_at && (
                          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Dernière synchro : {fmtDate(i.last_synced_at)}</p>
                        )}
                      </div>
                      <span className="text-[11px] font-semibold px-2 py-1 rounded-md flex-shrink-0" style={{
                        background: i.configured ? 'color-mix(in srgb, #3fb950 16%, transparent)' : 'var(--bg-secondary)',
                        color: i.configured ? '#3fb950' : 'var(--text-muted)',
                      }}>
                        {i.configured ? 'Configuré' : 'Non configuré'}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <p className="text-xs mt-6 mb-3" style={{ color: 'var(--text-muted)' }}>
                Politiques de scan planifié — scan d'inventaire/durcissement (SSH/WinRM + sites web)
                par groupe de criticité, cf. <code>services/scan_policy.py</code>.
              </p>
              {scanPoliciesError && <p className="text-xs mb-2" style={{ color: '#f85149' }}>{scanPoliciesError}</p>}
              {scanPoliciesList === null ? (
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                  {scanPoliciesList.map(p => (
                    <div key={p.criticite} className="py-3 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                          {SCAN_POLICY_CRITICITE_LABELS[p.criticite] || p.criticite}
                          {!p.enabled && <span className="ml-2 text-xs font-normal" style={{ color: 'var(--text-muted)' }}>(désactivée)</span>}
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                          {p.frequency === 'daily' ? 'Quotidien' : `Hebdomadaire — ${SCAN_POLICY_WEEKDAY_LABELS[p.weekday] || '?'}`}
                          {' '}à {String(p.hour).padStart(2, '0')}h00
                          {p.last_run_at && ` — dernière exécution : ${fmtDate(p.last_run_at)}`}
                          {p.running && ' — en cours…'}
                        </p>
                      </div>
                      {user?.role === 'admin' && (
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button onClick={() => handleRunPolicyNow(p.criticite)} disabled={p.running || runningNow === p.criticite}
                            className="text-xs px-2.5 py-1.5 rounded-lg font-medium disabled:opacity-50"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                          >{runningNow === p.criticite || p.running ? 'En cours…' : 'Lancer maintenant'}</button>
                          <button onClick={() => setEditingPolicy(p)}
                            className="text-xs px-2.5 py-1.5 rounded-lg font-medium"
                            style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
                          >Modifier</button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {editingPolicy && (
        <ScanPolicyFormModal
          initial={editingPolicy}
          onConfirm={(data) => handleSavePolicy(editingPolicy.criticite, data)}
          onClose={() => setEditingPolicy(null)}
        />
      )}
    </div>
  )
}
