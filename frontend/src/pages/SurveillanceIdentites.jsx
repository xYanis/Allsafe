import { useEffect, useState, useCallback } from 'react'
import { watchedIdentities, createIdentity, deleteIdentity, identityMatches } from '../api/client.js'
import FlagIcon from '../components/FlagIcon.jsx'
import { hexToRgba } from '../utils/color.js'
import { usePresentation } from '../contexts/PresentationContext.jsx'
import {
  isFakeId, anonymizeIdentity, anonymizeIdentityMatch, anonymizeIpMatch, anonymizeOsintMatch,
  FAKE_IDENTITIES, FAKE_IDENTITY_MATCHES, FAKE_IP_MATCHES, FAKE_OSINT_MATCHES,
} from '../utils/fakeData.js'
import PageLoader from '../components/PageLoader.jsx'

// Module Surveillance Identités (CyberVeille, couleur bleue #58a6ff) — repère
// les items de fuite de données concernant l'entreprise, en croisant des
// identités surveillées (nom + domaines, éditables ici) avec les fuites déjà
// collectées par la Veille (sources leak). Aucune source externe propre, 100%
// gratuit. Limite : ne voit que ce qui est publiquement rapporté par ces
// sources (cf. models.WatchedIdentity).
//
// IP/plage IP (kind="ip"/"ip_range") : une IP n'apparaît quasiment jamais dans
// le texte des sources de fuite (vérifié : 0/1500+ items) — vérifiées à la
// place contre des listes de blocage tierces (IPsum, Blocklist.de, Feodo
// Tracker), cf. services/ip_watch.py. Signal différent : pas "un article vous
// cite", mais "une machine de votre parc semble compromise".
//
// Email (kind="email", 28/07/2026) et vérification GitHub sur les domaines :
// deux sources gratuites en plus, interrogées en direct (cf.
// services/leak_lookup.py) — XposedOrNot (fuites connues pour un email,
// équivalent gratuit de HIBP, payant depuis 2023) et une recherche de code
// GitHub sur les domaines (identifiants committés par erreur, désactivée sans
// GITHUB_TOKEN configuré). Un premier brouillon à base d'API payantes (HIBP,
// IntelX, Hunter.io, Shodan, Censys, SecurityTrails) a été explicitement
// écarté pour rester 100% gratuit (cf. STATUS.md).
const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px' }
const ACCENT = '#58a6ff'

const KIND_OPTIONS = [
  { value: 'name',     label: 'Nom' },
  { value: 'domain',   label: 'Domaine' },
  { value: 'ip',       label: 'IP' },
  { value: 'ip_range', label: 'Plage IP' },
  { value: 'email',    label: 'Email' },
]
const KIND_PLACEHOLDERS = {
  name: 'Nom de l\'entreprise (ex : AER)',
  domain: 'Domaine (ex : aer.fr)',
  ip: 'Adresse IP publique (ex : 203.0.113.10)',
  ip_range: 'Plage IP au format CIDR (ex : 203.0.113.0/24)',
  email: 'Adresse email (ex : contact@aer.fr)',
}
const KIND_LABELS = { name: 'Nom', domain: 'Domaine', ip: 'IP', ip_range: 'Plage IP', email: 'Email' }

function truncate(text, max = 160) {
  if (!text) return ''
  return text.length > max ? text.slice(0, max).trimEnd() + '…' : text
}

// ransomware.live : titre "victime — groupe (activité)" — on isole la victime
// pour l'affichage (même logique que FuiteDeDonnees.parseCompany).
function displayTitle(item) {
  if (item.source !== 'ransomware-live') return item.title
  const m = item.title.match(/^(.*?) — /)
  return m ? m[1] : item.title
}

export default function SurveillanceIdentites() {
  const { isAnonymous } = usePresentation()
  const [identities, setIdentities] = useState([])
  const [matches, setMatches] = useState({ items: [], total: 0 })
  const [ipMatches, setIpMatches] = useState([])
  const [osintMatches, setOsintMatches] = useState([])
  const [loading, setLoading] = useState(true)
  const [value, setValue] = useState('')
  const [kind, setKind] = useState('name')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const reload = useCallback(() => {
    setLoading(true)
    Promise.all([
      watchedIdentities().then(r => r.data.identities),
      identityMatches().then(r => r.data),
    ]).then(([realIdentities, matchData]) => {
      const realMatches      = matchData.items
      const realIpMatches    = matchData.ip_matches || []
      const realOsintMatches = matchData.osint_matches || []
      if (isAnonymous) {
        setIdentities([...realIdentities.map(anonymizeIdentity), ...FAKE_IDENTITIES])
        const anonMatches = realMatches.map(m => anonymizeIdentityMatch(m, realIdentities))
        const items = [...anonMatches, ...FAKE_IDENTITY_MATCHES]
        setMatches({ items, total: items.length })
        const anonIpMatches = realIpMatches.map(m => anonymizeIpMatch(m, realIdentities))
        setIpMatches([...anonIpMatches, ...FAKE_IP_MATCHES])
        const anonOsintMatches = realOsintMatches.map(m => anonymizeOsintMatch(m, realIdentities))
        setOsintMatches([...anonOsintMatches, ...FAKE_OSINT_MATCHES])
      } else {
        setIdentities(realIdentities)
        setMatches({ items: realMatches, total: realMatches.length })
        setIpMatches(realIpMatches)
        setOsintMatches(realOsintMatches)
      }
    }).finally(() => setLoading(false))
  }, [isAnonymous])

  useEffect(() => { reload() }, [reload])

  async function handleAdd(e) {
    e.preventDefault()
    const v = value.trim()
    if (!v || isAnonymous) return
    setSaving(true)
    setError('')
    try {
      await createIdentity({ value: v, kind })
      setValue('')
      reload()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Erreur lors de l\'ajout.')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id) {
    if (isAnonymous || isFakeId(id)) return
    await deleteIdentity(id)
    reload()
  }

  const names     = identities.filter(i => i.kind === 'name')
  const domains   = identities.filter(i => i.kind === 'domain')
  const ips       = identities.filter(i => i.kind === 'ip')
  const ipRanges  = identities.filter(i => i.kind === 'ip_range')
  const emails    = identities.filter(i => i.kind === 'email')

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Surveillance Identités{' '}
          <span className="font-normal text-lg" style={{ color: 'var(--text-muted)' }}>({matches.total + ipMatches.length + osintMatches.length})</span>
        </h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Fuites de données mentionnant votre entreprise, croisées avec les sources de veille collectées,
          IP surveillées croisées avec des listes de blocage publiques, et emails/domaines vérifiés
          contre XposedOrNot et GitHub
        </p>
      </div>

      {/* Identités surveillées */}
      <div style={CARD} className="p-5 space-y-4">
        <div>
          <h2 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Identités surveillées</h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Ajoutez le nom de votre entreprise, vos domaines, une IP/plage IP publique, ou un email —
            chaque fuite ou correspondance mentionnant l'un d'eux remonte ci-dessous
          </p>
        </div>

        {isAnonymous ? (
          <p className="text-xs px-3 py-2 rounded-lg" style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
            Ajout/suppression désactivés en mode Anonyme — les identités ci-dessous sont fictives ou affichées à titre de démonstration.
          </p>
        ) : (
          <form onSubmit={handleAdd} className="flex flex-wrap items-center gap-2">
            <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
              {KIND_OPTIONS.map(({ value: k, label }) => (
                <button key={k} type="button" onClick={() => setKind(k)}
                  className="text-xs px-3 py-2 font-medium transition-colors"
                  style={kind === k
                    ? { background: hexToRgba(ACCENT, 0.15), color: ACCENT }
                    : { background: 'var(--bg-secondary)', color: 'var(--text-muted)' }
                  }
                >
                  {label}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={value}
              onChange={e => { setValue(e.target.value); setError('') }}
              placeholder={KIND_PLACEHOLDERS[kind]}
              className="flex-1 min-w-[200px] text-sm px-3 py-2 rounded-lg outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            />
            <button type="submit" disabled={saving || !value.trim()}
              className="px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
              style={{ background: ACCENT, color: '#fff' }}
            >
              {saving ? 'Ajout…' : 'Ajouter'}
            </button>
          </form>
        )}

        {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}

        {identities.length === 0 ? (
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucune identité surveillée pour l'instant.</p>
        ) : (
          <div className="space-y-2">
            {[['Noms', names], ['Domaines', domains], ['IP', ips], ['Plages IP', ipRanges], ['Emails', emails]].map(([label, list]) => list.length > 0 && (
              <div key={label} className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium w-20" style={{ color: 'var(--text-muted)' }}>{label} :</span>
                {list.map(i => (
                  <span key={i.id} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg font-medium"
                    style={{ background: hexToRgba(ACCENT, 0.12), color: ACCENT, border: `1px solid ${hexToRgba(ACCENT, 0.3)}` }}
                  >
                    {i.value}
                    {!isAnonymous && (
                      <button onClick={() => handleDelete(i.id)} title="Retirer"
                        className="w-3.5 h-3.5 rounded-full flex items-center justify-center"
                        style={{ color: ACCENT }}
                      >×</button>
                    )}
                  </span>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Résultats */}
      {loading ? (
        <div style={CARD} className="px-5 py-10 text-center">
          <PageLoader size="sm" />
        </div>
      ) : identities.length === 0 ? (
        <div style={CARD} className="px-5 py-10 text-center text-sm">
          <span style={{ color: 'var(--text-muted)' }}>Ajoutez une identité ci-dessus pour lancer la surveillance.</span>
        </div>
      ) : matches.items.length === 0 && ipMatches.length === 0 && osintMatches.length === 0 ? (
        <div style={CARD} className="px-5 py-10 text-center space-y-1">
          <p className="text-sm font-medium" style={{ color: '#3fb950' }}>Aucune fuite détectée</p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Aucune des sources collectées ne mentionne vos identités surveillées, aucune de vos IP
            n'apparaît sur les listes de blocage vérifiées, et aucun email/domaine n'a été retrouvé
            par XposedOrNot ou GitHub.
          </p>
        </div>
      ) : (
        <>
        {matches.items.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {matches.items.map(item => (
            <a key={item.id} href={item.url || '#'} target="_blank" rel="noopener noreferrer"
              style={CARD} className="flex flex-col px-4 py-4 transition-colors"
              onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-card)'}
            >
              <div className="flex items-start justify-between gap-2 mb-1">
                <div className="flex items-baseline gap-2 min-w-0">
                  <span className="text-xs px-2 py-0.5 rounded-md font-medium flex-shrink-0"
                    style={{ background: hexToRgba(ACCENT, 0.1), color: ACCENT, border: `1px solid ${hexToRgba(ACCENT, 0.2)}` }}>
                    {item.source_label}
                  </span>
                  <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{displayTitle(item)}</p>
                </div>
                <FlagIcon code={item.country} />
              </div>
              <div className="flex flex-wrap gap-1 mb-1.5">
                {item.matched_identities.map(v => (
                  <span key={v} className="text-xs px-1.5 py-0.5 rounded font-medium"
                    style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149', border: '1px solid rgba(248,81,73,0.2)' }}>
                    {v}
                  </span>
                ))}
              </div>
              {item.summary && (
                <p className="text-xs leading-relaxed mb-2" style={{ color: 'var(--text-muted)' }}>{truncate(item.summary)}</p>
              )}
              <span className="text-xs mt-auto pt-1" style={{ color: 'var(--text-muted)' }}>
                {item.received_at ? new Date(item.received_at).toLocaleDateString('fr-FR') : '—'}
              </span>
            </a>
          ))}
        </div>
        )}

        {ipMatches.length > 0 && (
        <div style={CARD} className="overflow-hidden">
          <div className="px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              IP surveillées sur des listes de blocage publiques
            </h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Signe qu'une machine correspondant à cette IP est probablement compromise (bot, scan, bruteforce…) —
              pas un article de presse, une liste tierce de menace (IPsum, Blocklist.de, Feodo Tracker)
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Votre identité', 'IP détectée', 'Source', 'Détail'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ipMatches.map((m, idx) => (
                  <tr key={idx} className="transition-colors" style={{ borderBottom: '1px solid var(--border-subtle)' }}
                    onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{m.identity_value}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'rgba(248,81,73,0.1)', color: '#f85149' }}>
                        {m.ip}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{m.source_label}</td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-muted)' }}>{m.detail || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        )}

        {osintMatches.length > 0 && (
        <div style={CARD} className="overflow-hidden">
          <div className="px-5 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              Emails et domaines vérifiés en direct
            </h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Email trouvé dans une fuite connue (XposedOrNot), ou domaine associé à un identifiant
              potentiel dans du code public (GitHub) — vérifié en direct, pas depuis la veille collectée
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  {['Votre identité', 'Source', 'Détail'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {osintMatches.map((m, idx) => (
                  <tr key={idx} className="transition-colors" style={{ borderBottom: '1px solid var(--border-subtle)' }}
                    onMouseEnter={e => e.currentTarget.style.background = hexToRgba(ACCENT, 0.04)}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td className="px-4 py-2.5 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{m.identity_value}</td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{m.source_label}</td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {m.url ? <a href={m.url} target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: ACCENT }}>{m.detail}</a> : (m.detail || '—')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        )}
        </>
      )}
    </div>
  )
}
