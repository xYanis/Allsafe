// Partagé entre Assets.jsx et Inventaire.jsx (même parc d'actifs, deux vues —
// sécurité vs patrimoine, cf. CLAUDE.md) : catégorie lisible d'un actif, dérivée
// pour un équipement Meraki du préfixe de modèle (nomenclature officielle Cisco
// Meraki : MR=borne Wi-Fi, MX=sécurité/SD-WAN, MS=switch, MG=passerelle
// cellulaire, MT=capteur, MV=caméra, Z=passerelle télétravail). PRTG ne remonte
// aucun modèle exploitable par device (cf. STATUS.md 04/08/2026) : reste générique.

export const TYPE_LABELS = { server: 'Serveur', workstation: 'Poste', network: 'Réseau' }

const MERAKI_MODEL_LABELS = {
  MR: 'Borne Wi-Fi', MX: 'Pare-feu / Routeur', MS: 'Switch',
  MG: 'Passerelle cellulaire', MT: 'Capteur', MV: 'Caméra', Z: 'Passerelle télétravail',
}

export function merakiModelLabel(os) {
  const prefix = os?.match(/^([A-Z]+)/)?.[1]
  return prefix ? MERAKI_MODEL_LABELS[prefix] : undefined
}

// PRTG ne remonte aucun modèle par device (cf. ci-dessus), seulement un vendor sur
// quelques cas repérés via un type de capteur précis (`hardware.vendor_hint`,
// services/prtg_client.py::VENDOR_SENSOR_TYPE_HINTS — "Synology" est le seul cas
// tenu à ce jour). Tenu à la main au cas par cas comme côté backend, pas une
// tentative de couvrir tous les vendors possibles.
const VENDOR_CATEGORY_LABELS = { Synology: 'NAS' }

// Catégorie tous actifs confondus (pas seulement réseau) — "Serveur"/"Poste" pour
// le parc scanné, catégorie de modèle, vendor connu (NAS...), ou générique
// "Équipement réseau" sinon.
export function assetCategory(asset) {
  if (asset.asset_type !== 'network') return TYPE_LABELS[asset.asset_type] || asset.asset_type || 'Autre'
  if (asset.source === 'meraki') return merakiModelLabel(asset.os) || 'Équipement réseau'
  const vendorHint = asset.hardware?.vendor_hint
  return VENDOR_CATEGORY_LABELS[vendorHint] || 'Équipement réseau'
}

// Une couleur par catégorie, pour qu'un coup d'œil suffise à distinguer les
// lignes du parc sans en ouvrir une seule.
const CATEGORY_STYLES = {
  'Serveur':                { background: 'rgba(88,166,255,0.12)',  color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)'  },
  'Poste':                  { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' },
  'Borne Wi-Fi':            { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  'Pare-feu / Routeur':     { background: 'rgba(248,81,73,0.12)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  'Switch':                 { background: 'rgba(57,197,207,0.12)',  color: '#39c5cf', border: '1px solid rgba(57,197,207,0.3)'  },
  'Passerelle cellulaire':  { background: 'rgba(219,109,40,0.12)',  color: '#db6d28', border: '1px solid rgba(219,109,40,0.3)'  },
  'Capteur':                { background: 'rgba(210,153,34,0.12)',  color: '#d29922', border: '1px solid rgba(210,153,34,0.3)'  },
  'Caméra':                 { background: 'rgba(219,109,153,0.12)', color: '#db6d99', border: '1px solid rgba(219,109,153,0.3)' },
  'Passerelle télétravail': { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  'Équipement réseau':      { background: 'rgba(110,118,129,0.12)', color: '#6e7681', border: '1px solid rgba(110,118,129,0.3)' },
  'NAS':                    { background: 'rgba(121,192,255,0.12)', color: '#79c0ff', border: '1px solid rgba(121,192,255,0.3)' },
}
const DEFAULT_CATEGORY_STYLE = { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
export function categoryStyle(category) {
  return CATEGORY_STYLES[category] || DEFAULT_CATEGORY_STYLE
}
