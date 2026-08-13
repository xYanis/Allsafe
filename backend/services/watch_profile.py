"""
watch_profile.py
Profil de veille : ce que le parc utilise réellement (OS, logiciels), pour mettre
en avant les éléments de veille qui le concernent.

**Ne filtre jamais la collecte ni le registre** — cf. docstring du modèle
`WatchProfileItem`. Le profil marque, il n'écarte pas.

Deux responsabilités :
- proposer des termes à partir de l'inventaire réel (`assets`), à cocher par
  l'analyste — jamais importés en bloc : un parc Debian remonte 300 paquets dont
  la quasi-totalité est du bruit (`adduser`, `base-files`…), et tout marquer
  revient à ne rien marquer ;
- dire si un élément de veille correspond au profil.
"""

import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Asset, WatchProfileItem, WatchItem

logger = logging.getLogger(__name__)

# Catégories du profil (session 22/07/2026) — seule source de vérité, utilisée
# par la validation du PUT (routers/watch.py) et par le frontend pour savoir
# quelles sections proposer des suggestions d'inventaire ou seulement un ajout
# manuel. Ajouter une 6e catégorie ne demande qu'une entrée ici, pas une
# modification éparpillée dans plusieurs fichiers (principe "penser scalable",
# CLAUDE.md).
#
# `from_inventory=False` pour firewall/saas : CBR ne scanne que les VM du parc
# (services/asset_scanner.py, WinRM/SSH) — un pare-feu ou un service SaaS
# n'apparaissent dans aucun relevé automatique. Ces catégories restent **saisie
# manuelle uniquement**, sans que ça les rende moins utiles : un pare-feu
# Fortinet est un point aveugle réel de la veille technologique sinon.
#
# `hardware` est passé à `from_inventory=True` le 04/08/2026 : les actifs réseau
# importés depuis PRTG (`services/prtg_matcher.py`) portent parfois un vendor
# détecté via le type de capteur (`Asset.hardware.vendor_hint`, ex. "Synology") —
# rendement volontairement faible (14 devices sur 410 au premier import), la
# grande majorité des équipements réseau (routeurs/bornes nommés par site) n'a
# aucune donnée vendor exploitable et reste hors de ce mécanisme. Toujours une
# **suggestion**, jamais un ajout automatique — même esprit que os/software.
PROFILE_CATEGORIES = {
    "os":           {"label": "Systèmes d'exploitation",       "from_inventory": True},
    "software":     {"label": "Logiciels",                     "from_inventory": True},
    "application":  {"label": "Applications",                  "from_inventory": False},
    "firewall":     {"label": "Firewall / Équipements réseau", "from_inventory": False},
    "saas":         {"label": "SaaS / Services cloud",         "from_inventory": False},
    "hardware":     {"label": "Matériel / Constructeurs",      "from_inventory": True},
}
# `application` (session 22/07/2026) — distinct de `software` : `software` reste
# la liste brute proposée depuis l'inventaire (ex. "VMware Tools", la chaîne
# exacte remontée par le paquet/programme installé) ; `application` est saisi à
# la main avec le nom de marque large qu'un article de veille emploie
# réellement ("VMware", pas "VMware Tools") — un article sur une faille VMware
# ne dit jamais "VMware Tools 12.3.5". Les deux catégories peuvent se recouper
# sur un même produit sans redondance gênante : l'une capte le nom exact
# installé, l'autre le nom sous lequel la presse en parle.

# Paquets présents sur toute installation et qui ne disent rien du rôle de la
# machine : les proposer noierait les quelques noms réellement utiles. Filtre
# volontairement conservateur — il ne masque que des évidences, l'analyste peut
# toujours ajouter un terme à la main.
_NOISE_PREFIXES = (
    "lib", "python3-", "perl-", "fonts-", "locales", "base-", "gcc-", "cpp-",
    "dpkg", "apt", "adduser", "debconf", "debian-", "init", "systemd", "sysvinit",
    "login", "passwd", "mount", "util-linux", "coreutils", "findutils", "grep",
    "gzip", "hostname", "ncurses", "readline", "sed", "tar", "zlib", "e2fs",
    "shared-mime", "xdg-", "x11-", "man-db", "media-types", "netbase", "tzdata",
    "ucf", "install-info", "iso-codes", "krb5-", "gpg", "gnupg", "ca-certificates",
)
_MIN_LEN = 3

# Paquets dont le nom **exact** est un mot du dictionnaire courant (anglais ou
# français) — aucun préfixe ne les attrape, mais en mot entier dans un titre
# de veille, ils matchent n'importe quel texte qui contient ce mot, pas le
# logiciel. Constaté en conditions réelles (22/07/2026, profil "tout
# sélectionner" sur le parc de démo) : "discover" (paquet de détection
# matérielle Debian) matchait 48 des 107 correspondances remontées, "file"
# (utilitaire d'identification de type MIME) 26 — ex. "FreeBSD: buffer
# overflow via Select **File** Descriptor" étiqueté comme concernant le parc
# alors que l'article ne parle pas du tout du paquet `file`. Liste tenue à la
# main sur la base des cas réellement observés, pas une tentative de couvrir
# tout le dictionnaire — un autre faux positif de ce type doit être ajouté ici
# au cas par cas plutôt que de complexifier le filtre par préfixe ci-dessus.
_AMBIGUOUS_WORDS = {"file", "discover", "less", "more", "at", "watch", "time", "who", "w"}


def _is_noise(name: str) -> bool:
    n = name.lower().split(":")[0]           # "libssh2-1:amd64" → "libssh2-1"
    if len(n) < _MIN_LEN:
        return True
    if n in _AMBIGUOUS_WORDS:
        return True
    return n.startswith(_NOISE_PREFIXES)


def _clean_package(name: str) -> str:
    """"libssh2-1:amd64" → "libssh2" — retire l'architecture et le suffixe de
    version de paquet, qui ne servent à rien comme mot-clé de veille (un avis
    parle d'« OpenSSL », pas d'« openssl:amd64 »)."""
    n = name.split(":")[0]
    n = re.sub(r"-\d[\d.]*$", "", n)          # libssh2-1 → libssh2
    return n


async def suggestions_from_inventory(session: AsyncSession) -> dict:
    """
    Termes proposés à partir du parc : OS déclarés (Actifs), applications
    installées (Inventaire), et vendor détecté sur les actifs réseau importés
    depuis PRTG (`Asset.hardware.vendor_hint`, cf. services/prtg_matcher.py).
    Dédupliqués, triés, bruit de base écarté.

    Chaque suggestion indique sur quels actifs elle a été vue — l'analyste sait
    *pourquoi* un terme lui est proposé avant de le cocher.
    """
    assets = (await session.execute(select(Asset))).scalars().all()

    os_seen: dict[str, set] = {}
    sw_seen: dict[str, set] = {}
    hw_seen: dict[str, set] = {}

    for a in assets:
        if a.os:
            os_seen.setdefault(a.os.strip(), set()).add(a.name)
        for pkg in (a.installed_packages or []):
            raw = (pkg.get("name") or "").strip()
            if not raw or _is_noise(raw):
                continue
            sw_seen.setdefault(_clean_package(raw), set()).add(a.name)
        vendor_hint = (a.hardware or {}).get("vendor_hint") if a.hardware else None
        if vendor_hint:
            hw_seen.setdefault(vendor_hint, set()).add(a.name)

    def _fmt(d):
        return [
            {"value": v, "assets": sorted(names)}
            for v, names in sorted(d.items(), key=lambda kv: kv[0].lower())
        ]

    return {"os": _fmt(os_seen), "software": _fmt(sw_seen), "hardware": _fmt(hw_seen)}


# ─── Correspondance profil ↔ élément de veille ────────────────────────────────

def _term_matches(term: str, text: str) -> bool:
    """
    Mot entier, insensible à la casse — même précaution que le matching
    d'identités (`routers/identities.py`) : en sous-chaîne, « AER » matcherait
    « laser » et « apt » matcherait « adapter ». `\\w` est Unicode-aware côté
    Python, les termes accentués sont donc gérés.
    """
    return re.search(rf"(?<!\w){re.escape(term.lower())}(?!\w)", text) is not None


async def load_profile_terms(session: AsyncSession) -> list[str]:
    """Termes actifs du profil, prêts pour le matching."""
    rows = (await session.execute(
        select(WatchProfileItem.value).where(WatchProfileItem.enabled.is_(True))
    )).scalars().all()
    return [v for v in rows if v and v.strip()]


def matched_terms(terms: list[str], title: str | None, summary: str | None) -> list[str]:
    """
    Termes du profil trouvés dans un élément de veille.

    Calculé **à la volée** et non stocké sur l'élément : le profil change (ajout
    d'un logiciel, nouveau scan d'inventaire) et un indicateur figé deviendrait
    faux sans que rien ne le signale. Le coût est négligeable — quelques dizaines
    de termes sur une page de 50 éléments.
    """
    if not terms:
        return []
    text = f"{title or ''} {summary or ''}".lower()
    return [t for t in terms if _term_matches(t, text)]


async def count_term_matches(session: AsyncSession, term: str) -> int:
    """
    Nombre d'éléments du registre (tous statuts, toutes sources — y compris
    "fuite de données", pour un compte simple et sans ambiguïté) qui
    contiennent `term` en mot entier, dès **avant** son ajout au profil.

    Alimente la confirmation en direct de la modale "Ajouter un terme"
    (session 22/07/2026, à la demande de l'utilisateur) : `> 0` = le terme
    correspond déjà à du contenu réel du registre ; `0` = aucune correspondance
    pour l'instant.

    ⚠️ **`0` ne veut jamais dire "terme invalide"** — juste qu'aucun élément
    collecté à ce jour ne le mentionne. Un pare-feu tout juste acheté ou un
    service SaaS peu couvert médiatiquement a légitimement 0 correspondance le
    jour où on l'ajoute ; le profil marque aussi les **futurs** éléments de
    veille, ce n'est pas un contrôle de saisie. Volontairement non bloquant :
    l'appelant n'empêche jamais l'ajout sur la base de ce chiffre.
    """
    term = (term or "").strip()
    if not term:
        return 0
    rows = (await session.execute(select(WatchItem.title, WatchItem.summary))).all()
    text_of = lambda title, summary: f"{title or ''} {summary or ''}".lower()
    return sum(1 for title, summary in rows if _term_matches(term, text_of(title, summary)))
