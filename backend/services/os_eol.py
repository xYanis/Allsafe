"""
services/os_eol.py
Détection d'OS en fin de support (17/08/2026) — équivalent du défaut "OS obsolète" de Cyberwatch
(référence utilisateur : "un OS qui est obsolète, ça remontera comme un défaut de sécurité").

Calculée dynamiquement depuis `Asset.os`/`Asset.os_version` déjà collectés par le scan read-only
existant (services/asset_scanner.py) — aucun nouveau scan, aucune connexion à l'actif. Recalculée
à chaque lecture (routers/assets.py::_asset_dict) plutôt que figée au moment du dernier scan : un
OS peut devenir obsolète simplement parce que le calendrier avance, pas parce que l'actif a changé.

`_EOL_TABLE` est une liste curatée à la main, pas exhaustive — mêmes limites qu'un produit
commercial sur ce point (cette donnée ne s'automatise pas depuis une source unique fiable).
`None` si l'OS ne matche aucune entrée : pas d'affirmation hasardeuse sur un OS inconnu de la
table plutôt qu'un faux "ok" ou "warn".
"""

import re
from datetime import date, datetime, timezone

# (nom affiché, match(os, os_version) -> bool, date de fin de support)
# os = chaîne déclarative (souvent générique côté Windows — "Windows Server", cf.
# apply_scan_result/_extract_windows_version dans asset_scanner.py, l'ANNÉE ne vit que dans
# os_version) ; PRETTY_NAME /etc/os-release côté Linux (contient bien la distro ET la version en
# texte, mais on se base sur VERSION_ID/os_version pour rester cohérent avec le côté Windows).
# Vérifié contre le parc réel (17/08/2026) : `os` = "Windows Server" pour toutes les éditions
# (2012/2016/2019/2022), seul `os_version` distingue l'année — chercher l'année dans `os` (1er
# jet de cette table) ne matchait jamais rien en conditions réelles.
_EOL_TABLE: list[tuple[str, "callable", date]] = [
    # Windows Server 2012 et 2012 R2 partagent la même date de fin de support étendu
    # (2023-10-10) — `os_version` ne distingue pas les deux (année seule, cf. ci-dessus), pas
    # d'ambiguïté pratique puisque le résultat est identique.
    ("Windows Server 2012 / 2012 R2", lambda o, v: "windows server" in o and v == "2012", date(2023, 10, 10)),
    ("Windows Server 2016",           lambda o, v: "windows server" in o and v == "2016", date(2027, 1, 12)),
    ("Windows Server 2019",           lambda o, v: "windows server" in o and v == "2019", date(2029, 1, 9)),
    ("Windows Server 2022",           lambda o, v: "windows server" in o and v == "2022", date(2031, 10, 14)),
    ("Windows 10",                    lambda o, v: "windows" in o and "server" not in o and v == "10", date(2025, 10, 14)),
    ("Ubuntu 18.04 LTS",              lambda o, v: "ubuntu" in o and v.startswith("18.04"), date(2023, 5, 31)),
    ("Ubuntu 20.04 LTS",              lambda o, v: "ubuntu" in o and v.startswith("20.04"), date(2025, 5, 31)),
    ("Ubuntu 22.04 LTS",              lambda o, v: "ubuntu" in o and v.startswith("22.04"), date(2027, 6, 1)),
    ("Ubuntu 24.04 LTS",              lambda o, v: "ubuntu" in o and v.startswith("24.04"), date(2029, 6, 1)),
    ("Debian 9",                      lambda o, v: "debian" in o and v.startswith("9"), date(2022, 6, 30)),
    ("Debian 10",                     lambda o, v: "debian" in o and v.startswith("10"), date(2024, 6, 30)),
    ("Debian 11",                     lambda o, v: "debian" in o and v.startswith("11"), date(2026, 8, 31)),
    ("Debian 12",                     lambda o, v: "debian" in o and v.startswith("12"), date(2028, 6, 30)),
    ("CentOS/RHEL 7",                 lambda o, v: re.search(r"centos|red hat|rhel", o) is not None and v.startswith("7"), date(2024, 6, 30)),
    ("CentOS/RHEL 8",                 lambda o, v: re.search(r"centos|red hat|rhel", o) is not None and v.startswith("8"), date(2029, 5, 31)),
]


def check_os_eol(os_: str | None, os_version: str | None) -> dict | None:
    """Retourne un check au format services/asset_scanner.py::_check() (id/label/status/detail),
    ou None si l'OS ne correspond à aucune entrée de _EOL_TABLE (pas de check affiché plutôt
    qu'une affirmation hasardeuse)."""
    o = (os_ or "").strip().lower()
    v = (os_version or "").strip()
    if not o:
        return None

    for name, match, eol in _EOL_TABLE:
        try:
            if match(o, v):
                today = datetime.now(timezone.utc).date()
                if today > eol:
                    return {
                        "id": "os_eol", "label": "Fin de support de l'OS", "status": "warn",
                        "detail": f"{name} — support terminé le {eol.isoformat()} (dépassé)",
                    }
                return {
                    "id": "os_eol", "label": "Fin de support de l'OS", "status": "ok",
                    "detail": f"{name} — support jusqu'au {eol.isoformat()}",
                }
        except Exception:
            continue
    return None
