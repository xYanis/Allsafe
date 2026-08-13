"""
services/access_control.py
Registre des pages restreignables pour un compte `analyst` (31/07/2026) — miroir de
frontend/src/constants/modulePages.js::MODULE_PAGE_TREE, à maintenir manuellement en
synchronisation (même limite que les *_LABELS déjà dupliqués entre backend et frontend,
cf. services/incident_report.py).

`/settings` (Paramètres) et `/` (accueil) sont volontairement HORS de ce registre : tout
compte connecté doit pouvoir s'y rendre quelle que soit sa restriction de modules, sinon un
analyste restreint ne pourrait plus se déconnecter ni changer un mot de passe forcé.
Administration (`/settings/administration`) reste séparément réservée au rôle admin
(`require_admin`), sans lien avec ce registre.
"""

MODULE_PAGES = {
    "cybervuln":     ["/dashboard", "/vulnerabilities", "/cves"],
    "incidents":     ["/incidents", "/crises"],
    "cyberveille":   ["/veille", "/fuite-de-donnees", "/surveillance-identites"],
    "inventaire":    ["/assets", "/inventaire", "/durcissement", "/agents"],
    "securite":      ["/audits", "/bastion"],
    "documentation": ["/documentation", "/notes"],
    "rapports":      ["/reports", "/rapport-veille", "/rapport-surveillance", "/rapport-incidents"],
}

PAGE_KEYS = {p for pages in MODULE_PAGES.values() for p in pages}
