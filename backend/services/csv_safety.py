"""
services/csv_safety.py
Neutralise l'injection de formule CSV/Excel (audit/AUDIT_SECURITE.md #7) : un champ
texte issu d'une source externe (flux de veille, y compris les sources
personnalisées ajoutables sans code) peut commencer par =/+/-/@ et être
interprété comme une formule (DDE compris) à l'ouverture du CSV dans
Excel/LibreOffice — notamment le registre de veille, destiné au rapport
auditeur NIS 2.
"""


def csv_safe(value) -> str:
    """Préfixe d'une apostrophe les valeurs pouvant être lues comme une
    formule par un tableur. Neutre pour tout le reste (round-trip inchangé)."""
    s = "" if value is None else str(value)
    return f"'{s}" if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s
