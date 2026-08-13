"""
services/vuln_history.py
Historique des transitions de statut de vulnérabilité (27/07/2026).

Fichier à part (pas dans routers/vulnerabilities.py) pour être importable
depuis services/patch_checker.py sans risque de cycle d'import.
"""

from datetime import datetime, timezone

from models import VulnerabilityStatusHistory


def record_status_change(session, vuln_id, old_status, new_status, validated_by=None, notes=None) -> None:
    """Enregistre une transition de statut — no-op si le statut ne change pas
    réellement (évite le bruit d'un re-clic sur le statut déjà actif).

    Synchrone : session.add() seul, pas d'I/O ici — le commit() déjà présent
    à chaque site d'appel couvre la vuln et cette ligne d'historique dans la
    même transaction.
    """
    if old_status == new_status:
        return
    session.add(VulnerabilityStatusHistory(
        vulnerability_id=vuln_id,
        old_status=old_status,
        new_status=new_status,
        changed_at=datetime.now(timezone.utc),
        validated_by=validated_by,
        notes=notes,
    ))
