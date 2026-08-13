"""
routers/identities.py
Surveillance Identités (CyberVeille) — repère les items de fuite de données
concernant l'entreprise, en croisant des identités surveillées (nom, domaine)
avec les items déjà collectés par run_watch_sync (sources leak uniquement).
Gère aussi les identités IP/plage IP (kind="ip"/"ip_range"), vérifiées contre
des listes de blocage tierces plutôt qu'un texte d'article — cf.
services/ip_watch.py pour le pourquoi (une IP n'apparaît jamais dans le texte
des sources de fuite actuelles).

Aucune source externe propre pour le matching nom/domaine : réutilise ce que
Fuite de données agrège déjà, donc 100% gratuit. Cf. models.WatchedIdentity
pour la limite assumée (visibilité limitée à ce qui est publiquement rapporté).

Extension du 28/07/2026 (cf. services/leak_lookup.py) : kind="email" vérifié
contre XposedOrNot (fuites connues), et kind="domain" contre une recherche de
code GitHub (identifiants committés par erreur) si GITHUB_TOKEN est configuré.
Même principe que le reste du module : gratuit, un premier brouillon à base
d'API payantes (HIBP, IntelX, Hunter.io, Shodan, Censys, SecurityTrails) a été
explicitement écarté (cf. STATUS.md).
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_session
from models import WatchItem, WatchSource, WatchedIdentity
from services.watch_fetcher import BUILTIN_LEAK_SOURCES
from services.ip_watch import find_ip_matches
from services.leak_lookup import find_osint_matches

router = APIRouter()

IDENTITY_KINDS = ("name", "domain", "ip", "ip_range", "email")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ─── Schémas ──────────────────────────────────────────────────────────────────

class IdentityCreate(BaseModel):
    value: str
    kind: str  # name | domain | ip | ip_range


# ─── Sérialisation ────────────────────────────────────────────────────────────

def _identity_dict(i: WatchedIdentity) -> dict:
    return {
        "id": str(i.id),
        "value": i.value,
        "kind": i.kind,
        "enabled": i.enabled,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


def _match_dict(w: WatchItem, matched: list[str]) -> dict:
    return {
        "id": str(w.id),
        "source": w.source,
        "source_label": w.source_label,
        "title": w.title,
        "url": w.url,
        "summary": w.summary,
        "received_at": w.received_at.isoformat() if w.received_at else None,
        "country": w.country,
        "matched_identities": matched,
    }


# ─── Matching ─────────────────────────────────────────────────────────────────

def _name_matches(value: str, text: str) -> bool:
    """Match d'un nom d'entreprise en mot entier (insensible à la casse) —
    (?<!\\w)/(?!\\w) plutôt qu'un simple `in` pour éviter les faux positifs en
    sous-chaîne (ex: "AER" ne doit pas matcher "AÉRIEN" ou "laser"), même
    précaution que le thème IA côté watch_fetcher. `\\w` est Unicode-aware pour
    les str Python, donc les noms accentués sont gérés."""
    return re.search(rf"(?<!\w){re.escape(value.lower())}(?!\w)", text) is not None


async def _leak_source_keys(session: AsyncSession) -> list[str]:
    """Sources à considérer comme "fuite de données" — natives + personnalisées
    actives de category="leak". Même logique que GET /watch/leak-sources, pour
    ne surveiller que les items de fuite (jamais les avis CERT-FR, blogs
    éditeurs… qui parlent de tout autre chose)."""
    rows = (await session.execute(
        select(WatchSource.slug).where(WatchSource.enabled.is_(True), WatchSource.category == "leak")
    )).scalars().all()
    return BUILTIN_LEAK_SOURCES + list(rows)


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("")
async def list_identities(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(WatchedIdentity).order_by(WatchedIdentity.created_at.asc())
    )).scalars().all()
    return {"identities": [_identity_dict(i) for i in rows]}


@router.post("", status_code=201)
async def create_identity(data: IdentityCreate, session: AsyncSession = Depends(get_session)):
    if data.kind not in IDENTITY_KINDS:
        raise HTTPException(400, f"kind invalide — valeurs : {', '.join(IDENTITY_KINDS)}")
    value = data.value.strip()
    if not value:
        raise HTTPException(400, "Valeur requise")
    # Domaine normalisé en minuscules (comparaison en sous-chaîne insensible à
    # la casse plus loin) ; nom conservé tel quel pour l'affichage.
    if data.kind == "domain":
        value = value.lower()
    elif data.kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(400, f"« {value} » n'est pas une adresse IP valide")
    elif data.kind == "ip_range":
        if "/" not in value:
            raise HTTPException(400, "Une plage IP doit être au format CIDR, ex : 203.0.113.0/24")
        try:
            # strict=False : accepte "203.0.113.5/24" et le normalise en
            # "203.0.113.0/24" (l'utilisateur ne connaît pas forcément
            # l'adresse réseau exacte de sa plage).
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise HTTPException(400, f"« {value} » n'est pas une plage IP (CIDR) valide")
    elif data.kind == "email":
        value = value.lower()
        if not _EMAIL_RE.match(value):
            raise HTTPException(400, f"« {value} » n'est pas une adresse email valide")

    existing = await session.scalar(
        select(WatchedIdentity).where(WatchedIdentity.kind == data.kind, WatchedIdentity.value == value)
    )
    if existing:
        raise HTTPException(409, f"« {value} » est déjà surveillé")

    identity = WatchedIdentity(
        value=value, kind=data.kind, enabled=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(identity)
    await session.commit()
    await session.refresh(identity)
    return _identity_dict(identity)


@router.delete("/{identity_id}", status_code=204)
async def delete_identity(identity_id: str, session: AsyncSession = Depends(get_session)):
    identity = await session.get(WatchedIdentity, identity_id)
    if not identity:
        raise HTTPException(404, "Identité introuvable")
    await session.delete(identity)
    await session.commit()


@router.get("/matches")
async def identity_matches(session: AsyncSession = Depends(get_session)):
    """Items de fuite de données concernant au moins une identité surveillée.

    Croisement à la volée (pas de stockage) : toujours frais, volume faible
    (les fuites concernant une entreprise donnée sont rares). Un nom est matché
    en mot entier ; un domaine en sous-chaîne. Pour ransomware.live, le nom est
    aussi comparé au champ victime (partie du titre avant " — ", plus précise
    que le titre entier)."""
    identities = (await session.execute(
        select(WatchedIdentity).where(WatchedIdentity.enabled.is_(True))
    )).scalars().all()
    if not identities:
        return {
            "total": 0, "items": [], "identities_count": 0, "ip_total": 0, "ip_matches": [],
            "osint_total": 0, "osint_matches": [],
        }

    leak_sources = await _leak_source_keys(session)
    items = (await session.execute(
        select(WatchItem)
        .where(WatchItem.source.in_(leak_sources))
        .order_by(WatchItem.received_at.desc())
    )).scalars().all()

    names   = [i.value for i in identities if i.kind == "name"]
    domains = [i.value for i in identities if i.kind == "domain"]

    results = []
    for w in items:
        text = f"{w.title} {w.summary or ''}".lower()
        # ransomware.live : le titre est "victime — groupe (activité)", on
        # isole la victime pour un match de nom plus fiable (cf. watch_fetcher
        # _fetch_ransomware_live / parseCompany côté frontend).
        company = w.title.split(" — ", 1)[0].lower() if w.source == "ransomware-live" else None

        matched = []
        for name in names:
            if _name_matches(name, text) or (company and _name_matches(name, company)):
                matched.append(name)
        for dom in domains:
            if dom in text:
                matched.append(dom)

        if matched:
            results.append(_match_dict(w, matched))

    ip_matches = await find_ip_matches(identities)
    osint_matches = await find_osint_matches(identities)

    return {
        "total": len(results), "items": results, "identities_count": len(identities),
        "ip_total": len(ip_matches), "ip_matches": ip_matches,
        "osint_total": len(osint_matches), "osint_matches": osint_matches,
    }
