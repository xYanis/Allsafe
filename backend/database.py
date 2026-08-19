"""
database.py
Connexion PostgreSQL via SQLAlchemy async.
"""

import asyncio

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from config import settings

# NullPool : les tâches Celery (nvd_fetcher, rss_fetcher, watch_fetcher) ouvrent
# une boucle asyncio différente à chaque asyncio.run(). Un pool de connexions
# persistant survit à la fermeture de la boucle qui l'a créé et provoque
# "cannot perform operation: another operation is in progress" en cascade dès
# qu'une connexion est réutilisée depuis une nouvelle boucle.
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    poolclass=NullPool,
    echo=settings.DEBUG,
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Limite les requêtes HTTP à DB_MAX_CONCURRENT_SESSIONS sessions simultanées (10/08/2026,
# cf. audit/AUDIT_SECURITE.md et config.py). Ne couvre que `get_session` — utilisé par les 162
# routes de l'API (cf. routers/), le vrai chemin qu'emprunte une rafale de requêtes HTTP
# externes. Les `SessionLocal()` ouverts directement dans services/ (tâches de fond,
# Celery) restent hors de ce plafond, volontairement : ce ne sont jamais des dizaines de
# requêtes concurrentes déclenchées de l'extérieur, le scénario qui a fait geler le
# backend. Un asyncio.Semaphore créé ici (au niveau module, avant toute boucle asyncio)
# se lie paresseusement à la boucle courante au premier `await` (comportement Python
# ≥3.10) — sûr à réutiliser tel quel dans le process `backend` (une seule boucle,
# persistante, tout le cycle de vie de uvicorn).
_session_semaphore = asyncio.Semaphore(settings.DB_MAX_CONCURRENT_SESSIONS)


async def get_session():
    async with _session_semaphore:
        async with SessionLocal() as session:
            yield session
