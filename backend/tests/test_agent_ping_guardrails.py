"""
tests/test_agent_ping_guardrails.py
Garde-fous du mécanisme ping/pong de l'agent (routers/agents.py, session 21/08/2026) :
- seul un agent actif (status="enrolled") peut être pingé — revoked → 409,
- pong sans ping en attente (ping_requested_at = None) est ignoré silencieusement,
- pong avec ping en attente enregistre la latence, efface le flag et écrit l'historique,
- cancel_ping efface ping_requested_at sans condition sur le statut.

Tests unitaires purs, sans base de données ni serveur HTTP : `session.get` mocké,
objets Agent/AgentCheckinLog en mémoire (mêmes conventions que test_auth_guardrails.py).
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from models import Agent, AgentCheckinLog
from routers.agents import cancel_ping, ping_agent, pong


def _make_agent(status="enrolled", ping_requested_at=None):
    a = MagicMock(spec=Agent)
    a.id = str(uuid.uuid4())
    a.status = status
    a.ping_requested_at = ping_requested_at
    a.last_pong_at = None
    a.last_pong_ms = None
    a.last_seen_at = None
    return a


def _make_session(agent=None):
    session = MagicMock()
    session.get = AsyncMock(return_value=agent)
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


class TestPingAgent:
    async def test_unknown_agent_raises_404(self):
        session = _make_session(agent=None)
        with pytest.raises(HTTPException) as exc:
            await ping_agent(str(uuid.uuid4()), session, MagicMock())
        assert exc.value.status_code == 404

    async def test_revoked_agent_raises_409(self):
        session = _make_session(agent=_make_agent(status="revoked"))
        with pytest.raises(HTTPException) as exc:
            await ping_agent(str(uuid.uuid4()), session, MagicMock())
        assert exc.value.status_code == 409

    async def test_enrolled_agent_sets_ping_requested_at(self):
        agent = _make_agent(status="enrolled")
        session = _make_session(agent=agent)
        before = datetime.now(timezone.utc)
        with patch("routers.agents._agent_dict", return_value={}):
            await ping_agent(str(uuid.uuid4()), session, MagicMock())
        assert agent.ping_requested_at is not None
        assert agent.ping_requested_at >= before
        session.commit.assert_awaited_once()


class TestCancelPing:
    async def test_unknown_agent_raises_404(self):
        session = _make_session(agent=None)
        with pytest.raises(HTTPException) as exc:
            await cancel_ping(str(uuid.uuid4()), session, MagicMock())
        assert exc.value.status_code == 404

    async def test_clears_ping_requested_at(self):
        agent = _make_agent(ping_requested_at=datetime.now(timezone.utc))
        session = _make_session(agent=agent)
        with patch("routers.agents._agent_dict", return_value={}):
            await cancel_ping(str(uuid.uuid4()), session, MagicMock())
        assert agent.ping_requested_at is None
        session.commit.assert_awaited_once()

    async def test_cancel_with_no_pending_ping_is_harmless(self):
        agent = _make_agent(ping_requested_at=None)
        session = _make_session(agent=agent)
        with patch("routers.agents._agent_dict", return_value={}):
            await cancel_ping(str(uuid.uuid4()), session, MagicMock())
        assert agent.ping_requested_at is None
        session.commit.assert_awaited_once()


class TestPong:
    async def test_pong_without_pending_ping_is_silent(self):
        agent = _make_agent(ping_requested_at=None)
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        result = await pong(session, agent)
        assert result == {"ok": True}
        session.add.assert_not_called()
        session.commit.assert_not_awaited()

    async def test_pong_records_latency_and_clears_flag(self):
        requested_at = datetime.now(timezone.utc) - timedelta(milliseconds=120)
        agent = _make_agent(ping_requested_at=requested_at)
        added_logs = []
        session = MagicMock()
        session.add = MagicMock(side_effect=lambda obj: added_logs.append(obj))
        session.commit = AsyncMock()

        result = await pong(session, agent)

        assert result == {"ok": True}
        assert agent.ping_requested_at is None
        assert agent.last_pong_ms is not None
        assert agent.last_pong_ms >= 100
        assert agent.last_pong_at is not None
        assert agent.last_seen_at is not None
        session.commit.assert_awaited_once()
        assert len(added_logs) == 1
        log = added_logs[0]
        assert isinstance(log, AgentCheckinLog)
        assert log.is_ping is True
        assert log.pong_ms == agent.last_pong_ms

    async def test_pong_latency_matches_elapsed_time(self):
        elapsed_ms = 250
        requested_at = datetime.now(timezone.utc) - timedelta(milliseconds=elapsed_ms)
        agent = _make_agent(ping_requested_at=requested_at)
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()

        await pong(session, agent)

        assert abs(agent.last_pong_ms - elapsed_ms) < 50
