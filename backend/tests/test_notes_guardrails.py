"""
tests/test_notes_guardrails.py
Garde-fous BOLA du module Notes (routers/notes.py, audit #39, 21/08/2026) :
- un utilisateur ne peut pas lire, modifier ou supprimer les thèmes/sujets/images
  d'un autre utilisateur — le handler lève HTTP 404 (sans révéler l'existence de l'objet).

Tests unitaires purs, sans base de données ni serveur HTTP : `session` mocké,
objets NoteTheme/NoteSubject/NoteImage en mémoire (mêmes conventions que
test_incidents_guardrails.py).
"""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from models import NoteImage, NoteSubject, NoteTheme, User
from routers.notes import (
    ThemeUpdate,
    SubjectUpdate,
    delete_note_image,
    delete_subject,
    delete_theme,
    get_image_file,
    get_subject,
    update_subject,
    update_theme,
)


def _user(uid=None) -> User:
    u = User()
    u.id = uid or uuid.uuid4()
    return u


def _theme(owner_id) -> NoteTheme:
    t = NoteTheme()
    t.id = uuid.uuid4()
    t.user_id = owner_id
    t.name = "Cybersécurité"
    t.icon = "🛡️"
    t.color = "#f85149"
    return t


def _subject(owner_id, theme_id=None) -> NoteSubject:
    s = NoteSubject()
    s.id = uuid.uuid4()
    s.user_id = owner_id
    s.theme_id = theme_id or uuid.uuid4()
    s.title = "Sujet test"
    s.content_markdown = ""
    return s


def _image(owner_id) -> NoteImage:
    img = NoteImage()
    img.id = uuid.uuid4()
    img.user_id = owner_id
    img.stored_filename = f"{uuid.uuid4()}.png"
    return img


def _session(obj):
    """Session mockée dont get() renvoie toujours `obj`."""
    s = MagicMock()
    s.get = AsyncMock(return_value=obj)
    s.commit = AsyncMock()
    s.refresh = AsyncMock()
    s.delete = AsyncMock()
    return s


# ─── Thèmes ───────────────────────────────────────────────────────────────────

class TestThemeOwnership:
    async def test_update_other_user_theme_is_404(self):
        owner = _user()
        caller = _user()
        theme = _theme(owner.id)
        with pytest.raises(HTTPException) as exc:
            await update_theme(str(theme.id), ThemeUpdate(name="Hack"), caller, _session(theme))
        assert exc.value.status_code == 404

    async def test_delete_other_user_theme_is_404(self):
        owner = _user()
        caller = _user()
        theme = _theme(owner.id)
        with pytest.raises(HTTPException) as exc:
            await delete_theme(str(theme.id), caller, _session(theme))
        assert exc.value.status_code == 404

    async def test_owner_can_update_own_theme(self):
        owner = _user()
        theme = _theme(owner.id)
        session = _session(theme)
        session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
        await update_theme(str(theme.id), ThemeUpdate(name="Nouveau nom"), owner, session)
        session.commit.assert_called_once()


# ─── Sujets ───────────────────────────────────────────────────────────────────

class TestSubjectOwnership:
    async def test_get_other_user_subject_is_404(self):
        owner = _user()
        caller = _user()
        subject = _subject(owner.id)
        with pytest.raises(HTTPException) as exc:
            await get_subject(str(subject.id), caller, _session(subject))
        assert exc.value.status_code == 404

    async def test_update_other_user_subject_is_404(self):
        owner = _user()
        caller = _user()
        subject = _subject(owner.id)
        with pytest.raises(HTTPException) as exc:
            await update_subject(str(subject.id), SubjectUpdate(title="Hack"), caller, _session(subject))
        assert exc.value.status_code == 404

    async def test_delete_other_user_subject_is_404(self):
        owner = _user()
        caller = _user()
        subject = _subject(owner.id)
        session = _session(subject)
        session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))
        with pytest.raises(HTTPException) as exc:
            await delete_subject(str(subject.id), caller, session)
        assert exc.value.status_code == 404

    async def test_owner_can_get_own_subject(self):
        owner = _user()
        subject = _subject(owner.id)
        result = await get_subject(str(subject.id), owner, _session(subject))
        assert result["title"] == "Sujet test"


# ─── Images ───────────────────────────────────────────────────────────────────

class TestImageOwnership:
    async def test_get_other_user_image_is_404(self):
        owner = _user()
        caller = _user()
        image = _image(owner.id)
        with pytest.raises(HTTPException) as exc:
            await get_image_file(str(image.id), caller, _session(image))
        assert exc.value.status_code == 404

    async def test_delete_other_user_image_is_404(self):
        owner = _user()
        caller = _user()
        image = _image(owner.id)
        with pytest.raises(HTTPException) as exc:
            await delete_note_image(str(image.id), caller, _session(image))
        assert exc.value.status_code == 404

    async def test_owner_can_delete_own_image(self, tmp_path, monkeypatch):
        owner = _user()
        image = _image(owner.id)
        fake_file = tmp_path / image.stored_filename
        fake_file.write_bytes(b"PNG")
        monkeypatch.setattr("routers.notes.NOTE_IMAGES_ROOT", str(tmp_path))
        session = _session(image)
        await delete_note_image(str(image.id), owner, session)
        session.delete.assert_called_once_with(image)
        assert not fake_file.exists()
