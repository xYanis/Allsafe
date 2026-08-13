"""
crypto.py
Chiffrement symétrique (Fernet) des identifiants SSH par machine (phase de test —
cf. models.py Asset.scan_password_encrypted). Clé dérivée de SECRET_KEY : pas de
secret supplémentaire à gérer, mais tourne SECRET_KEY invalide tous les mots de
passe déjà chiffrés (à changer avant mise en prod avec de vraies données).
"""

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

from config import settings


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_password(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_password(encrypted: str) -> str | None:
    try:
        return _fernet().decrypt(encrypted.encode()).decode()
    except (InvalidToken, ValueError):
        return None
