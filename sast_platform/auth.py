import base64
import hashlib
import hmac
import json
import secrets
import time
from .models import User


class AuthError(Exception):
    pass


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt_text), int(iterations))
        return hmac.compare_digest(base64.urlsafe_b64encode(digest).decode(), digest_text)
    except (ValueError, TypeError):
        return False


class TokenService:
    def __init__(self, secret: bytes, ttl_seconds: int = 3600):
        self.secret = secret
        self.ttl_seconds = ttl_seconds

    def issue(self, user: User) -> str:
        payload = {"sub": user.user_id, "role": user.role.value, "exp": int(time.time()) + self.ttl_seconds}
        body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        signature = hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
        return body + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def verify(self, token: str) -> dict:
        try:
            body, signature = token.split(".", 1)
            expected = hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
            supplied = base64.urlsafe_b64decode(signature + "===")
            payload = json.loads(base64.urlsafe_b64decode(body + "==="))
            if not hmac.compare_digest(expected, supplied) or payload["exp"] <= int(time.time()):
                raise AuthError("invalid or expired token")
            return payload
        except (ValueError, KeyError, json.JSONDecodeError, TypeError):
            raise AuthError("invalid token")
