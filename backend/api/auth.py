"""AegisX API Authentication and Authorization.

Provides API key authentication and role-based access control (RBAC)
for the FastAPI backend. Development-appropriate security baseline.

Roles:
    admin   - Full access including endpoint management and configuration
    analyst - Triage, investigation, approve response actions
    viewer  - Dashboard read, incident read
    agent   - Telemetry ingestion, command acknowledgement

Configuration via environment variables:
    AEGISX_API_KEY         - Single shared API key (development)
    AEGISX_API_KEYS_JSON   - JSON mapping of key -> role (production)
    AEGISX_AUTH_ENABLED     - Enable/disable auth (default: true)

Example AEGISX_API_KEYS_JSON:
    {"key-admin-abc123": "admin", "key-analyst-def456": "analyst"}
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("AegisX.API.Auth")

try:
    from fastapi import Depends, HTTPException, Security, Request
    from fastapi.security import APIKeyHeader

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


class Role(str, Enum):
    """API authorization roles."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AGENT = "agent"


# Role hierarchy: higher roles include lower role permissions
ROLE_HIERARCHY = {
    Role.ADMIN: {Role.ADMIN, Role.ANALYST, Role.VIEWER, Role.AGENT},
    Role.ANALYST: {Role.ANALYST, Role.VIEWER},
    Role.VIEWER: {Role.VIEWER},
    Role.AGENT: {Role.AGENT},
}

# Default seeded user directory for authentication fallback
DEFAULT_USERS = {
    "admin": {
        "user_id": "usr-admin-001",
        "password": os.environ.get("AEGISX_ADMIN_PASSWORD", "adminpassword"),
        "role": Role.ADMIN,
        "display_name": "AegisX Administrator",
        "email": "admin@aegisx.local",
    },
    "analyst": {
        "user_id": "usr-analyst-001",
        "password": os.environ.get("AEGISX_ANALYST_PASSWORD", "analystpassword"),
        "role": Role.ANALYST,
        "display_name": "Senior SOC Analyst",
        "email": "analyst@aegisx.local",
    },
    "viewer": {
        "user_id": "usr-viewer-001",
        "password": os.environ.get("AEGISX_VIEWER_PASSWORD", "viewerpassword"),
        "role": Role.VIEWER,
        "display_name": "Security Auditor",
        "email": "viewer@aegisx.local",
    },
}


# ---------------------------------------------------------------------------
# Zero-Dependency RFC 7519 HMAC-SHA256 JWT Implementation
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without trailing '='."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data_str: str) -> bytes:
    """Decode base64url string to bytes, padding with '=' as necessary."""
    rem = len(data_str) % 4
    if rem > 0:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def create_access_token(
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    expires_in_seconds: Optional[int] = None,
) -> str:
    """Generate an RFC 7519 compliant HS256 JWT access token."""
    config = get_auth_config()
    secret_key = secret or config.jwt_secret
    exp_seconds = expires_in_seconds if expires_in_seconds is not None else config.jwt_expiry_seconds

    header = {"alg": "HS256", "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    header_b64 = _b64url_encode(header_bytes)

    now = int(time.time())
    token_payload = dict(payload)
    token_payload.setdefault("iat", now)
    token_payload.setdefault("exp", now + exp_seconds)
    token_payload.setdefault("iss", "aegisx-soc")

    payload_bytes = json.dumps(token_payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str, secret: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verify and decode an HS256 JWT access token.

    Returns the payload dictionary if valid and unexpired, or None if invalid.
    """
    if not token or not isinstance(token, str):
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts
    config = get_auth_config()
    secret_key = secret or config.jwt_secret

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    # Verify expiration
    now = int(time.time())
    exp = payload.get("exp")
    if exp is not None and now > exp:
        return None

    return payload


# ---------------------------------------------------------------------------
# Auth Configuration
# ---------------------------------------------------------------------------

class AuthConfig:
    """Authentication configuration from environment."""

    def __init__(self):
        self.enabled = os.environ.get("AEGISX_AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
        self.jwt_secret = os.environ.get("AEGISX_JWT_SECRET", "aegisx-dev-jwt-secret-not-for-production")
        self.jwt_expiry_seconds = int(os.environ.get("AEGISX_JWT_EXPIRY_SECONDS", "86400"))
        self._keys: Dict[str, str] = {}  # api_key -> role
        self._load_keys()

    def _load_keys(self):
        """Load API keys from environment."""
        # Method 1: Single shared key (development)
        single_key = os.environ.get("AEGISX_API_KEY", "")
        if single_key:
            single_role = os.environ.get("AEGISX_API_KEY_ROLE", "admin")
            self._keys[single_key] = single_role

        # Method 2: JSON key mapping (production)
        keys_json = os.environ.get("AEGISX_API_KEYS_JSON", "")
        if keys_json:
            try:
                mapping = json.loads(keys_json)
                if isinstance(mapping, dict):
                    self._keys.update(mapping)
            except json.JSONDecodeError:
                logger.warning("Invalid AEGISX_API_KEYS_JSON format")

        # Development fallback: if auth enabled but no keys configured,
        # create a default development key
        if self.enabled and not self._keys:
            dev_key = "aegisx-dev-key-not-for-production"
            self._keys[dev_key] = "admin"
            logger.warning(
                "No API keys configured. Using development key: %s. "
                "Set AEGISX_API_KEY or AEGISX_API_KEYS_JSON for production.",
                dev_key,
            )

    def validate_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return role, or None if invalid."""
        return self._keys.get(api_key)

    @property
    def is_enabled(self) -> bool:
        return self.enabled


# Module-level singleton
_auth_config: Optional[AuthConfig] = None


def get_auth_config() -> AuthConfig:
    """Get or create the auth config singleton."""
    global _auth_config
    if _auth_config is None:
        _auth_config = AuthConfig()
    return _auth_config


def reset_auth_config() -> None:
    """Reset auth config (for testing)."""
    global _auth_config
    _auth_config = None


# ---------------------------------------------------------------------------
# FastAPI Dependency & Authenticated User
# ---------------------------------------------------------------------------

class AuthenticatedUser:
    """Represents an authenticated API user with role, identity, and permissions."""

    def __init__(
        self,
        api_key: str = "",
        role: str = "viewer",
        user_id: str = "usr-unknown",
        username: str = "anonymous",
        display_name: str = "Anonymous User",
        auth_type: str = "api_key",
    ):
        self.api_key = api_key
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.auth_type = auth_type
        self.role = Role(role) if role in [r.value for r in Role] else Role.VIEWER
        self.permissions = ROLE_HIERARCHY.get(self.role, {self.role})

    def has_role(self, required_role: Role) -> bool:
        """Check if user has the required role (including hierarchy)."""
        return required_role in self.permissions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role.value,
            "auth_type": self.auth_type,
            "permissions": [r.value for r in self.permissions],
        }


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate user credentials against configured users."""
    user_record = DEFAULT_USERS.get(username)
    if not user_record:
        return None
    if user_record["password"] != password:
        return None
    return user_record


if HAS_FASTAPI:
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def get_current_user(
        request: Request,
        api_key: Optional[str] = Security(api_key_header),
    ) -> AuthenticatedUser:
        """FastAPI dependency: authenticate request via Bearer JWT or X-API-Key header."""
        config = get_auth_config()

        if not config.is_enabled:
            # Auth disabled - return admin user for development
            return AuthenticatedUser(
                api_key="disabled",
                role="admin",
                user_id="usr-admin-dev",
                username="admin_dev",
                auth_type="disabled",
            )

        # 1. First priority: Check Authorization: Bearer <token>
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            payload = decode_access_token(token)
            if payload is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired Bearer token.",
                )
            role_val = payload.get("role", "viewer")
            return AuthenticatedUser(
                api_key="",
                role=role_val,
                user_id=payload.get("sub", "usr-jwt"),
                username=payload.get("username", "jwt_user"),
                display_name=payload.get("display_name", "JWT User"),
                auth_type="bearer",
            )

        # 2. Second priority: Check X-API-Key header
        if not api_key:
            raise HTTPException(
                status_code=401,
                detail="Missing API key. Provide X-API-Key header or Authorization: Bearer token.",
            )

        role = config.validate_key(api_key)
        if role is None:
            raise HTTPException(
                status_code=403,
                detail="Invalid API key.",
            )

        return AuthenticatedUser(
            api_key=api_key,
            role=role,
            user_id=f"usr-key-{api_key[:8]}",
            username=f"key_{role}",
            auth_type="api_key",
        )

    def require_role(required_role: Role):
        """FastAPI dependency factory: require a specific role."""

        async def _check_role(
            user: AuthenticatedUser = Depends(get_current_user),
        ) -> AuthenticatedUser:
            if not user.has_role(required_role):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required role: {required_role.value}",
                )
            return user

        return _check_role

else:
    # Stubs for import compatibility without FastAPI
    async def get_current_user(*a, **kw):  # type: ignore
        return AuthenticatedUser()

    def require_role(required_role):  # type: ignore
        return get_current_user
