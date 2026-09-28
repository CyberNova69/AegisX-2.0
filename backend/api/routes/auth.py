"""Authentication API routes.

Provides endpoints for authentication and token management:
    POST /auth/login — Login with credentials or API key and obtain JWT bearer token
    GET  /auth/me    — Retrieve current authenticated user profile and roles
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("AegisX.API.AuthRoutes")

try:
    from fastapi import APIRouter, HTTPException, Depends
    from pydantic import BaseModel, Field

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class APIRouter:  # type: ignore
        def post(self, *a, **kw):
            def d(f): return f
            return d

        def get(self, *a, **kw):
            def d(f): return f
            return d

    class BaseModel:  # type: ignore
        pass

    def Field(*a, **kw):  # type: ignore
        return None

    def Depends(*a, **kw):  # type: ignore
        return None

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code=500, detail=""):
            self.status_code = status_code
            self.detail = detail

from backend.api.auth import (
    AuthenticatedUser,
    Role,
    get_auth_config,
    authenticate_user,
    create_access_token,
    get_current_user,
    require_role,
)

router = APIRouter()


class LoginRequest(BaseModel):
    """Login payload supporting username/password or API key exchange."""
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None


class TokenResponse(BaseModel):
    """JWT bearer token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    user: Dict[str, Any]


@router.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest) -> Dict[str, Any]:
    """Authenticate and obtain a JWT bearer access token.

    Supports:
    1. Username + Password authentication (analyst, admin, viewer accounts)
    2. API Key exchange for interactive UI sessions
    """
    config = get_auth_config()

    # 1. API key exchange
    if request.api_key:
        role = config.validate_key(request.api_key)
        if role is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")
        payload = {
            "sub": f"usr-key-{request.api_key[:8]}",
            "username": f"key_{role}",
            "role": role,
            "display_name": f"API Key ({role})",
        }
        token = create_access_token(payload)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": config.jwt_expiry_seconds,
            "role": role,
            "user": {
                "user_id": payload["sub"],
                "username": payload["username"],
                "role": role,
                "display_name": payload["display_name"],
            },
        }

    # 2. Username and password
    if request.username and request.password:
        user_record = authenticate_user(request.username, request.password)
        if not user_record:
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        role_str = user_record["role"].value if hasattr(user_record["role"], "value") else str(user_record["role"])
        payload = {
            "sub": user_record["user_id"],
            "username": request.username,
            "role": role_str,
            "display_name": user_record.get("display_name", request.username),
            "email": user_record.get("email", ""),
        }
        token = create_access_token(payload)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": config.jwt_expiry_seconds,
            "role": role_str,
            "user": {
                "user_id": user_record["user_id"],
                "username": request.username,
                "role": role_str,
                "display_name": user_record.get("display_name", request.username),
                "email": user_record.get("email", ""),
            },
        }

    raise HTTPException(
        status_code=400,
        detail="Must provide either username/password or api_key.",
    )


@router.get("/auth/me")
async def get_current_user_profile(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve current authenticated user profile and permissions."""
    return {
        "authenticated": True,
        "user": user.to_dict(),
    }
