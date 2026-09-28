"""AegisX Backend API Application.

FastAPI application implementing the SOC platform REST API.
Provides endpoints for telemetry ingestion, endpoint management,
incident management, and dashboard data.

Architecture position:
    Endpoint Agent → [REST API] → Ingestion → Detection → Correlation →
    AI Triage → Investigation → Response → Dashboard

All response actions remain human-gated per security requirements.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger("AegisX.API")

# Detect FastAPI availability — the API module should be importable
# for testing even without FastAPI installed.
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None  # type: ignore


def create_app() -> Any:
    """Create and configure the FastAPI application.

    Returns the FastAPI app instance, or raises ImportError if FastAPI
    is not installed.
    """
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the AegisX backend. "
            "Install with: pip install fastapi uvicorn"
        )

    app = FastAPI(
        title="AegisX SOC Platform",
        description="Agentic AI-powered Security Operations Center API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS middleware for dashboard frontend
    import os
    allowed_origins_env = os.environ.get(
        "AEGISX_ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
    )
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register routes
    _register_routes(app)

    return app


def _register_routes(app: Any) -> None:
    """Register all API route modules."""

    @app.get("/", tags=["health"])
    async def root():
        """Root endpoint — API information."""
        return {
            "name": "AegisX SOC Platform",
            "version": "0.1.0",
            "status": "running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/health", tags=["health"])
    async def health_check():
        """Health check endpoint for load balancers and monitoring."""
        from backend.api.services import get_services
        services = get_services()
        db_status = "up" if services.is_db_available else "not_configured"

        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "api": "up",
                "detection_engine": "up",
                "correlation_engine": "up",
                "database": db_status,
            },
        }

    # Import and register route modules
    from backend.api.routes.auth import router as auth_router
    from backend.api.routes.telemetry import router as telemetry_router
    from backend.api.routes.endpoints import router as endpoints_router
    from backend.api.routes.incidents import router as incidents_router
    from backend.api.routes.dashboard import router as dashboard_router

    app.include_router(auth_router, prefix="/api/v1", tags=["auth"])
    app.include_router(telemetry_router, prefix="/api/v1", tags=["telemetry"])
    app.include_router(endpoints_router, prefix="/api/v1", tags=["endpoints"])
    app.include_router(incidents_router, prefix="/api/v1", tags=["incidents"])
    app.include_router(dashboard_router, prefix="/api/v1", tags=["dashboard"])
