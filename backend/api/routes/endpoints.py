"""Endpoint management API routes.

Implements the contracted endpoint endpoints:
    POST /endpoints/register — Register endpoint agents
    GET  /agent/commands — Agent command polling
    POST /agent/commands/{command_id}/ack — Command acknowledgment
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.API.Endpoints")

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

from backend.api.auth import require_role, Role

router = APIRouter()


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class EndpointRegistration(BaseModel):
    """Endpoint registration request from an agent."""
    hostname: str = Field(description="Endpoint hostname")
    ip_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    environment: str = "unknown"
    asset_criticality: str = "unknown"
    department: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EndpointResponse(BaseModel):
    """Response after successful registration."""
    endpoint_id: str
    agent_id: str
    status: str = "active"
    registered_at: str = ""


class AgentCommand(BaseModel):
    """A command to be executed by an endpoint agent."""
    command_id: str
    command_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: str = "medium"
    created_at: str = ""


class CommandAck(BaseModel):
    """Acknowledgment of command receipt/execution."""
    status: str = "received"
    result: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# In-memory stores (replaced by database in production)
# ---------------------------------------------------------------------------

_endpoints: Dict[str, Dict[str, Any]] = {}
_pending_commands: Dict[str, List[Dict[str, Any]]] = {}  # agent_id → commands


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/endpoints/register", response_model=EndpointResponse)
async def register_endpoint(
    registration: EndpointRegistration,
    _auth: Any = Depends(require_role(Role.AGENT)),
) -> Dict[str, Any]:
    """Register an endpoint agent with the SOC platform.

    Returns endpoint_id and agent_id for subsequent telemetry submission
    and command polling.
    """
    endpoint_id = f"ep-{uuid.uuid4().hex[:12]}"
    agent_id = f"ag-{uuid.uuid4().hex[:12]}"
    registered_at = datetime.now(timezone.utc).isoformat()

    _endpoints[endpoint_id] = {
        "endpoint_id": endpoint_id,
        "agent_id": agent_id,
        "hostname": registration.hostname,
        "ip_address": registration.ip_address,
        "os": registration.os,
        "os_version": registration.os_version,
        "agent_version": registration.agent_version,
        "environment": registration.environment,
        "asset_criticality": registration.asset_criticality,
        "department": registration.department,
        "status": "active",
        "registered_at": registered_at,
        "last_seen": registered_at,
        "metadata": registration.metadata,
    }

    logger.info(
        "Endpoint registered: %s (hostname=%s, agent=%s)",
        endpoint_id, registration.hostname, agent_id,
    )

    return {
        "endpoint_id": endpoint_id,
        "agent_id": agent_id,
        "status": "active",
        "registered_at": registered_at,
    }


@router.get("/endpoints")
async def list_endpoints(
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """List registered endpoints (for dashboard/analyst inspection)."""
    endpoints = list(_endpoints.values())
    return {
        "endpoints": endpoints,
        "count": len(endpoints),
    }


@router.get("/agent/commands")
async def get_agent_commands(
    agent_id: str,
    _auth: Any = Depends(require_role(Role.AGENT)),
) -> Dict[str, Any]:
    """Poll for pending commands for a specific agent.

    Agents call this endpoint periodically to check for commands
    (e.g., response actions that have been human-approved).
    """
    commands = _pending_commands.get(agent_id, [])

    # Return and clear pending commands
    if commands:
        _pending_commands[agent_id] = []

    return {
        "agent_id": agent_id,
        "commands": commands,
        "count": len(commands),
    }


@router.post("/agent/commands/{command_id}/ack")
async def acknowledge_command(
    command_id: str,
    ack: CommandAck,
    _auth: Any = Depends(require_role(Role.AGENT)),
) -> Dict[str, Any]:
    """Acknowledge receipt or completion of a command.

    Agents send this after receiving or executing a command to confirm
    status and report results.
    """
    logger.info(
        "Command %s acknowledged: status=%s", command_id, ack.status
    )

    return {
        "command_id": command_id,
        "acknowledged": True,
        "status": ack.status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
