"""AegisX Threat Intelligence Providers.

Provides abstraction and concrete implementations for threat intelligence lookups:
    - ThreatIntelProvider (abstract base class)
    - SyntheticThreatIntelProvider (deterministic synthetic database)
    - DatabaseThreatIntelProvider (PostgreSQL threat_intelligence table)

Invariants:
    - Read-only queries
    - Parameterized database queries
    - Honest "NOT_AVAILABLE" / None when indicator is absent
    - Zero fabrication of intelligence
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.ThreatIntel.Providers")


class ThreatIntelProvider(ABC):
    """Abstract interface for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    @abstractmethod
    def lookup(
        self,
        indicator: str,
        indicator_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up a specific indicator (IP, domain, SHA-256 hash).

        Returns intelligence dictionary or None if indicator is not found.
        """
        pass

    @abstractmethod
    def search(
        self,
        keyword: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search threat intelligence records by keyword."""
        pass

    def health(self) -> Dict[str, Any]:
        """Check provider operational status."""
        return {"provider": self.name, "status": "healthy"}


class SyntheticThreatIntelProvider(ThreatIntelProvider):
    """Deterministic synthetic threat intelligence provider for testing and offline development."""

    def __init__(self):
        from ai.tools.synthetic_threat_intel import (
            get_threat_intel,
            search_threat_intel,
            list_all_threat_intel,
        )
        self._get_ti = get_threat_intel
        self._search_ti = search_threat_intel
        self._all_ind = list_all_threat_intel

    @property
    def name(self) -> str:
        return "synthetic"

    def lookup(
        self,
        indicator: str,
        indicator_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not indicator or not isinstance(indicator, str):
            return None
        res = self._get_ti(indicator.strip())
        if res:
            res_copy = dict(res)
            res_copy["provider"] = self.name
            return res_copy
        return None

    def search(
        self,
        keyword: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        if not keyword or not isinstance(keyword, str):
            return []
        matches = self._search_ti(keyword.strip())
        return matches[:limit]


class DatabaseThreatIntelProvider(ThreatIntelProvider):
    """Database-backed threat intelligence provider querying PostgreSQL schema."""

    def __init__(self, db_pool: Optional[Any] = None, fallback_to_synthetic: bool = True):
        self._pool = db_pool
        self._fallback = SyntheticThreatIntelProvider() if fallback_to_synthetic else None

    @property
    def name(self) -> str:
        return "database"

    def lookup(
        self,
        indicator: str,
        indicator_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not indicator:
            return None

        # If pool is available and connected, query PostgreSQL threat_intelligence table
        if self._pool and getattr(self._pool, "is_initialized", False):
            try:
                query = """
                SELECT indicator_type, indicator_value, threat_type, reputation,
                       confidence, source, first_seen, last_seen, description, tags, metadata
                FROM threat_intelligence
                WHERE indicator_value = $1;
                """
                row = self._pool.fetchrow_sync(query, indicator.strip())
                if row:
                    meta = row.get("metadata") or {}
                    if isinstance(meta, str):
                        try:
                            meta = json.loads(meta)
                        except Exception:
                            meta = {}
                    return {
                        "indicator": row["indicator_value"],
                        "indicator_type": row["indicator_type"],
                        "threat_type": row.get("threat_type"),
                        "threat_actor": meta.get("threat_actor") if isinstance(meta, dict) else None,
                        "malware_family": meta.get("malware_family") if isinstance(meta, dict) else row.get("threat_type"),
                        "reputation": row["reputation"],
                        "confidence": float(row["confidence"]) if row["confidence"] is not None else 0.0,
                        "description": row.get("description"),
                        "tags": row.get("tags") or [],
                        "source": row.get("source"),
                        "provider": self.name,
                    }
            except Exception as exc:
                logger.warning("Database threat intel lookup failed: %s; falling back to synthetic", exc)

        # Honest fallback or NOT_AVAILABLE
        if self._fallback:
            return self._fallback.lookup(indicator, indicator_type)

        return {
            "indicator": indicator,
            "status": "NOT_AVAILABLE",
            "provider": self.name,
            "message": "Database threat intelligence store is currently unavailable.",
        }

    def search(
        self,
        keyword: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        if not keyword or not isinstance(keyword, str):
            return []

        if self._pool and getattr(self._pool, "is_initialized", False):
            try:
                query = """
                SELECT indicator_type, indicator_value, threat_type, reputation,
                       confidence, description, tags, metadata
                FROM threat_intelligence
                WHERE indicator_value ILIKE ('%' || $1 || '%')
                   OR threat_type ILIKE ('%' || $1 || '%')
                   OR description ILIKE ('%' || $1 || '%')
                LIMIT $2;
                """
                rows = self._pool.fetch_sync(query, keyword.strip(), limit)
                if rows:
                    results = []
                    for r in rows:
                        results.append({
                            "indicator": r["indicator_value"],
                            "indicator_type": r["indicator_type"],
                            "threat_type": r.get("threat_type"),
                            "reputation": r["reputation"],
                            "confidence": float(r["confidence"]) if r["confidence"] is not None else 0.0,
                            "description": r.get("description"),
                            "provider": self.name,
                        })
                    return results
            except Exception as exc:
                logger.warning("Database threat intel search failed: %s; falling back to synthetic", exc)

        if self._fallback:
            return self._fallback.search(keyword, limit=limit)
        return []

    def health(self) -> Dict[str, Any]:
        is_conn = bool(self._pool and getattr(self._pool, "is_initialized", False))
        return {
            "provider": self.name,
            "status": "healthy" if is_conn else "degraded",
            "database_connected": is_conn,
            "fallback_active": self._fallback is not None,
        }


# Module default provider instance
_default_provider: Optional[ThreatIntelProvider] = None


def get_threat_intel_provider(
    provider_type: str = "synthetic",
    db_pool: Optional[Any] = None,
) -> ThreatIntelProvider:
    """Factory retrieving the configured threat intelligence provider."""
    global _default_provider
    if _default_provider is None:
        if provider_type == "database" or (db_pool and getattr(db_pool, "is_initialized", False)):
            _default_provider = DatabaseThreatIntelProvider(db_pool=db_pool)
        else:
            _default_provider = SyntheticThreatIntelProvider()
    return _default_provider


def reset_threat_intel_provider() -> None:
    """Reset provider singleton (for testing)."""
    global _default_provider
    _default_provider = None
