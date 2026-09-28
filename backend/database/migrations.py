"""AegisX Database Migration Mechanism.

Provides schema versioning and migration tracking for PostgreSQL:
    - Tracks applied migrations in `schema_migrations` table
    - Versioned SQL migrations execution
    - Deterministic verification of 25 core SOC schema tables
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.Database.Migrations")

CORE_SCHEMA_TABLES = [
    "users", "endpoints", "agents", "events", "processes",
    "network_events", "alerts", "incidents", "incident_events",
    "investigations", "investigation_steps", "threat_intelligence",
    "mitre_tactics", "mitre_techniques", "mitre_mappings",
    "entity_relationships", "document_chunks", "responses",
    "response_actions", "verification_results", "agent_traces",
    "feedback", "audit_logs", "training_examples", "dataset_provenance",
]

SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     VARCHAR(50) PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    checksum    VARCHAR(64),
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

DEFAULT_TACTICS = [
    ("TA0001", "Initial Access", "The adversary is trying to get into your network.", 1),
    ("TA0002", "Execution", "The adversary is trying to run malicious code.", 2),
    ("TA0003", "Persistence", "The adversary is trying to maintain their foothold.", 3),
    ("TA0004", "Privilege Escalation", "The adversary is trying to gain higher-level permissions.", 4),
    ("TA0005", "Defense Evasion", "The adversary is trying to avoid being detected.", 5),
    ("TA0006", "Credential Access", "The adversary is trying to steal account names and passwords.", 6),
    ("TA0007", "Discovery", "The adversary is trying to figure out your environment.", 7),
    ("TA0008", "Lateral Movement", "The adversary is trying to move through your environment.", 8),
    ("TA0009", "Collection", "The adversary is trying to gather data of interest to their goal.", 9),
    ("TA0011", "Command and Control", "The adversary is trying to communicate with compromised systems.", 10),
    ("TA0010", "Exfiltration", "The adversary is trying to steal data.", 11),
    ("TA0040", "Impact", "The adversary is trying to manipulate, interrupt, or destroy your systems.", 12),
]


class MigrationRunner:
    """Deterministic migration runner for AegisX database."""

    def __init__(self, schema_path: Optional[Path] = None):
        self.schema_path = schema_path or (Path(__file__).parent / "schema.sql")
        self._applied_migrations: List[Dict[str, Any]] = []

    def get_core_tables(self) -> List[str]:
        """Return the authoritative list of 25 core schema tables."""
        return list(CORE_SCHEMA_TABLES)

    def verify_table_count(self) -> Dict[str, Any]:
        """Verify the exact table count in schema.sql matches authoritative 25."""
        import re
        if not self.schema_path.exists():
            return {"verified": False, "error": f"Schema file {self.schema_path} does not exist"}

        with open(self.schema_path, "r", encoding="utf-8") as f:
            content = f.read()

        tables = re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?([a-zA-Z0-9_]+)", content)
        return {
            "verified": len(tables) == 25,
            "table_count": len(tables),
            "expected": 25,
            "tables": tables,
        }

    async def apply_migrations(self, pool: Optional[Any] = None) -> Dict[str, Any]:
        """Apply the initial schema and migrations to the database.

        If pool is None or not connected, tracks migration state in-memory.
        """
        verification = self.verify_table_count()
        if not verification.get("verified"):
            return {
                "success": False,
                "error": "Schema verification failed before migration",
                "details": verification,
            }

        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema_content = f.read()

        checksum = hashlib.sha256(schema_content.encode("utf-8")).hexdigest()
        migration_record = {
            "version": "001_initial_schema",
            "description": "25 core AegisX SOC platform tables",
            "checksum": checksum,
            "applied_at": datetime.now(timezone.utc).isoformat(),
        }

        # Offline / in-memory development fallback
        if pool is None or not getattr(pool, "is_initialized", False):
            if migration_record not in self._applied_migrations:
                self._applied_migrations.append(migration_record)
            logger.info("Migrations recorded in development/test in-memory mode.")
            return {
                "success": True,
                "mode": "in_memory",
                "applied": [migration_record["version"]],
                "table_count": verification["table_count"],
            }

        # Active PostgreSQL execution
        try:
            # 1. Ensure schema_migrations table exists
            await pool.execute(SCHEMA_MIGRATIONS_DDL)

            # 2. Check if migration already applied
            row = await pool.fetchrow(
                "SELECT version, applied_at FROM schema_migrations WHERE version = $1",
                "001_initial_schema",
            )
            if row:
                logger.info("Schema migration 001_initial_schema already applied at %s", row["applied_at"])
                return {
                    "success": True,
                    "mode": "postgresql",
                    "applied": [],
                    "message": "Schema already up to date",
                }

            # 3. Apply full schema
            await pool.execute(schema_content)

            # 4. Record migration in tracking table
            await pool.execute(
                """
                INSERT INTO schema_migrations (version, description, checksum, applied_at)
                VALUES ($1, $2, $3, NOW())
                """,
                migration_record["version"],
                migration_record["description"],
                migration_record["checksum"],
            )

            # 5. Seed initial data
            seeded = await self.seed_initial_data(pool)

            self._applied_migrations.append(migration_record)
            logger.info("Successfully applied 001_initial_schema to PostgreSQL database.")
            return {
                "success": True,
                "mode": "postgresql",
                "applied": [migration_record["version"]],
                "seeded": seeded,
            }
        except Exception as exc:
            logger.error("Failed to apply migrations: %s", exc)
            return {"success": False, "mode": "postgresql", "error": str(exc)}

    def apply_migrations_sync(self, pool: Optional[Any] = None) -> Dict[str, Any]:
        """Synchronous migration execution."""
        from backend.database.connection import _run_sync
        return _run_sync(self.apply_migrations(pool))

    async def seed_initial_data(self, pool: Any) -> Dict[str, int]:
        """Seed default admin user, MITRE tactics, and initial threat intel records."""
        counts = {"users": 0, "tactics": 0, "threat_intel": 0}
        if not getattr(pool, "is_initialized", False):
            return counts

        try:
            # Seed default users
            default_users = [
                ("usr-admin-001", "admin", "admin@aegisx.local", "AegisX Administrator", "admin"),
                ("usr-analyst-001", "analyst", "analyst@aegisx.local", "Senior SOC Analyst", "analyst"),
                ("usr-viewer-001", "viewer", "viewer@aegisx.local", "Security Auditor", "viewer"),
            ]
            for uid, username, email, dname, role in default_users:
                await pool.execute(
                    """
                    INSERT INTO users (user_id, username, email, display_name, role)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (username) DO NOTHING
                    """,
                    uid, username, email, dname, role,
                )
                counts["users"] += 1

            # Seed MITRE tactics
            for tid, name, desc, order in DEFAULT_TACTICS:
                await pool.execute(
                    """
                    INSERT INTO mitre_tactics (tactic_id, name, description, kill_chain_order)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (tactic_id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
                    """,
                    tid, name, desc, order,
                )
                counts["tactics"] += 1

            # Seed threat intel indicators
            from ai.tools.synthetic_threat_intel import SYNTHETIC_THREAT_INTEL_DB
            for indicator, data in SYNTHETIC_THREAT_INTEL_DB.items():
                ind_type = data.get("indicator_type", "ip")
                threat_type = data.get("malware_family") or data.get("threat_actor") or "malware"
                reputation = data.get("reputation", "malicious")
                confidence = float(data.get("confidence", 0.9))
                source = "AegisX Threat Intel Seed"
                desc = data.get("description", "")
                tags = data.get("tags", [])
                meta = json.dumps({
                    "threat_actor": data.get("threat_actor"),
                    "malware_family": data.get("malware_family"),
                    "associated_ports": data.get("associated_ports"),
                    "mitre_techniques": data.get("mitre_techniques"),
                })
                await pool.execute(
                    """
                    INSERT INTO threat_intelligence (
                        indicator_type, indicator_value, threat_type, reputation,
                        confidence, source, description, tags, metadata
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                    """,
                    ind_type, indicator, threat_type, reputation,
                    confidence, source, desc, tags, meta,
                )
                counts["threat_intel"] += 1

        except Exception as exc:
            logger.warning("Data seeding partially completed or encountered error: %s", exc)

        return counts

    def status(self) -> Dict[str, Any]:
        """Report migration status."""
        verification = self.verify_table_count()
        return {
            "status": "ready",
            "schema_path": str(self.schema_path),
            "schema_tables_verified": verification["verified"],
            "table_count": verification["table_count"],
            "core_tables": self.get_core_tables(),
            "applied_count": len(self._applied_migrations),
            "applied_migrations": list(self._applied_migrations),
        }
