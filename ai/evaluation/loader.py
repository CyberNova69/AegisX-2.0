"""
AegisX Held-Out Test Set Loader
================================

Safe, validating loader for datasets/finetuning/v0.4/test.jsonl.
Strictly read-only, verifies record integrity, schema compliance,
and enforces the test-set firewall.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
)
from ai.evaluation.test_set_firewall import (
    DEFAULT_TEST_SET_PATH,
    EXPECTED_TEST_SET_COUNT,
    TestSetFirewall,
)

class DatasetValidationError(ValueError):
    """Raised when test dataset records violate the expected schema."""
    pass

REQUIRED_RECORD_KEYS = {"id", "task", "input", "output", "metadata"}
REQUIRED_INPUT_KEYS = {"alert", "context", "evidence"}
REQUIRED_OUTPUT_KEYS = {"classification", "confidence", "findings"}

def load_test_records(
    filepath: Optional[Path] = None,
    enforce_count: bool = True,
    verify_firewall: bool = True,
) -> List[Dict[str, Any]]:
    """
    Load and strictly validate the held-out test set records.

    Args:
        filepath: Path to the test.jsonl file (defaults to official v0.4 test set).
        enforce_count: If True and using official test set, verifies exactly 300 records.
        verify_firewall: If True, asserts read-only access and firewall integrity.

    Returns:
        List[Dict[str, Any]]: Validated list of raw test dataset records.

    Raises:
        FileNotFoundError: If test file is missing.
        FirewallViolationError: If firewall check fails.
        DatasetValidationError: If schema or validation fails.
    """
    target_path = Path(filepath) if filepath else DEFAULT_TEST_SET_PATH
    if not target_path.exists():
        raise FileNotFoundError(f"Test dataset not found at: {target_path}")

    if verify_firewall:
        TestSetFirewall.assert_read_only_access(target_path, "r")

    records: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    with open(target_path, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except json.JSONDecodeError as e:
                raise DatasetValidationError(
                    f"Line {line_idx} in '{target_path.name}' is invalid JSON: {e}"
                )

            if not isinstance(record, dict):
                raise DatasetValidationError(
                    f"Line {line_idx} in '{target_path.name}' is not a JSON object."
                )

            # 1. Top-level keys
            missing = REQUIRED_RECORD_KEYS - set(record.keys())
            if missing:
                rec_id = record.get("id", f"line-{line_idx}")
                raise DatasetValidationError(
                    f"Record '{rec_id}' missing required keys: {sorted(list(missing))}"
                )

            rec_id = record["id"]
            if rec_id in seen_ids:
                raise DatasetValidationError(
                    f"Duplicate record ID '{rec_id}' found at line {line_idx}."
                )
            seen_ids.add(rec_id)

            # 2. Input structure
            inp = record["input"]
            if not isinstance(inp, dict):
                raise DatasetValidationError(f"Record '{rec_id}' has non-dictionary 'input'.")
            missing_input = REQUIRED_INPUT_KEYS - set(inp.keys())
            if missing_input:
                raise DatasetValidationError(
                    f"Record '{rec_id}' input missing keys: {sorted(list(missing_input))}"
                )

            # 3. Output structure & labels
            out = record["output"]
            if not isinstance(out, dict):
                raise DatasetValidationError(f"Record '{rec_id}' has non-dictionary 'output'.")
            missing_out = REQUIRED_OUTPUT_KEYS - set(out.keys())
            if missing_out:
                raise DatasetValidationError(
                    f"Record '{rec_id}' output missing keys: {sorted(list(missing_out))}"
                )

            classification = out["classification"]
            if classification not in VALID_CLASSIFICATIONS:
                raise DatasetValidationError(
                    f"Record '{rec_id}' has invalid classification '{classification}'."
                )

            # Severity check in alert
            sev = inp["alert"].get("severity")
            if sev and sev not in VALID_SEVERITIES:
                raise DatasetValidationError(
                    f"Record '{rec_id}' has invalid alert severity '{sev}'."
                )

            records.append(record)

    # Enforce exact count if official path
    is_official_path = target_path.resolve() == DEFAULT_TEST_SET_PATH.resolve()
    if enforce_count and is_official_path:
        if len(records) != EXPECTED_TEST_SET_COUNT:
            raise DatasetValidationError(
                f"Expected exactly {EXPECTED_TEST_SET_COUNT} records in test set, found {len(records)}."
            )

    return records
