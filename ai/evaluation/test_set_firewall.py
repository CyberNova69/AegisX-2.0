"""
AegisX Held-Out Test Set Firewall
==================================

Enforces strict isolation of the 300-record held-out test dataset
(datasets/finetuning/v0.4/test.jsonl).

Rules:
  1. The test set is PROTECTED and HELD-OUT.
  2. Evaluation code may read test.jsonl strictly in read-only mode ('r').
  3. Training preparation and fine-tuning pipelines MUST NOT read or include test.jsonl.
  4. Write/append/modify operations targeting test.jsonl are strictly prohibited.
  5. The test set must match its golden SHA-256 hash bit-for-bit.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_TEST_SET_PATH = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "test.jsonl"
EXPECTED_TEST_SET_SHA256 = "BFF898861F75A0982D6C2F6EFDBA99F0C5E8549A4B0EA72A687E91A8D80A4333"
EXPECTED_TEST_SET_COUNT = 300

class FirewallViolationError(PermissionError):
    """Raised when an operation violates the held-out test set firewall."""
    pass

class TestSetFirewall:
    """Security firewall guarding the held-out benchmark test set."""

    @staticmethod
    def compute_sha256(filepath: Path) -> str:
        """Compute uppercase SHA-256 hex digest of a file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest().upper()

    @classmethod
    def verify_test_set_integrity(
        cls,
        test_path: Optional[Path] = None,
        expected_hash: str = EXPECTED_TEST_SET_SHA256,
        expected_count: int = EXPECTED_TEST_SET_COUNT,
    ) -> Dict[str, Any]:
        """
        Verify the held-out test set exists, has not been altered, and has the exact count.
        """
        path = Path(test_path) if test_path else DEFAULT_TEST_SET_PATH
        if not path.exists():
            raise FileNotFoundError(f"Test set not found at {path}")

        current_hash = cls.compute_sha256(path)
        with open(path, "r", encoding="utf-8") as f:
            count = sum(1 for line in f if line.strip())

        is_hash_valid = current_hash.upper() == expected_hash.upper()
        is_count_valid = count == expected_count

        if not is_hash_valid:
            raise FirewallViolationError(
                f"Test set hash mismatch! Expected {expected_hash}, got {current_hash}. "
                "The held-out test set may have been modified or corrupted."
            )
        if not is_count_valid:
            raise FirewallViolationError(
                f"Test set record count mismatch! Expected {expected_count}, got {count}."
            )

        return {
            "path": str(path),
            "sha256": current_hash,
            "record_count": count,
            "integrity_verified": True,
        }

    @classmethod
    def assert_read_only_access(cls, file_path: Path, mode: str) -> None:
        """
        Assert that file access to test.jsonl is strictly read-only.
        Rejects write ('w'), append ('a'), update ('+'), and exclusive create ('x').
        """
        norm_path = Path(file_path).resolve()
        test_norm = DEFAULT_TEST_SET_PATH.resolve()

        if norm_path == test_norm or norm_path.name == "test.jsonl":
            write_modes = {"w", "a", "+", "x"}
            if any(m in mode for m in write_modes):
                raise FirewallViolationError(
                    f"Firewall Violation: Attempted modifying held-out test set '{norm_path}' with mode '{mode}'."
                )

    @classmethod
    def verify_training_isolation(cls, sft_dir: Optional[Path] = None) -> bool:
        """
        Verify that the SFT training dataset directory does NOT contain or reference test.jsonl.
        """
        target_sft = Path(sft_dir) if sft_dir else PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "sft"
        if not target_sft.exists():
            return True

        # Check that test.jsonl is not in the SFT output directory
        sft_test = target_sft / "test.jsonl"
        if sft_test.exists():
            raise FirewallViolationError(
                f"Firewall Violation: test.jsonl found in SFT training directory: {sft_test}"
            )

        # Check conversion metadata if present
        meta_file = target_sft / "conversion_metadata.json"
        if meta_file.exists():
            import json
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if not meta.get("test_set_excluded", False):
                raise FirewallViolationError(
                    "Firewall Violation: SFT conversion metadata does not confirm test_set_excluded=True."
                )

        return True
