"""Stratified dataset splitter with configurable ratios and seed control.

Includes a test firewall that prevents protected test records from
leaking into train/validation splits.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ..core.types import DatasetRecord


class ProtectedTestFirewall:
    """Deterministic test-set protection.

    Computes SHA-256 content fingerprints from a protected test JSONL file.
    Records matching these fingerprints are excluded from train/validation
    splits and can only appear in the test split.

    Fingerprints are computed from canonical JSON (sorted keys, compact
    separators), making them deterministic regardless of field ordering.
    """

    def __init__(self, fingerprints: FrozenSet[str]):
        self._fingerprints = fingerprints

    @classmethod
    def from_jsonl(cls, path: Path) -> "ProtectedTestFirewall":
        """Load protected test fingerprints from a JSONL file.

        Args:
            path: Path to the protected test JSONL (e.g. datasets/finetuning/v1.0/test.jsonl)

        Returns:
            ProtectedTestFirewall with fingerprints for each line in the file.
        """
        fingerprints: Set[str] = set()
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    # Canonicalize: parse and re-serialize with sorted keys
                    try:
                        obj = json.loads(line)
                        canonical = json.dumps(obj, sort_keys=True,
                                               ensure_ascii=False,
                                               separators=(",", ":"))
                    except json.JSONDecodeError:
                        canonical = line
                    fp = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    fingerprints.add(fp)
        return cls(frozenset(fingerprints))

    def fingerprint_record_dict(self, record_dict: Dict) -> str:
        """Compute the SHA-256 fingerprint for a record dict.

        Uses the same serialization as the JSONL line format.
        """
        line = json.dumps(record_dict, ensure_ascii=False, separators=(",", ":"),
                          sort_keys=True)
        return hashlib.sha256(line.encode("utf-8")).hexdigest()

    def is_protected(self, record_fingerprint: str) -> bool:
        """Check if a record matches a protected test fingerprint."""
        return record_fingerprint in self._fingerprints

    @property
    def size(self) -> int:
        """Number of protected test fingerprints."""
        return len(self._fingerprints)


class DatasetSplitter:
    """Split records into train/val/test with stratification by classification.

    Ensures each split maintains roughly the same class distribution.

    If a TestFirewall is provided, protected test records are excluded from
    train and validation splits. Protected records are NOT added to the test
    split (they already exist in the protected test set).
    """

    def __init__(
        self,
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        seed: int = 42,
        test_firewall: Optional[ProtectedTestFirewall] = None,
    ):
        total = train_ratio + val_ratio + test_ratio
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Ratios must sum to 1.0, got {total}")

        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.seed = seed
        self.test_firewall = test_firewall
        self.firewall_excluded: int = 0  # Count of records excluded by firewall

    def split(
        self, records: List[DatasetRecord]
    ) -> Tuple[List[DatasetRecord], List[DatasetRecord], List[DatasetRecord]]:
        """Split records into train, validation, and test sets.

        Uses stratified splitting by classification to maintain class balance.
        If a TestFirewall is configured, matching records are excluded from
        all splits (they are already in the protected test set).
        """
        rng = random.Random(self.seed)
        self.firewall_excluded = 0

        # Filter out protected test records if firewall is active
        if self.test_firewall:
            filtered = []
            for record in records:
                rd = record.to_dict()
                fp = self.test_firewall.fingerprint_record_dict(rd)
                if self.test_firewall.is_protected(fp):
                    self.firewall_excluded += 1
                else:
                    filtered.append(record)
            records = filtered

        # Group by classification
        groups: Dict[str, List[DatasetRecord]] = {}
        for record in records:
            key = record.classification.value if record.classification else "unlabeled"
            groups.setdefault(key, []).append(record)

        train: List[DatasetRecord] = []
        val: List[DatasetRecord] = []
        test: List[DatasetRecord] = []

        for _cls, group in groups.items():
            rng.shuffle(group)
            n = len(group)
            n_train = max(1, int(n * self.train_ratio))
            n_val = max(0, int(n * self.val_ratio))
            # test gets the remainder
            n_test = n - n_train - n_val

            if n_test < 0:
                n_test = 0
                n_val = n - n_train

            train.extend(group[:n_train])
            val.extend(group[n_train:n_train + n_val])
            test.extend(group[n_train + n_val:])

        # Shuffle each split
        rng.shuffle(train)
        rng.shuffle(val)
        rng.shuffle(test)

        return train, val, test

    def balance(
        self,
        records: List[DatasetRecord],
        strategy: str = "oversample_minority",
        target_count: Optional[int] = None,
    ) -> List[DatasetRecord]:
        """Balance class distribution.

        Strategies:
            - "none": no balancing
            - "oversample_minority": duplicate minority class records
            - "undersample_majority": remove majority class records
        """
        if strategy == "none":
            return records

        rng = random.Random(self.seed)

        groups: Dict[str, List[DatasetRecord]] = {}
        for record in records:
            key = record.classification.value if record.classification else "unlabeled"
            groups.setdefault(key, []).append(record)

        if not groups:
            return records

        counts = {cls: len(recs) for cls, recs in groups.items()}

        if strategy == "oversample_minority":
            target = target_count or max(counts.values())
            balanced: List[DatasetRecord] = []
            for cls, recs in groups.items():
                if len(recs) >= target:
                    balanced.extend(recs[:target])
                else:
                    # Repeat + sample remainder
                    repeats = target // len(recs)
                    remainder = target % len(recs)
                    balanced.extend(recs * repeats)
                    balanced.extend(rng.sample(recs, min(remainder, len(recs))))
            rng.shuffle(balanced)
            return balanced

        elif strategy == "undersample_majority":
            target = target_count or min(counts.values())
            balanced = []
            for cls, recs in groups.items():
                rng.shuffle(recs)
                balanced.extend(recs[:target])
            rng.shuffle(balanced)
            return balanced

        return records
