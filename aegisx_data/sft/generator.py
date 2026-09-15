"""SFT dataset generator.

Converts processed DatasetRecords into supervised fine-tuning chat format
compatible with the existing finetuning/prepare_sft_dataset.py output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.types import Classification, DatasetRecord
from .splitter import DatasetSplitter, ProtectedTestFirewall
from .templates import (
    TRIAGE_SYSTEM_PROMPT,
    format_assistant_response,
    format_triage_user_prompt,
)


class SFTGenerator:
    """Generate SFT chat-format datasets from processed records.

    Output format (per line in JSONL):
        {
          "messages": [
            {"role": "system", "content": "<system prompt>"},
            {"role": "user", "content": "<formatted alert>"},
            {"role": "assistant", "content": "<structured JSON response>"}
          ]
        }

    This format is model-agnostic. The tokenizer's apply_chat_template()
    is applied at training time, matching the existing pipeline.
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        balance_strategy: str = "none",
        max_examples: Optional[int] = None,
        seed: int = 42,
        protected_test_path: Optional[Path] = None,
    ):
        self.system_prompt = system_prompt or TRIAGE_SYSTEM_PROMPT

        # Build test firewall if a protected test set path is provided
        firewall = None
        if protected_test_path and protected_test_path.exists():
            firewall = ProtectedTestFirewall.from_jsonl(protected_test_path)

        self.splitter = DatasetSplitter(
            train_ratio=train_ratio,
            val_ratio=val_ratio,
            test_ratio=test_ratio,
            seed=seed,
            test_firewall=firewall,
        )
        self.balance_strategy = balance_strategy
        self.max_examples = max_examples
        self.seed = seed

    def convert_record(self, record: DatasetRecord) -> Optional[Dict[str, Any]]:
        """Convert a single record to SFT chat format.

        Returns None if the record cannot be converted.
        """
        try:
            user_prompt = format_triage_user_prompt(record)
            assistant_response = format_assistant_response(record)
            assistant_json = json.dumps(assistant_response, indent=2)

            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": assistant_json},
            ]

            return {"messages": messages}
        except Exception:
            return None

    def generate(
        self,
        records: List[DatasetRecord],
        output_dir: Path,
    ) -> Dict[str, Any]:
        """Generate train/val/test SFT datasets.

        Args:
            records: Processed DatasetRecord instances
            output_dir: Directory to write JSONL files to

        Returns:
            Generation metadata dict
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Filter to records with classifications, excluding REVIEW_REQUIRED
        # (REVIEW_REQUIRED records need human review before becoming SFT examples)
        labeled = [
            r for r in records
            if r.classification is not None
            and r.classification != Classification.REVIEW_REQUIRED
        ]

        if self.max_examples and len(labeled) > self.max_examples:
            import random
            rng = random.Random(self.seed)
            labeled = rng.sample(labeled, self.max_examples)

        # Balance
        if self.balance_strategy != "none":
            labeled = self.splitter.balance(labeled, strategy=self.balance_strategy)

        # Split
        train_records, val_records, test_records = self.splitter.split(labeled)

        # Convert and write each split
        train_result = self._write_split(train_records, output_dir / "train.jsonl", "train")
        val_result = self._write_split(val_records, output_dir / "validation.jsonl", "validation")
        test_result = self._write_split(test_records, output_dir / "test.jsonl", "test")

        # Metadata
        metadata = {
            "schema_version": "sft-chat-v1",
            "system_prompt_length": len(self.system_prompt),
            "balance_strategy": self.balance_strategy,
            "seed": self.seed,
            "source_records": len(records),
            "labeled_records": len(labeled),
            "splits": {
                "train": train_result,
                "validation": val_result,
                "test": test_result,
            },
            "totals": {
                "converted": sum(r["converted"] for r in [train_result, val_result, test_result]),
                "rejected": sum(r["rejected"] for r in [train_result, val_result, test_result]),
            },
        }

        # Write metadata
        with open(output_dir / "sft_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return metadata

    def _write_split(
        self,
        records: List[DatasetRecord],
        output_path: Path,
        split_name: str,
    ) -> Dict[str, Any]:
        """Convert and write one split."""
        converted = 0
        rejected = 0

        with open(output_path, "w", encoding="utf-8") as f:
            for record in records:
                example = self.convert_record(record)
                if example:
                    f.write(json.dumps(example, ensure_ascii=False) + "\n")
                    converted += 1
                else:
                    rejected += 1

        file_hash = self._compute_hash(output_path)

        return {
            "split": split_name,
            "input_records": len(records),
            "converted": converted,
            "rejected": rejected,
            "file": output_path.name,
            "sha256": file_hash,
        }

    @staticmethod
    def _compute_hash(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
