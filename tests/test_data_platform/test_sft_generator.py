"""Tests for the SFT generator."""

import json
import pytest
from pathlib import Path
from aegisx_data.sft.generator import SFTGenerator
from aegisx_data.sft.splitter import DatasetSplitter
from aegisx_data.sft.templates import format_triage_user_prompt, format_assistant_response
from aegisx_data.core.types import (
    AttackCategory, Classification, DatasetRecord, DatasetSourceType, Severity,
)


class TestSFTTemplates:
    def _make_record(self):
        return DatasetRecord(
            record_id="t-001",
            source=DatasetSourceType.CICIDS_2017,
            record_index=0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.50",
            src_port=54321,
            dst_port=80,
            protocol="tcp",
            classification=Classification.MALICIOUS,
            attack_category=AttackCategory.DDOS,
            severity=Severity.HIGH,
            source_label="DDoS",
            confidence=0.9,
        )

    def test_user_prompt_format(self):
        r = self._make_record()
        prompt = format_triage_user_prompt(r)
        assert "Security Alert" in prompt
        assert "192.168.1.100" in prompt
        assert "10.0.0.50" in prompt

    def test_assistant_response_format(self):
        r = self._make_record()
        response = format_assistant_response(r)
        assert response["classification"] == "malicious"
        assert response["severity"] == "high"
        assert 0 < response["confidence"] <= 1.0
        assert isinstance(response["findings"], list)

    def test_benign_no_investigation(self):
        r = self._make_record()
        r.classification = Classification.BENIGN
        r.attack_category = AttackCategory.NONE
        r.confidence = 0.95
        response = format_assistant_response(r)
        assert response["investigation_required"] is False


class TestDatasetSplitter:
    def _make_records(self, n=100):
        records = []
        for i in range(n):
            records.append(DatasetRecord(
                record_id=f"r-{i}", source=DatasetSourceType.CICIDS_2017,
                classification=Classification.BENIGN if i % 3 == 0 else Classification.MALICIOUS,
            ))
        return records

    def test_split_ratios(self):
        splitter = DatasetSplitter(train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)
        records = self._make_records(100)
        train, val, test = splitter.split(records)

        total = len(train) + len(val) + len(test)
        assert total == 100
        assert len(train) >= 70  # Roughly 80%

    def test_invalid_ratios(self):
        with pytest.raises(ValueError):
            DatasetSplitter(train_ratio=0.5, val_ratio=0.5, test_ratio=0.5)

    def test_balance_oversample(self):
        splitter = DatasetSplitter()
        records = self._make_records(100)
        # Unbalanced: ~34 benign, ~66 malicious
        balanced = splitter.balance(records, strategy="oversample_minority")
        assert len(balanced) > 100  # Minority oversampled

    def test_balance_undersample(self):
        splitter = DatasetSplitter()
        records = self._make_records(100)
        balanced = splitter.balance(records, strategy="undersample_majority")
        assert len(balanced) < 100  # Majority undersampled


class TestSFTGenerator:
    def _make_records(self, n=20):
        records = []
        for i in range(n):
            records.append(DatasetRecord(
                record_id=f"r-{i}", source=DatasetSourceType.CICIDS_2017,
                record_index=i,
                src_ip=f"10.0.0.{i}", dst_ip="10.0.0.1",
                protocol="tcp",
                classification=Classification.BENIGN if i % 2 == 0 else Classification.MALICIOUS,
                attack_category=AttackCategory.NONE if i % 2 == 0 else AttackCategory.DDOS,
                severity=Severity.LOW if i % 2 == 0 else Severity.HIGH,
                source_label="BENIGN" if i % 2 == 0 else "DDoS",
            ))
        return records

    def test_generate(self, tmp_path):
        generator = SFTGenerator(
            train_ratio=0.8, val_ratio=0.1, test_ratio=0.1,
        )
        records = self._make_records(20)
        metadata = generator.generate(records, tmp_path / "sft")

        assert (tmp_path / "sft" / "train.jsonl").exists()
        assert (tmp_path / "sft" / "validation.jsonl").exists()
        assert (tmp_path / "sft" / "test.jsonl").exists()
        assert (tmp_path / "sft" / "sft_metadata.json").exists()

        assert metadata["totals"]["converted"] > 0

    def test_chat_format(self, tmp_path):
        generator = SFTGenerator()
        records = self._make_records(5)
        generator.generate(records, tmp_path / "sft")

        with open(tmp_path / "sft" / "train.jsonl") as f:
            line = f.readline()
            example = json.loads(line)

        assert "messages" in example
        assert len(example["messages"]) == 3
        assert example["messages"][0]["role"] == "system"
        assert example["messages"][1]["role"] == "user"
        assert example["messages"][2]["role"] == "assistant"

        # Assistant response should be valid JSON
        assistant_text = example["messages"][2]["content"]
        response = json.loads(assistant_text)
        assert "classification" in response
