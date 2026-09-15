"""Tests for the run manager."""

import json
import pytest
from pathlib import Path
from aegisx_data.training.run_manager import RunManager
from aegisx_data.core.types import RunStatus


class TestRunManager:
    def test_create_run(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        run = rm.create_run(
            dataset_version="1.0",
            base_model="qwen2.5-7b",
            run_id="test_run_001",
        )
        assert run.run_id == "test_run_001"
        assert run.status == RunStatus.PENDING
        assert (tmp_path / "runs" / "test_run_001" / "run.json").exists()

    def test_start_run(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        run = rm.create_run("1.0", "qwen", run_id="run_start")
        run = rm.start_run("run_start")
        assert run.status == RunStatus.RUNNING
        assert run.started_at is not None

    def test_complete_run(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_complete")
        rm.start_run("run_complete")
        run = rm.complete_run("run_complete", metrics={"accuracy": 0.85})
        assert run.status == RunStatus.COMPLETED
        assert run.metrics["accuracy"] == 0.85

    def test_fail_run(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_fail")
        rm.start_run("run_fail")
        run = rm.fail_run("run_fail", "OOM error")
        assert run.status == RunStatus.FAILED
        assert run.error_message == "OOM error"

    def test_log_metrics(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_metrics")
        rm.log_metrics("run_metrics", epoch=1, metrics={"loss": 0.5})
        rm.log_metrics("run_metrics", epoch=2, metrics={"loss": 0.3})

        run = rm.get_run("run_metrics")
        assert run.metrics["1"]["loss"] == 0.5
        assert run.metrics["2"]["loss"] == 0.3

    def test_list_runs(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_a")
        rm.create_run("1.0", "qwen", run_id="run_b")

        runs = rm.list_runs()
        assert len(runs) == 2

    def test_list_runs_by_status(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_pending")
        rm.create_run("1.0", "qwen", run_id="run_running")
        rm.start_run("run_running")

        pending = rm.list_runs(status=RunStatus.PENDING)
        assert len(pending) == 1
        assert pending[0].run_id == "run_pending"

    def test_compare_runs(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="r1")
        rm.create_run("2.0", "llama", run_id="r2")

        comparison = rm.compare_runs(["r1", "r2"])
        assert len(comparison["runs"]) == 2

    def test_get_nonexistent_raises(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        with pytest.raises(FileNotFoundError):
            rm.get_run("nonexistent")

    def test_delete_run(self, tmp_path):
        rm = RunManager(tmp_path / "runs")
        rm.create_run("1.0", "qwen", run_id="run_delete")
        rm.delete_run("run_delete")
        assert not (tmp_path / "runs" / "run_delete").exists()
