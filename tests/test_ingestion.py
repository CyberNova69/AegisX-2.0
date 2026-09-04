"""Tests for the AegisX external dataset ingestion foundation (Phase 1)."""

import json
import os
import unittest

from ai.ingestion import (
    IngestionPipeline, discover, detect_format, map_record, infer_event_type,
)
from ai.ingestion.types import Format, CanonicalEvent
from ai.ingestion.parsers.base import MissingDependencyError

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "ingestion")


class TestFormatDetection(unittest.TestCase):
    def test_detect_csv(self):
        fmt, _ = detect_format(os.path.join(FIX, "auth_events.csv"))
        self.assertEqual(fmt, Format.CSV)

    def test_detect_json(self):
        fmt, _ = detect_format(os.path.join(FIX, "process_events.json"))
        self.assertEqual(fmt, Format.JSON)

    def test_detect_jsonl(self):
        fmt, _ = detect_format(os.path.join(FIX, "network.jsonl"))
        self.assertEqual(fmt, Format.JSONL)

    def test_detect_xml(self):
        fmt, _ = detect_format(os.path.join(FIX, "events.xml"))
        self.assertEqual(fmt, Format.XML)

    def test_detect_text_log(self):
        fmt, _ = detect_format(os.path.join(FIX, "system.log"))
        self.assertEqual(fmt, Format.TEXT_LOG)


class TestParsers(unittest.TestCase):
    def test_csv_count(self):
        p = IngestionPipeline().run(os.path.join(FIX, "auth_events.csv"))
        self.assertEqual(p.total_records, 3)

    def test_json_count(self):
        p = IngestionPipeline().run(os.path.join(FIX, "process_events.json"))
        self.assertEqual(p.total_records, 2)

    def test_jsonl_count(self):
        p = IngestionPipeline().run(os.path.join(FIX, "network.jsonl"))
        self.assertEqual(p.total_records, 2)

    def test_malformed_jsonl_is_preserved_and_reported(self):
        p = IngestionPipeline().run(os.path.join(FIX, "malformed.jsonl"))
        self.assertEqual(p.total_records, 3)
        self.assertEqual(p.errors, 1)
        malformed = [e for e in p.events if e.raw.get("_parse_error")]
        self.assertEqual(len(malformed), 1)
        self.assertIn("JSONL line 2", malformed[0].raw["_parse_error"])

    def test_xml_count(self):
        p = IngestionPipeline().run(os.path.join(FIX, "events.xml"))
        self.assertEqual(p.total_records, 2)

    def test_text_count(self):
        p = IngestionPipeline().run(os.path.join(FIX, "system.log"))
        self.assertEqual(p.total_records, 3)


class TestCanonicalization(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIX, "process_events.json"), encoding="utf-8") as fh:
            self.records = json.load(fh)

    def test_key_variant_mapping(self):
        ev = map_record(self.records[0], "process_events", 0, Format.JSON, "proc-000000")
        # 'SourceIp', 'src_ip-ish', and 'ip' all collapse to source_ip
        self.assertEqual(ev.source_ip, "91.234.56.78")
        # 'Computer' -> hostname
        self.assertEqual(ev.hostname, "SRV-FILE-01")
        # 'Account' -> username
        self.assertEqual(ev.username, "it_admin02")
        # 'CommandLine' -> command_line
        self.assertTrue(ev.command_line.startswith("powershell"))
        # 'eventTime' -> normalized ISO-8601 UTC timestamp
        self.assertEqual(ev.timestamp, "2026-09-04T12:00:00Z")
        self.assertEqual(ev.event_type, "process_creation")

    def test_network_event_type(self):
        with open(os.path.join(FIX, "network.jsonl"), encoding="utf-8") as fh:
            rec = json.loads(fh.readline())
        ev = map_record(rec, "network", 0, Format.JSONL, "net-000000")
        self.assertEqual(ev.source_ip, "10.0.0.5")
        self.assertEqual(ev.dest_ip, "8.8.8.8")
        self.assertEqual(ev.domain, "evil.example.com")
        self.assertEqual(ev.event_type, "network_connection")

    def test_xml_field_mapping(self):
        p = IngestionPipeline().run(os.path.join(FIX, "events.xml"))
        first = p.events[0]
        self.assertEqual(first.hostname, "WS-01")
        self.assertEqual(first.username, "bob")
        self.assertEqual(first.event_type, "file_modification")

    def test_to_alert_input_bridge(self):
        ev = map_record(self.records[0], "process_events", 0, Format.JSON, "proc-000000")
        alert = ev.to_alert_input()
        self.assertIn("alert", alert)
        self.assertIn("context", alert)
        self.assertIn("evidence", alert)
        self.assertEqual(alert["context"]["hostname"], "SRV-FILE-01")
        self.assertEqual(alert["evidence"][0]["id"], "EVT-000001")


class TestEventInference(unittest.TestCase):
    def test_auth_inference_from_text(self):
        flat = {"message": "failed logon for user bob", "level": "info"}
        self.assertEqual(infer_event_type(flat), "authentication")


class TestPipeline(unittest.TestCase):
    def test_run_over_fixtures_dir(self):
        result = IngestionPipeline().run(FIX)
        # 3 CSV + 2 JSON + 3 pre-existing malformed JSONL + 2 network JSONL +
        # 5 processing JSONL + 2 XML + 3 text log = 20 canonical records.
        self.assertEqual(result.total_records, 20)
        self.assertEqual(result.by_format.get("csv"), 3)
        self.assertEqual(result.by_format.get("json"), 2)
        self.assertEqual(result.by_format.get("jsonl"), 10)
        self.assertEqual(result.by_format.get("xml"), 2)
        self.assertEqual(result.by_format.get("text_log"), 3)
        # One malformed source fixture plus one deliberately malformed record
        # in the Task 2 processing fixture are preserved and counted.
        self.assertEqual(result.errors, 2)

    def test_streaming_ingest_limits_memory(self):
        events = list(IngestionPipeline(max_records=4).ingest(FIX))
        self.assertEqual(len(events), 4)
        for ev in events:
            self.assertIsInstance(ev, CanonicalEvent)

    def test_run_honors_global_record_limit(self):
        result = IngestionPipeline(max_records=2).run(FIX)
        self.assertEqual(result.total_records, 2)
        self.assertEqual(len(result.events), 2)

    def test_discover_skips_venv_like_dirs(self):
        sources = discover(FIX)
        paths = [s.path for s in sources]
        self.assertGreater(len(sources), 0)
        # No nested junk should appear in this clean fixture dir.
        self.assertTrue(all(os.path.isfile(p) for p in paths))


class TestOptionalDependencies(unittest.TestCase):
    def test_excel_parser_missing_dep(self):
        parser = __import__(
            "ai.ingestion.parsers.excel_parser", fromlist=["ExcelParser"]
        ).ExcelParser()
        with self.assertRaises(MissingDependencyError):
            list(parser.parse(os.path.join(FIX, "auth_events.csv")))

    def test_parquet_parser_missing_dep(self):
        parser = __import__(
            "ai.ingestion.parsers.parquet_parser", fromlist=["ParquetParser"]
        ).ParquetParser()
        with self.assertRaises(MissingDependencyError):
            list(parser.parse(os.path.join(FIX, "auth_events.csv")))


if __name__ == "__main__":
    unittest.main()
