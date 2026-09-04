"""Tests for Task 2: normalize -> validate -> exact deduplicate."""

import os
import unittest

from ai.ingestion import (
    CanonicalEvent, EventDeduplicator, EventNormalizer, EventProcessor,
    EventValidator, Format, IngestionPipeline,
)

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "ingestion")
PROCESSING_SOURCE = os.path.join(FIX, "processing_events.jsonl")


class TestEventNormalizer(unittest.TestCase):
    def test_normalizes_timestamp_severity_hostname_and_whitespace(self):
        event = CanonicalEvent(
            event_id="E-1", source_name="x", source_format=Format.JSONL,
            timestamp="2026-09-04 12:00:00", hostname=" WS-01 ",
            username=" alice   smith ", severity="WARN", event_type="authentication",
        )
        out = EventNormalizer().normalize(event)
        self.assertEqual(out.event.timestamp, "2026-09-04T12:00:00Z")
        self.assertEqual(out.event.hostname, "ws-01")
        self.assertEqual(out.event.username, "alice smith")
        self.assertEqual(out.event.severity, "medium")
        self.assertTrue(out.normalization_actions)
        # Original object stays unchanged; processing is provenance-safe.
        self.assertEqual(event.hostname, " WS-01 ")

    def test_does_not_guess_unparseable_timestamp(self):
        event = CanonicalEvent(
            event_id="E-1", source_name="x", source_format=Format.JSONL,
            timestamp="not-a-date", event_type="generic",
        )
        out = EventNormalizer().normalize(event)
        self.assertIsNone(out.event.timestamp)
        self.assertEqual(out.event.attributes["_unparsed_timestamp"], "not-a-date")
        # Validator exposes the gap as a warning.
        issues = EventValidator().validate(out)
        self.assertIn("missing_timestamp", [i.code for i in issues])


class TestEventValidator(unittest.TestCase):
    def test_port_out_of_range_rejected(self):
        event = CanonicalEvent(
            event_id="E-1", source_name="x", source_format=Format.JSONL,
            event_type="network_connection", port=70000,
        )
        out = EventNormalizer().normalize(event)
        issues = EventValidator().validate(out)
        self.assertIn("invalid_port", [i.code for i in issues])
        self.assertTrue(any(i.severity == "error" for i in issues))

    def test_missing_timestamp_is_warning_not_rejection(self):
        event = CanonicalEvent(
            event_id="E-1", source_name="x", source_format=Format.JSONL,
            event_type="authentication", hostname="ws-01",
        )
        out = EventNormalizer().normalize(event)
        issues = EventValidator().validate(out)
        self.assertIn("missing_timestamp", [i.code for i in issues])
        self.assertFalse(any(i.severity == "error" for i in issues))

    def test_parse_error_rejected(self):
        event = CanonicalEvent(
            event_id="E-1", source_name="x", source_format=Format.JSONL,
            event_type="raw", raw={"_parse_error": "invalid JSON"},
        )
        outcome = EventProcessor().process_one(event)
        self.assertEqual(outcome.status, "rejected")
        self.assertIn("source_parse_error", [i.code for i in outcome.normalized.validation_issues])


class TestExactDeduplication(unittest.TestCase):
    def _event(self, eid):
        return CanonicalEvent(
            event_id=eid, source_name="x", source_format=Format.JSONL,
            timestamp="2026-09-04T12:00:00Z", event_type="authentication",
            hostname="ws-01", username="alice", source_ip="10.0.0.5",
        )

    def test_exact_duplicates_have_stable_fingerprint(self):
        processor = EventProcessor()
        first = processor.process_one(self._event("E-1"))
        second = processor.process_one(self._event("E-2"))
        self.assertEqual(first.status, "trusted")
        self.assertEqual(second.status, "duplicate")
        self.assertEqual(second.normalized.duplicate_of, "E-1")
        self.assertEqual(first.normalized.fingerprint, second.normalized.fingerprint)

    def test_change_in_semantic_field_is_not_duplicate(self):
        processor = EventProcessor()
        first = self._event("E-1")
        second = self._event("E-2")
        second.username = "bob"
        self.assertEqual(processor.process_one(first).status, "trusted")
        self.assertEqual(processor.process_one(second).status, "trusted")

    def test_bounded_window_eviction_is_reported(self):
        dedup = EventDeduplicator(max_fingerprints=1)
        processor = EventProcessor(deduplicator=dedup)
        first = self._event("E-1")
        other = self._event("E-2")
        other.username = "bob"
        again = self._event("E-3")
        self.assertEqual(processor.process_one(first).status, "trusted")
        self.assertEqual(processor.process_one(other).status, "trusted")
        self.assertEqual(dedup.evictions, 1)
        # First fingerprint has fallen outside bounded memory, so duplicate cannot
        # be claimed globally and is accepted. This is documented behavior.
        self.assertEqual(processor.process_one(again).status, "trusted")


class TestProcessingPipeline(unittest.TestCase):
    def test_processing_fixture_summary(self):
        trusted, report, outcomes = IngestionPipeline().run_processed(PROCESSING_SOURCE)
        self.assertEqual(report.input_events, 5)
        self.assertEqual(report.trusted_events, 2)
        self.assertEqual(report.duplicate_events, 1)
        self.assertEqual(report.rejected_events, 2)
        self.assertEqual(report.errors, 2)
        self.assertGreaterEqual(report.warnings, 1)
        self.assertEqual(len(trusted), 2)
        self.assertEqual([o.status for o in outcomes], [
            "trusted", "duplicate", "trusted", "rejected", "rejected",
        ])

    def test_streaming_process_only_yields_trusted(self):
        events = list(IngestionPipeline().process(PROCESSING_SOURCE))
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e.trusted for e in events))
        self.assertEqual(events[0].event.hostname, "ws-01")

    def test_trusted_event_retains_raw_provenance_and_agent_bridge(self):
        event = next(IngestionPipeline().process(PROCESSING_SOURCE))
        self.assertIn("host", event.event.raw)
        alert_input = event.to_alert_input()
        self.assertEqual(alert_input["context"]["hostname"], "ws-01")
        self.assertTrue(alert_input["evidence"][0]["id"].startswith("EVT-"))


if __name__ == "__main__":
    unittest.main()
