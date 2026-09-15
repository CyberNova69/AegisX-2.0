"""
AegisX Data Platform
=====================

External cybersecurity dataset ingestion, processing, fine-tuning,
and model management platform for AegisX SOC.

This package provides:
- External dataset connectors (CICIDS, CTU-13, UNSW-NB15, EMBER, MITRE ATT&CK)
- Processing pipeline (normalize → validate → deduplicate → enrich → harmonize)
- Dataset quality analysis
- Dataset versioning
- SFT dataset generation
- Training run management
- Model evaluation and registry
- Unified CLI interface
"""

__version__ = "0.1.0"
__author__ = "AegisX Team"
