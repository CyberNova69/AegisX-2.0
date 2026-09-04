"""
AegisX Document Ingestion & Chunking
====================================

Loads and normalizes threat intelligence knowledge sources:
  - MITRE ATT&CK techniques from datasets/metadata/mitre_reference.json
  - Synthetic threat intelligence database from ai/tools/synthetic_threat_intel.py
Splits documents into overlapping chunks suitable for retrieval.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai.tools.synthetic_threat_intel import list_all_threat_intel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MITRE_PATH = PROJECT_ROOT / "datasets" / "metadata" / "mitre_reference.json"

@dataclass
class Document:
    """Normalized source document prior to chunking."""
    id: str
    title: str
    content: str
    source_type: str  # "mitre_technique", "threat_intel_report", "playbook"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "source_type": self.source_type,
            "metadata": self.metadata,
        }

@dataclass
class DocumentChunk:
    """Atomic text chunk indexed for vector/keyword retrieval."""
    chunk_id: str
    document_id: str
    title: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "title": self.title,
            "content": self.content,
            "metadata": self.metadata,
        }

class DocumentIngester:
    """Ingests raw security knowledge bases and produces indexed text chunks."""

    def __init__(self, chunk_size: int = 400, chunk_overlap: int = 50):
        self.chunk_size = max(50, int(chunk_size))
        self.chunk_overlap = max(0, min(self.chunk_size - 1, int(chunk_overlap)))

    def load_mitre_reference(self, path: Optional[Path] = None) -> List[Document]:
        """Load MITRE ATT&CK reference records and convert into Document objects."""
        mitre_file = Path(path) if path else DEFAULT_MITRE_PATH
        if not mitre_file.exists():
            return []

        documents = []
        with open(mitre_file, "r", encoding="utf-8") as f:
            records = json.load(f)

        for rec in records:
            tid = rec.get("technique_id", "T0000")
            name = rec.get("technique_name", "Unknown")
            tactic = rec.get("tactic", "Unknown")
            desc = rec.get("description", "")

            content = (
                f"MITRE ATT&CK Technique: {tid} - {name}\n"
                f"Tactic: {tactic}\n"
                f"Description: {desc}"
            )

            documents.append(
                Document(
                    id=f"MITRE-{tid}",
                    title=f"MITRE {tid}: {name}",
                    content=content,
                    source_type="mitre_technique",
                    metadata={
                        "technique_id": tid,
                        "technique_name": name,
                        "tactic": tactic,
                    },
                )
            )
        return documents

    def load_synthetic_threat_intel(
        self,
        records: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Document]:
        """Convert synthetic threat intelligence database into Document objects."""
        raw_records = records if records is not None else list_all_threat_intel()
        documents = []

        for item in raw_records:
            indicator = item.get("indicator", "UNKNOWN")
            itype = item.get("indicator_type", "unknown")
            rep = item.get("reputation", "unknown")
            actor = item.get("threat_actor", "Unknown")
            malware = item.get("malware_family", "None")
            desc = item.get("description", "")
            tags = ", ".join(item.get("tags", []))
            mitre_list = ", ".join(item.get("mitre_techniques", []))

            content = (
                f"Threat Intelligence Indicator: {indicator} ({itype.upper()})\n"
                f"Reputation: {rep.upper()} | Threat Actor: {actor} | Malware: {malware}\n"
                f"MITRE Techniques: {mitre_list if mitre_list else 'None'}\n"
                f"Tags: {tags}\n"
                f"Description: {desc}"
            )

            doc_id = f"TI-{indicator.replace(':', '_').replace('/', '_')}"
            documents.append(
                Document(
                    id=doc_id,
                    title=f"Threat Intel: {indicator} ({malware})",
                    content=content,
                    source_type="threat_intel_report",
                    metadata={
                        "indicator": indicator,
                        "indicator_type": itype,
                        "reputation": rep,
                        "threat_actor": actor,
                        "malware_family": malware,
                    },
                )
            )
        return documents

    def chunk_document(self, doc: Document) -> List[DocumentChunk]:
        """Split a Document into overlapping DocumentChunks."""
        text = doc.content.strip()
        if len(text) <= self.chunk_size:
            return [
                DocumentChunk(
                    chunk_id=f"{doc.id}-0",
                    document_id=doc.id,
                    title=doc.title,
                    content=text,
                    metadata=dict(doc.metadata),
                )
            ]

        chunks = []
        start = 0
        step = self.chunk_size - self.chunk_overlap
        chunk_idx = 0

        while start < len(text):
            end = min(start + self.chunk_size, len(text))
            chunk_text = text[start:end].strip()
            if chunk_text:
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"{doc.id}-{chunk_idx}",
                        document_id=doc.id,
                        title=doc.title,
                        content=chunk_text,
                        metadata=dict(doc.metadata),
                    )
                )
                chunk_idx += 1
            if end >= len(text):
                break
            start += step

        return chunks

    def ingest_all(
        self,
        mitre_path: Optional[Path] = None,
        threat_intel_records: Optional[List[Dict[str, Any]]] = None,
    ) -> List[DocumentChunk]:
        """Ingest all knowledge sources and return full chunked inventory."""
        docs = []
        docs.extend(self.load_mitre_reference(mitre_path))
        docs.extend(self.load_synthetic_threat_intel(threat_intel_records))

        all_chunks = []
        for doc in docs:
            all_chunks.extend(self.chunk_document(doc))
        return all_chunks
