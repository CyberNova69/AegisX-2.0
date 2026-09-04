"""XML parser. Streams direct root-child records via ``iterparse``.

A source's first direct child under its root defines the record tag; further
children with other tags are left untouched rather than guessed as records.
Attributes are merged with child text and nested values remain structured, so no
information is silently dropped. Parse errors are surfaced to the pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional
from xml.etree import ElementTree as ET

from ..types import Format
from .base import BaseParser


class XmlParser(BaseParser):
    format = Format.XML
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        # At the end event of a direct child (depth 2) its complete subtree is
        # available. We immediately flatten and clear it, keeping memory bounded
        # by one record rather than the full XML document.
        context = ET.iterparse(path, events=("start", "end"))
        depth = 0
        row_tag: Optional[str] = None
        count = 0

        for event, elem in context:
            if event == "start":
                depth += 1
                if depth == 2 and row_tag is None:
                    row_tag = elem.tag
                continue

            if depth == 2 and row_tag == elem.tag:
                yield self._flatten(elem)
                elem.clear()
                count += 1
                if limit is not None and count >= limit:
                    return
            depth -= 1

    @staticmethod
    def _flatten(elem) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if elem.attrib:
            out.update({f"@{k}": v for k, v in elem.attrib.items()})
        for child in elem:
            tag = child.tag
            text = (child.text or "").strip()
            if len(child) == 0 and not child.attrib:
                out[tag] = text
            else:
                out[tag] = XmlParser._flatten(child)
        if not out:
            out["#text"] = (elem.text or "").strip()
        return out
