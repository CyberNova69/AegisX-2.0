"""Plugin registry for dataset sources, processors, and exporters.

Provides a simple registration pattern so new dataset connectors can be
added without modifying core pipeline code.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Type


class Registry:
    """Generic plugin registry with name-based lookup."""

    def __init__(self, name: str = "registry"):
        self.name = name
        self._entries: Dict[str, Any] = {}

    def register(self, key: str, value: Any) -> None:
        """Register a plugin under a unique key."""
        if key in self._entries:
            raise ValueError(
                f"{self.name}: '{key}' is already registered "
                f"(current: {self._entries[key]}, new: {value})"
            )
        self._entries[key] = value

    def get(self, key: str) -> Optional[Any]:
        """Retrieve a registered plugin by key."""
        return self._entries.get(key)

    def get_or_raise(self, key: str) -> Any:
        """Retrieve a registered plugin, raising KeyError if not found."""
        if key not in self._entries:
            available = ", ".join(sorted(self._entries.keys()))
            raise KeyError(
                f"{self.name}: '{key}' not found. Available: [{available}]"
            )
        return self._entries[key]

    def keys(self) -> List[str]:
        """List all registered keys."""
        return sorted(self._entries.keys())

    def items(self) -> List[tuple]:
        """List all (key, value) pairs."""
        return sorted(self._entries.items())

    def __contains__(self, key: str) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"Registry(name='{self.name}', entries={self.keys()})"


# ---------------------------------------------------------------------------
# Global registries
# ---------------------------------------------------------------------------

# Registry of dataset source classes (key=DatasetSourceType.value)
source_registry = Registry("sources")

# Registry of label map loaders (key=source name)
label_map_registry = Registry("label_maps")

# Registry of enrichment plugins (key=enricher name)
enricher_registry = Registry("enrichers")


def register_source(key: str) -> Callable:
    """Decorator to register a dataset source class."""
    def decorator(cls: Type) -> Type:
        source_registry.register(key, cls)
        return cls
    return decorator


def register_enricher(key: str) -> Callable:
    """Decorator to register an enrichment plugin."""
    def decorator(cls: Type) -> Type:
        enricher_registry.register(key, cls)
        return cls
    return decorator
