"""
Read-only loader/sampler for corpus profiles mined by scripts/mine_corpus.py.

A corpus profile (kinetix/intelligence/corpus_profiles/<table>.json) only ever
contains "freeform" fields as real sampleable values -- user agents, URLs,
ports, protocols, result codes, and similar format-carrying-but-non-identifying
fields. "Identifier" fields (IPs, hostnames, usernames, emails, GUIDs, ...) are
never stored with real values by the miner, so CorpusProfile has no way to
surface entity data from a source corpus even by accident; those placeholders
keep using VariableManager's existing static pools.

This module is intentionally decoupled from VariableManager: it can be loaded
and queried independently (e.g. by tests, or a future noise generator) without
constructing a full simulation context.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import random

DEFAULT_PROFILE_DIR = Path(__file__).parent / "corpus_profiles"


class CorpusProfile:
    """Weighted sampler over mined field-value profiles, keyed by table+field."""

    def __init__(self, tables: Dict[str, Dict[str, Any]]):
        self._tables = tables

    @classmethod
    def load(cls, directory: Optional[Path] = None) -> "CorpusProfile":
        directory = Path(directory) if directory else DEFAULT_PROFILE_DIR
        tables: Dict[str, Dict[str, Any]] = {}
        if directory.is_dir():
            for path in sorted(directory.glob("*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                table = data.get("table") or path.stem
                tables[table] = data
        return cls(tables)

    @classmethod
    def empty(cls) -> "CorpusProfile":
        return cls({})

    def tables(self) -> List[str]:
        return list(self._tables.keys())

    def fields(self, table: str) -> List[str]:
        return list(self._tables.get(table, {}).get("fields", {}).keys())

    def _field_entry(self, table: str, field: str) -> Optional[Dict[str, Any]]:
        entry = self._tables.get(table, {}).get("fields", {}).get(field)
        if not entry or entry.get("kind") != "freeform" or not entry.get("values"):
            return None
        return entry

    def has(self, table: str, field: str) -> bool:
        return self._field_entry(table, field) is not None

    def sample(self, table: str, field: str, default: Optional[str] = None) -> Optional[str]:
        entry = self._field_entry(table, field)
        if entry is None:
            return default
        values = entry["values"]
        weights = [row.get("weight") or 1.0 for row in values]
        row = random.choices(values, weights=weights, k=1)[0]
        return row.get("value", default)

    def sample_first(self, pairs: Sequence[Tuple[str, str]], default: Optional[str] = None) -> Optional[str]:
        """Try each (table, field) candidate in order; return the first hit."""
        for table, field in pairs:
            if self.has(table, field):
                return self.sample(table, field, default)
        return default


@lru_cache(maxsize=None)
def _cached_load(directory_key: str) -> CorpusProfile:
    return CorpusProfile.load(Path(directory_key) if directory_key else None)


def get_profile(directory: Optional[Path] = None) -> CorpusProfile:
    """Process-wide cached loader.

    VariableManager is constructed frequently (once per simulation loop
    iteration and in nearly every test); caching by resolved directory avoids
    re-reading and re-parsing profile JSON files from disk each time.
    """
    key = str(Path(directory)) if directory else ""
    return _cached_load(key)
