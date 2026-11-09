"""Loader and helpers for the bundled ATT&CK technique reference."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, List

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "attack_techniques.json")


@lru_cache(maxsize=1)
def techniques() -> Dict[str, Dict]:
    with open(_DATA, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {t["id"]: t for t in raw["techniques"]}


def describe(technique_id: str) -> Dict:
    return techniques().get(technique_id, {"id": technique_id, "name": "unknown"})


def tactics_covered(technique_ids: List[str]) -> List[str]:
    out = []
    for tid in technique_ids:
        tactic = describe(tid).get("tactic")
        if tactic and tactic not in out:
            out.append(tactic)
    return out
