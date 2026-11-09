"""A tiny stateful detection engine.

Rules are callables that consume events one at a time (in time order) and may
emit zero or more Alerts. Each rule keeps its own state, which makes it easy to
express windowed / stateful logic (e.g. "N failures within M seconds") without a
full streaming framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Protocol

from attack_sim.scenarios import Event


@dataclass
class Alert:
    rule: str
    technique: str
    timestamp: datetime          # when the alert fired
    first_seen: datetime         # first event in the triggering window
    actor: str
    source_ip: str
    detail: str
    severity: str = "medium"


class Rule(Protocol):
    name: str
    technique: str

    def __call__(self, event: Event) -> List[Alert]:
        ...


class Engine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def run(self, events: List[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        for event in events:
            for rule in self.rules:
                alerts.extend(rule(event))
        return alerts
