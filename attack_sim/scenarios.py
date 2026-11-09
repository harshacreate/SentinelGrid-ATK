"""Synthetic cloud-audit event generation.

This module produces *fake* log events that look like a simplified cloud
audit trail (think CloudTrail / Azure Activity log). Nothing here touches a
real system, network, or account. Each scenario emits a mix of benign
background activity and a labelled attack sequence so that detections can be
scored against ground truth.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Optional


@dataclass
class Event:
    """A single normalized audit event."""

    timestamp: datetime
    actor: str
    source_ip: str
    action: str
    resource: str
    outcome: str  # "success" | "failure"
    # Ground-truth labels used only for scoring, never by the detections.
    is_attack: bool = False
    technique: Optional[str] = None  # ATT&CK id, when is_attack is True
    meta: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


_BENIGN_USERS = ["alice", "bob", "carol", "service-ci", "service-backup"]
_BENIGN_IPS = ["10.0.0.11", "10.0.0.12", "10.0.0.40", "203.0.113.9"]
_BENIGN_ACTIONS = [
    ("GetObject", "storage/reports"),
    ("PutObject", "storage/reports"),
    ("DescribeInstances", "compute/fleet"),
    ("AssumeRole", "iam/ci-role"),
    ("ListBuckets", "storage/"),
]


def _rand_ip(public: bool = True) -> str:
    if public:
        return "198.51.100.%d" % random.randint(2, 254)
    return random.choice(_BENIGN_IPS)


def background_noise(start: datetime, count: int) -> List[Event]:
    """Routine, benign activity spread over time."""
    events: List[Event] = []
    t = start
    for _ in range(count):
        t += timedelta(seconds=random.randint(5, 90))
        action, resource = random.choice(_BENIGN_ACTIONS)
        events.append(
            Event(
                timestamp=t,
                actor=random.choice(_BENIGN_USERS),
                source_ip=_rand_ip(public=False),
                action=action,
                resource=resource,
                outcome="success",
            )
        )
    return events


# --- Attack scenarios -------------------------------------------------------
# Each returns (events, technique_id). Events carry ground-truth labels.


def scenario_password_guessing(start: datetime) -> List[Event]:
    """T1110.001 - many failed logins for one account from one IP."""
    attacker_ip = _rand_ip()
    victim = "alice"
    events: List[Event] = []
    t = start
    for i in range(25):
        t += timedelta(seconds=random.randint(1, 4))
        events.append(
            Event(
                timestamp=t,
                actor=victim,
                source_ip=attacker_ip,
                action="ConsoleLogin",
                resource="iam/console",
                outcome="failure",
                is_attack=True,
                technique="T1110.001",
            )
        )
    # Eventual success - the account is compromised.
    t += timedelta(seconds=2)
    events.append(
        Event(
            timestamp=t,
            actor=victim,
            source_ip=attacker_ip,
            action="ConsoleLogin",
            resource="iam/console",
            outcome="success",
            is_attack=True,
            technique="T1110.001",
        )
    )
    return events


def scenario_impossible_travel(start: datetime) -> List[Event]:
    """T1078 - valid account used from two far-apart IPs in a short window."""
    victim = "bob"
    events = [
        Event(
            timestamp=start,
            actor=victim,
            source_ip="10.0.0.12",
            action="ConsoleLogin",
            resource="iam/console",
            outcome="success",
            is_attack=False,  # the first, legitimate login
        ),
        Event(
            timestamp=start + timedelta(minutes=3),
            actor=victim,
            source_ip="185.220.101.5",  # unexpected foreign address
            action="ConsoleLogin",
            resource="iam/console",
            outcome="success",
            is_attack=True,
            technique="T1078",
            meta={"geo": "unexpected"},
        ),
    ]
    return events


def scenario_bucket_enumeration(start: datetime) -> List[Event]:
    """T1619 + T1530 - rapid object discovery then bulk download."""
    attacker_ip = _rand_ip()
    actor = "service-backup"  # a stolen service identity
    events: List[Event] = []
    t = start
    for i in range(40):
        t += timedelta(milliseconds=random.randint(100, 400))
        events.append(
            Event(
                timestamp=t,
                actor=actor,
                source_ip=attacker_ip,
                action="ListObjects" if i < 10 else "GetObject",
                resource="storage/customer-pii",
                outcome="success",
                is_attack=True,
                technique="T1619" if i < 10 else "T1530",
            )
        )
    return events


def scenario_new_access_key(start: datetime) -> List[Event]:
    """T1098 - attacker mints a new long-lived access key for persistence."""
    return [
        Event(
            timestamp=start,
            actor="carol",
            source_ip=_rand_ip(),
            action="CreateAccessKey",
            resource="iam/user/carol",
            outcome="success",
            is_attack=True,
            technique="T1098",
        )
    ]


def scenario_disable_logging(start: datetime) -> List[Event]:
    """T1562.008 - audit trail switched off to blind defenders."""
    return [
        Event(
            timestamp=start,
            actor="service-ci",
            source_ip=_rand_ip(),
            action="StopLogging",
            resource="audit/trail-main",
            outcome="success",
            is_attack=True,
            technique="T1562.008",
        )
    ]


SCENARIOS = {
    "password_guessing": scenario_password_guessing,
    "impossible_travel": scenario_impossible_travel,
    "bucket_enumeration": scenario_bucket_enumeration,
    "new_access_key": scenario_new_access_key,
    "disable_logging": scenario_disable_logging,
}


def build_timeline(
    scenario_names: Optional[List[str]] = None,
    noise_events: int = 120,
    seed: Optional[int] = None,
) -> List[Event]:
    """Interleave benign noise with one or more attack scenarios, time-sorted."""
    if seed is not None:
        random.seed(seed)
    names = scenario_names if scenario_names is not None else list(SCENARIOS)
    base = datetime(2025, 1, 1, 9, 0, 0)

    events = background_noise(base, noise_events)
    offset = 1
    for name in names:
        start = base + timedelta(minutes=10 * offset)
        events.extend(SCENARIOS[name](start))
        offset += 1

    events.sort(key=lambda e: e.timestamp)
    return events


def iter_scenarios() -> Iterator[str]:
    return iter(SCENARIOS)
