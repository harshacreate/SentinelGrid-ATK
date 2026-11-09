"""Concrete detection rules mapped to ATT&CK techniques.

Each rule is intentionally small and readable. The thresholds are deliberately
conservative so that the evaluation harness surfaces realistic trade-offs
between detection rate and false positives.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, List, Tuple

from attack_sim.scenarios import Event
from detections.engine import Alert


class BruteForceLogin:
    """T1110.001 - >= `threshold` failed ConsoleLogin for one actor within window."""

    name = "brute_force_login"
    technique = "T1110.001"

    def __init__(self, threshold: int = 10, window_seconds: int = 120):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._fails: Dict[str, Deque] = defaultdict(deque)
        self._fired: set = set()

    def __call__(self, event: Event) -> List[Alert]:
        if event.action != "ConsoleLogin" or event.outcome != "failure":
            return []
        key = event.actor
        q = self._fails[key]
        q.append(event.timestamp)
        while q and event.timestamp - q[0] > self.window:
            q.popleft()
        if len(q) >= self.threshold and key not in self._fired:
            self._fired.add(key)
            return [
                Alert(
                    rule=self.name,
                    technique=self.technique,
                    timestamp=event.timestamp,
                    first_seen=q[0],
                    actor=event.actor,
                    source_ip=event.source_ip,
                    detail="%d failed logins within %ss" % (len(q), int(self.window.total_seconds())),
                    severity="high",
                )
            ]
        return []


class ImpossibleTravel:
    """T1078 - same actor logs in successfully from two IPs within window."""

    name = "impossible_travel"
    technique = "T1078"

    def __init__(self, window_seconds: int = 600):
        self.window = timedelta(seconds=window_seconds)
        self._last: Dict[str, Tuple] = {}

    def __call__(self, event: Event) -> List[Alert]:
        if event.action != "ConsoleLogin" or event.outcome != "success":
            return []
        prev = self._last.get(event.actor)
        self._last[event.actor] = (event.timestamp, event.source_ip)
        if prev is None:
            return []
        prev_time, prev_ip = prev
        if prev_ip != event.source_ip and event.timestamp - prev_time <= self.window:
            return [
                Alert(
                    rule=self.name,
                    technique=self.technique,
                    timestamp=event.timestamp,
                    first_seen=prev_time,
                    actor=event.actor,
                    source_ip=event.source_ip,
                    detail="login from %s then %s within window" % (prev_ip, event.source_ip),
                    severity="high",
                )
            ]
        return []


class BulkObjectAccess:
    """T1530 - a single actor reads many storage objects very quickly."""

    name = "bulk_object_access"
    technique = "T1530"

    def __init__(self, threshold: int = 20, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._reads: Dict[str, Deque] = defaultdict(deque)
        self._fired: set = set()

    def __call__(self, event: Event) -> List[Alert]:
        if event.action != "GetObject":
            return []
        key = event.actor
        q = self._reads[key]
        q.append(event.timestamp)
        while q and event.timestamp - q[0] > self.window:
            q.popleft()
        if len(q) >= self.threshold and key not in self._fired:
            self._fired.add(key)
            return [
                Alert(
                    rule=self.name,
                    technique=self.technique,
                    timestamp=event.timestamp,
                    first_seen=q[0],
                    actor=event.actor,
                    source_ip=event.source_ip,
                    detail="%d object reads within %ss" % (len(q), int(self.window.total_seconds())),
                    severity="medium",
                )
            ]
        return []


class SensitiveApiCall:
    """Single-event rules for high-signal actions (T1098, T1562.008)."""

    name = "sensitive_api_call"
    technique = "T1098"  # reported per-event below

    _WATCH = {
        "CreateAccessKey": ("T1098", "new long-lived access key created", "high"),
        "StopLogging": ("T1562.008", "cloud audit logging disabled", "critical"),
    }

    def __call__(self, event: Event) -> List[Alert]:
        hit = self._WATCH.get(event.action)
        if not hit:
            return []
        technique, detail, severity = hit
        return [
            Alert(
                rule=self.name,
                technique=technique,
                timestamp=event.timestamp,
                first_seen=event.timestamp,
                actor=event.actor,
                source_ip=event.source_ip,
                detail=detail,
                severity=severity,
            )
        ]


def default_ruleset() -> List:
    return [
        BruteForceLogin(),
        ImpossibleTravel(),
        BulkObjectAccess(),
        SensitiveApiCall(),
    ]
