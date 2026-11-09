from datetime import datetime, timedelta

from attack_sim import scenarios
from detections.engine import Engine
from detections.rules import (
    BruteForceLogin,
    BulkObjectAccess,
    ImpossibleTravel,
    SensitiveApiCall,
    default_ruleset,
)


def _run(rules, events):
    return Engine(rules).run(events)


def test_brute_force_fires_once_above_threshold():
    events = scenarios.scenario_password_guessing(datetime(2025, 1, 1, 9, 0, 0))
    alerts = _run([BruteForceLogin(threshold=10, window_seconds=120)], events)
    assert len(alerts) == 1
    assert alerts[0].technique == "T1110.001"


def test_brute_force_silent_below_threshold():
    base = datetime(2025, 1, 1, 9, 0, 0)
    events = [
        scenarios.Event(base + timedelta(seconds=i), "alice", "198.51.100.3",
                        "ConsoleLogin", "iam/console", "failure")
        for i in range(5)
    ]
    assert _run([BruteForceLogin(threshold=10)], events) == []


def test_impossible_travel_detects_second_ip():
    events = scenarios.scenario_impossible_travel(datetime(2025, 1, 1, 9, 0, 0))
    alerts = _run([ImpossibleTravel()], events)
    assert len(alerts) == 1
    assert alerts[0].technique == "T1078"


def test_bulk_access_detects_mass_reads():
    events = scenarios.scenario_bucket_enumeration(datetime(2025, 1, 1, 9, 0, 0))
    alerts = _run([BulkObjectAccess(threshold=20, window_seconds=60)], events)
    assert any(a.technique == "T1530" for a in alerts)


def test_sensitive_calls_flag_key_and_logging():
    base = datetime(2025, 1, 1, 9, 0, 0)
    events = scenarios.scenario_new_access_key(base) + scenarios.scenario_disable_logging(base)
    alerts = _run([SensitiveApiCall()], events)
    techniques = {a.technique for a in alerts}
    assert "T1098" in techniques
    assert "T1562.008" in techniques


def test_full_ruleset_has_no_false_alert_on_pure_noise():
    events = scenarios.background_noise(datetime(2025, 1, 1, 9, 0, 0), 300)
    alerts = _run(default_ruleset(), events)
    assert alerts == []
