"""Evaluate detections against labelled scenarios.

Metrics reported per run:
  * coverage      - fraction of attack scenarios that produced >= 1 true alert
  * true_alerts   - alerts whose technique matches an attack present in the run
  * false_alerts  - alerts that do not correspond to any labelled attack
  * mean_latency  - seconds from first attack event to the first true alert
Run:
  python -m harness.evaluate
  python -m harness.evaluate --json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from typing import Dict, List, Optional

from attack_sim import scenarios
from attack_sim.mitre_map import describe, tactics_covered
from detections.engine import Alert, Engine
from detections.rules import default_ruleset


def _attack_windows(events: List[scenarios.Event]) -> Dict[str, Dict]:
    """Group labelled attack events by technique -> first/last timestamps."""
    windows: Dict[str, Dict] = {}
    for e in events:
        if not e.is_attack or not e.technique:
            continue
        w = windows.setdefault(e.technique, {"first": e.timestamp, "last": e.timestamp})
        w["first"] = min(w["first"], e.timestamp)
        w["last"] = max(w["last"], e.timestamp)
    return windows


def evaluate_scenario(name: str, seed: int = 7) -> Dict:
    events = scenarios.build_timeline([name], seed=seed)
    windows = _attack_windows(events)
    engine = Engine(default_ruleset())
    alerts: List[Alert] = engine.run(events)

    true_alerts: List[Alert] = []
    false_alerts: List[Alert] = []
    for a in alerts:
        if a.technique in windows:
            true_alerts.append(a)
        else:
            false_alerts.append(a)

    # Latency: first true alert relative to the first attack event of its technique.
    latencies: List[float] = []
    seen_tech = set()
    for a in sorted(true_alerts, key=lambda x: x.timestamp):
        if a.technique in seen_tech:
            continue
        seen_tech.add(a.technique)
        first = windows[a.technique]["first"]
        latencies.append((a.timestamp - first).total_seconds())

    detected = bool(true_alerts)
    return {
        "scenario": name,
        "techniques_present": sorted(windows),
        "techniques_detected": sorted(seen_tech),
        "detected": detected,
        "true_alerts": len(true_alerts),
        "false_alerts": len(false_alerts),
        "mean_latency_s": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "tactics": tactics_covered(sorted(windows)),
    }


def evaluate_all(seed: int = 7) -> Dict:
    per = [evaluate_scenario(name, seed=seed) for name in scenarios.iter_scenarios()]
    total = len(per)
    detected = sum(1 for r in per if r["detected"])
    false_total = sum(r["false_alerts"] for r in per)
    lats = [r["mean_latency_s"] for r in per if r["mean_latency_s"] is not None]
    return {
        "summary": {
            "scenarios": total,
            "scenarios_detected": detected,
            "coverage": round(detected / total, 3) if total else 0.0,
            "false_alerts_total": false_total,
            "mean_latency_s": round(sum(lats) / len(lats), 2) if lats else None,
        },
        "scenarios": per,
    }


def evaluate_over_seeds(base_seed: int = 7, n_seeds: int = 20) -> Dict:
    """Run the whole evaluation across many random seeds and aggregate.

    One seed only tells you about one generated timeline; averaging over many
    seeds (and reporting the worst case) is a far more honest summary of how the
    detections behave on this *synthetic* scenario family.
    """
    runs = [evaluate_all(seed=base_seed + i) for i in range(n_seeds)]
    coverages = [r["summary"]["coverage"] for r in runs]
    false_totals = [r["summary"]["false_alerts_total"] for r in runs]
    lats = [r["summary"]["mean_latency_s"] for r in runs if r["summary"]["mean_latency_s"] is not None]
    return {
        "base_seed": base_seed,
        "n_seeds": n_seeds,
        "synthetic_scenario_coverage_mean": round(sum(coverages) / len(coverages), 3),
        "synthetic_scenario_coverage_min": round(min(coverages), 3),
        "false_alerts_total": sum(false_totals),
        "false_alerts_per_run_mean": round(sum(false_totals) / len(false_totals), 3),
        "mean_latency_s": round(sum(lats) / len(lats), 2) if lats else None,
        "per_scenario_base_seed": runs[0]["scenarios"],
    }


def _print_report(agg: Dict) -> None:
    print("=" * 66)
    print("Cloud Attack Detection Lab - evaluation report")
    print("=" * 66)
    print("NOTE: all metrics are measured on GENERATED (synthetic) scenarios.")
    print("'Synthetic-scenario coverage' is the fraction of generated attack")
    print("scenarios detected; it is NOT a measure of performance on real cloud")
    print("logs or unseen attacks.")
    print("-" * 66)
    print("Seeds evaluated             : %d (%d..%d)" % (
        agg["n_seeds"], agg["base_seed"], agg["base_seed"] + agg["n_seeds"] - 1))
    print("Synthetic-scenario coverage : mean %.0f%%  (worst seed %.0f%%)" % (
        agg["synthetic_scenario_coverage_mean"] * 100,
        agg["synthetic_scenario_coverage_min"] * 100))
    print("False alerts                : %.2f per run  (%d total over %d runs)" % (
        agg["false_alerts_per_run_mean"], agg["false_alerts_total"], agg["n_seeds"]))
    print("Mean alert latency          : %s s" % agg["mean_latency_s"])
    print("-" * 66)
    print("Per-scenario breakdown (base seed %d):" % agg["base_seed"])
    print("  %-22s %-10s %-9s %-8s %s" % ("scenario", "detected", "true", "false", "latency"))
    for r in agg["per_scenario_base_seed"]:
        techs = ",".join(describe(t)["id"] for t in r["techniques_detected"]) or "-"
        print(
            "  %-22s %-10s %-9d %-8d %-8s %s"
            % (
                r["scenario"],
                "yes" if r["detected"] else "NO",
                r["true_alerts"],
                r["false_alerts"],
                str(r["mean_latency_s"]),
                techs,
            )
        )
    print("=" * 66)


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(description="Evaluate detections against labelled synthetic attack scenarios.")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--seed", type=int, default=7, help="base random seed")
    ap.add_argument("--seeds", type=int, default=20, help="number of seeds to evaluate over")
    args = ap.parse_args(argv)
    agg = evaluate_over_seeds(base_seed=args.seed, n_seeds=args.seeds)
    if args.json:
        print(json.dumps(agg, indent=2))
    else:
        _print_report(agg)


if __name__ == "__main__":
    main()
