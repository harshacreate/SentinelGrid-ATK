"""SentinelGrid-ATK — interactive detection console (Flask).

Serves a polished dashboard plus JSON APIs that let you choose attack scenarios,
tune detection thresholds and background noise, run the detection engine, and
drill into each alert's evidence and response playbook. Everything runs on
synthetic events; no external systems are touched.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request, send_from_directory

from attack_sim import scenarios
from attack_sim.mitre_map import describe
from detections.engine import Engine
from detections.rules import (
    BruteForceLogin, BulkObjectAccess, ImpossibleTravel, SensitiveApiCall,
)

STATIC = os.path.join(os.path.dirname(__file__), "static")
app = Flask(__name__, static_folder=STATIC, static_url_path="/static")

# Concise response playbooks keyed by ATT&CK technique (full text in response/playbooks.md).
PLAYBOOKS = {
    "T1110.001": ("Password guessing", [
        "Contain — disable the targeted principal's password; revoke active sessions.",
        "Scope — list successful logins for that principal around the alert.",
        "Eradicate — rotate the password; require MFA re-enrollment.",
        "Harden — enable lockout / rate limiting; watchlist the source IP."]),
    "T1078": ("Valid accounts / impossible travel", [
        "Contain — revoke active sessions for the principal.",
        "Scope — pull every action from the anomalous IP since first login.",
        "Eradicate — rotate credentials and any keys created in the window.",
        "Harden — enforce conditional access (geo / device posture)."]),
    "T1530": ("Bulk cloud-storage access", [
        "Contain — attach a deny policy for the affected bucket.",
        "Scope — enumerate objects read; classify the data.",
        "Assess — if regulated data was read, open an incident.",
        "Harden — enable object-level logging + egress alerting."]),
    "T1619": ("Cloud storage discovery", [
        "Scope — review the enumeration source and session.",
        "Harden — alert on rapid ListObjects from one principal."]),
    "T1098": ("Account manipulation (new access key)", [
        "Verify — was the key creation expected (change ticket)?",
        "Contain — if not, deactivate then delete the key.",
        "Scope — review all calls made with the new key.",
        "Harden — alert on access-key creation for human identities."]),
    "T1562.008": ("Audit logging disabled", [
        "Contain — re-enable the trail immediately; lock the config.",
        "Scope — assume a blind spot during the gap; correlate telemetry.",
        "Escalate — logging tamper is a strong compromise indicator."]),
}


def _ruleset(bf_threshold, bulk_threshold, bf_window):
    return [
        BruteForceLogin(threshold=bf_threshold, window_seconds=bf_window),
        ImpossibleTravel(),
        BulkObjectAccess(threshold=bulk_threshold),
        SensitiveApiCall(),
    ]


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/api/catalogue")
def catalogue():
    return jsonify({
        "scenarios": [
            {"name": n, "label": n.replace("_", " ").title()} for n in scenarios.SCENARIOS
        ],
    })


@app.route("/api/run", methods=["POST"])
def run():
    data = request.get_json(force=True, silent=True) or {}
    chosen = data.get("scenarios") or list(scenarios.SCENARIOS)
    noise = int(data.get("noise", 120))
    bf_threshold = int(data.get("bf_threshold", 10))
    bulk_threshold = int(data.get("bulk_threshold", 20))
    bf_window = int(data.get("bf_window", 120))
    seed = int(data.get("seed", 7))

    events = scenarios.build_timeline(chosen, noise_events=noise, seed=seed)
    engine = Engine(_ruleset(bf_threshold, bulk_threshold, bf_window))
    alerts = engine.run(events)

    # ground truth: which techniques are actually present
    present = sorted({e.technique for e in events if e.is_attack and e.technique})
    detected = sorted({a.technique for a in alerts if a.technique in present})
    false_alerts = [a for a in alerts if a.technique not in present]

    alert_rows = []
    for a in sorted(alerts, key=lambda x: x.timestamp):
        tech = describe(a.technique)
        pb = PLAYBOOKS.get(a.technique)
        alert_rows.append({
            "time": a.timestamp.strftime("%H:%M:%S"),
            "rule": a.rule, "technique": a.technique,
            "technique_name": tech.get("name", a.technique),
            "tactic": tech.get("tactic", ""),
            "severity": a.severity, "actor": a.actor, "source_ip": a.source_ip,
            "detail": a.detail,
            "is_true": a.technique in present,
            "playbook_title": pb[0] if pb else "",
            "playbook": pb[1] if pb else [],
        })

    benign = sum(1 for e in events if not e.is_attack)
    attack_ev = sum(1 for e in events if e.is_attack)
    return jsonify({
        "metrics": {
            "scenarios": len(chosen),
            "techniques_present": len(present),
            "techniques_detected": len(detected),
            "coverage": round(len(detected) / len(present), 3) if present else 0.0,
            "alerts": len(alerts),
            "false_alerts": len(false_alerts),
            "events_total": len(events),
            "events_benign": benign, "events_attack": attack_ev,
        },
        "present": [{"id": t, "name": describe(t).get("name", t)} for t in present],
        "alerts": alert_rows,
    })


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
