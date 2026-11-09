# SentinelGrid-ATK — Multi-Scenario Cloud Attack Detection & Response Lab

## Run with Docker

```bash
docker compose up --build -d      # then open http://localhost:8091
docker compose down               # stop
```

This repository is standalone; the commands below build and run this project on its own.

A small, self-contained lab for writing cloud-attack **detections** and
**response playbooks**, then measuring how well they work. It generates a
synthetic cloud audit trail (benign activity plus labelled attack sequences),
runs a detection engine over it, and scores the results against ground truth
across many random seeds: **synthetic-scenario coverage**, false alerts, and
alert latency.

Everything runs locally against **synthetic events** — no real accounts, no
network access, nothing to authorize. The attack sequences are modelled on
public [MITRE ATT&CK](https://attack.mitre.org/) techniques so the detections
map to a shared vocabulary.

> **What the numbers mean (and don't).** "Synthetic-scenario coverage" is the
> fraction of the lab's *generated* attack scenarios that the detections catch.
> It is a measure of the rules against this synthetic scenario family — **not**
> of real-world detection performance on production cloud logs or on attacks the
> generator doesn't model. Treat it as a regression/so-far-so-good signal for
> your rules, not as a security assurance.

## Why this exists

Detection engineering is usually judged by anecdotes ("we caught that one
time"). This lab makes it measurable: every detection is scored against a
labelled scenario, so you can see what you catch, what you miss, and how noisy
a rule is before it ever touches production.

## Techniques covered

| ATT&CK | Technique | Detection |
|--------|-----------|-----------|
| T1110.001 | Password guessing | `brute_force_login` |
| T1078 | Valid accounts (impossible travel) | `impossible_travel` |
| T1530 / T1619 | Cloud storage collection / discovery | `bulk_object_access` |
| T1098 | Account manipulation (new access key) | `sensitive_api_call` |
| T1562.008 | Impair defenses (disable logging) | `sensitive_api_call` |

## Layout

```
attack_sim/     synthetic audit-event generators + ATT&CK reference
detections/     the detection engine and rules
harness/        scoring: coverage, false alerts, latency
response/        response playbooks (one per detection)
tests/          unit tests for every rule
data/           bundled ATT&CK technique reference
docker-compose.yml   optional sealed OpenSearch lab (not required)
```

## Quick start

```bash
make setup          # installs pytest (the lab itself is stdlib-only)
make test           # run the unit tests
make eval           # run the scored evaluation report (over 20 seeds)
make eval-json      # same, as JSON
```

The evaluation runs over many random seeds (`--seeds`, default 20) and reports
the mean and worst-case synthetic-scenario coverage, so one lucky timeline can't
flatter the result. Example report:

```
Synthetic-scenario coverage : mean 100%  (worst seed 100%)
False alerts                : 0.00 per run  (0 total over 20 runs)
Mean alert latency          : ... s
```

## How scoring works

1. `attack_sim/scenarios.py` builds a time-ordered event stream: background
   noise plus one or more attack scenarios. Attack events carry hidden
   ground-truth labels (`is_attack`, `technique`) that the detections never see.
2. `detections/` runs stateful rules over the stream and emits alerts.
3. `harness/evaluate.py` compares alerts to the labels:
   - a **true alert** matches a technique actually present in the run,
   - a **false alert** matches none,
   - **latency** is the time from the first attack event to the first true alert.

## Extending it

- **New technique:** add it to `data/attack_techniques.json`, write a generator
  in `attack_sim/scenarios.py`, add it to `SCENARIOS`.
- **New detection:** add a rule class in `detections/rules.py` (the engine calls
  each rule once per event, in time order, so windowed state is easy), register
  it in `default_ruleset()`, and add a test.
- **Tune for noise:** lower a rule's threshold and watch `false_alerts_total`
  climb — the harness makes the precision/recall trade-off visible.

## Optional sealed lab

`docker compose up -d` starts a single-node OpenSearch + Dashboards stack on an
`internal: true` network (no internet egress, dashboards bound to `127.0.0.1`).
Use it if you want to ship the synthetic events into a SIEM-like store and build
queries. It is entirely optional; the detections and scoring do not need it.

## Scope & safety

This project only ever operates on data it generates itself. There is no
scanning, no exploitation, and no interaction with third-party systems.
