# SentinelGrid-ATK — Project Overview

**Cloud Attack Detection & Response Console**
Project overview

## Project summary

SentinelGrid-ATK is an interactive lab for writing cloud-attack detections and
measuring how well they work. It generates a synthetic cloud audit trail (benign
activity plus labelled attack sequences), runs a detection engine over it, and
scores the results against ground truth. Attack sequences are modelled on public
MITRE ATT&CK techniques. Everything runs on synthetic events — no real accounts
or networks are touched.

## Main features

- **Detection console (web UI):** choose attack scenarios, tune the detection
  thresholds and background-noise level, and run the engine live.
- **Scored results:** synthetic-scenario coverage, alert counts, false alerts and
  event totals update on every run.
- **Alert drill-down:** click any alert to see its evidence and the matching
  response playbook (contain → scope → eradicate → harden).
- **ATT&CK mapping:** each alert is tagged with its technique id and tactic.
- **Tunable rules:** brute-force and bulk-access thresholds are sliders, so you
  can watch the precision/recall trade-off directly.

## Run with Docker

```sh
docker compose up --build -d      # then open http://localhost:8091
docker compose ps
docker compose down
```

The dashboard binds to `127.0.0.1` only and runs as a non-root user with a
read-only root filesystem and dropped Linux capabilities.

## What the numbers mean

"Coverage" is the share of the lab's *generated* scenarios that the detections
catch — a signal about the rules against this synthetic family, **not** a measure
of real-world detection performance on production cloud logs.
