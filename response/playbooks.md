# Response playbooks

Each playbook maps a detection to containment and recovery steps. They are
written for a cloud environment (AWS/Azure/GCP terminology is generalized).

---

## PB-01 — Password guessing against an identity (T1110.001)

**Trigger:** `brute_force_login`

1. **Contain** — Disable the targeted principal's console password and force a
   session revocation (invalidate active tokens).
2. **Scope** — List all successful logins for that principal in the 24h around
   the alert; flag any from the attacker source IP.
3. **Eradicate** — Rotate the password; require MFA re-enrollment.
4. **Recover** — Re-enable the account only after MFA is confirmed.
5. **Harden** — Enable account lockout / rate limiting at the IdP; add the
   source IP range to a watchlist.

## PB-02 — Anomalous valid-account use / impossible travel (T1078)

**Trigger:** `impossible_travel`

1. **Contain** — Revoke active sessions for the principal.
2. **Scope** — Pull every action taken from the anomalous IP since first login.
3. **Eradicate** — Rotate credentials and any access keys created in the window.
4. **Harden** — Enforce conditional access (geo / device posture).

## PB-03 — Bulk storage access / data staging (T1530, T1619)

**Trigger:** `bulk_object_access`

1. **Contain** — Attach a deny policy to the principal for the affected bucket.
2. **Scope** — Enumerate objects read; determine data classification.
3. **Assess** — If PII/regulated data was read, open an incident with legal.
4. **Harden** — Enable object-level logging and egress alerting on the bucket.

## PB-04 — New access key created (T1098)

**Trigger:** `sensitive_api_call` (CreateAccessKey)

1. **Verify** — Confirm the key creation was expected (change ticket?).
2. **Contain** — If not, deactivate then delete the key.
3. **Scope** — Review all calls made with the new key.
4. **Harden** — Alert on access-key creation for human identities by default.

## PB-05 — Audit logging disabled (T1562.008)

**Trigger:** `sensitive_api_call` (StopLogging) — treat as **critical**

1. **Contain** — Re-enable the trail immediately; lock the config with SCP/policy.
2. **Scope** — Assume blind spot during the gap; correlate with other telemetry.
3. **Escalate** — Logging tamper is a strong compromise indicator; invoke IR.
