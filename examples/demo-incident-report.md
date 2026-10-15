# AegisIR Incident Report — IR-B0B8EDBBA6

Generated: 2026-10-14T21:50:25+00:00  
**Live-host triage observations are not a substitute for a full forensic acquisition.**

## Case
- Title: DEMO: Simulated Linux endpoint compromise
- Asset: lab-linux-example
- Analyst: demo-analyst
- Severity: high
- Status: open
- Current workflow phase: identification
- Synthetic demonstration: True

## Three critical IR questions
- **Active Malware**: review_indicators (not proof of malware/compromise)
- **Suspicious Communications**: review_indicators (not proof of malware/compromise)
- **Persistence**: review_indicators (not proof of malware/compromise)

## Collection coverage
| Module | Status | Observations | Evidence SHA-256 |
|---|---|---:|---|
| users | ok | 2 | `246eb2c8b8b998f077d0f062b85a6332509138af530f71591dd3306840841902` |
| processes | ok | 1 | `afd91747c71a4684b98aac48227cb79d7ad893f18c24ddcbfd575de03564621c` |
| cron | ok | 1 | `7bf9107a3f316c7653050bfafb449c21f6f1137ad92f0cb98a6b05f20f6864b8` |
| ssh | ok | 1 | `43c2f1faa554a462c4a19bde9f2dcc269c317e28ee776b517764508073b19d96` |
| network | ok | 1 | `dfbfec7adf61feb02bd8bf82893e830a52ef8fa85c20300f49f241d7f216601a` |
| readiness | partial | 0 | `35067c5e59ca8024442d78a9ffd7809b0d65723216e50ae6fd4e5cf04193aa4f` |

## Findings
| ID | Severity | Rule | Decision | Action status |
|---|---|---|---|---|
| FD-97D8D00AAD | high | PRIVILEGED-SERVICE | pending | not_requested |
| FD-1C6AA2447D | high | TEMP-EXECUTABLE | pending | not_requested |
| FD-5787246401 | high | SUSPICIOUS-CRON | pending | not_requested |
| FD-83695F12C4 | info | ROOT-SSH-KEY-REVIEW | pending | not_requested |
| FD-024D7F02CD | info | LISTENING-PORT-REVIEW | pending | not_requested |
| FD-B6509CF152 | medium | READINESS-GAP | pending | not_requested |

### FD-97D8D00AAD — Service account belongs to privileged group
- Module: users; MITRE: T1098; Confidence: medium
- **Observed:** www-data groups: ['sudo']
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Compare to expected privileges; remove unauthorized group membership after owner approval.
- **Decision:** pending — 

### FD-1C6AA2447D — Process executing from writable temporary location
- Module: processes; MITRE: T1059; Confidence: medium
- **Observed:** PID 4111 user=1000 executable=/tmp/update-service cmd=/tmp/update-service
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Capture process/file details, check signed baseline and network connections; consider scoped termination after approval.
- **Decision:** pending — 

### FD-5787246401 — Cron persistence candidate
- Module: cron; MITRE: T1053.003; Confidence: medium
- **Observed:** /etc/cron.d/updates: */5 * * * * root /tmp/update-service
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Confirm schedule, execution log and script ownership; preserve then revert unauthorized scheduled task.
- **Decision:** pending — 

### FD-83695F12C4 — Root authorized SSH key present
- Module: ssh; MITRE: T1098.004; Confidence: low
- **Observed:** /root/.ssh/authorized_keys: SHA256:SYNTHETIC-NOT-A-REAL-KEY
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Compare fingerprint to authorized-key registry; revoke only confirmed unknown keys after confirming alternate administrator access.
- **Decision:** pending — 

### FD-024D7F02CD — Listening TCP port requires baseline review
- Module: network; MITRE: T1571; Confidence: low
- **Observed:** Listener 0.0.0.0:4444
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Map listening socket inode to owning process and validate service against host baseline; no automatic blocking.
- **Decision:** pending — 

### FD-B6509CF152 — Preparation data incomplete
- Module: readiness; MITRE: unmapped; Confidence: low
- **Observed:** Simulated NTP verification gap
- **Interpretation:** Review indicator; detection is heuristic and unconfirmed.
- **Recommended:** Confirm NTP, logging retention, collector permissions and asset owner.
- **Decision:** pending — 

## Workflow checklist
- [ ] preparation: asset_owner — 
- [ ] preparation: contact_plan — 
- [ ] preparation: logging_ntp — 
- [ ] preparation: legal_authority — 
- [ ] preparation: baseline_inventory — 
- [ ] identification: alert_validated — 
- [ ] identification: lead_assigned — 
- [ ] identification: attack_window — 
- [ ] identification: three_questions — 
- [ ] scope: affected_hosts — 
- [ ] scope: affected_accounts — 
- [ ] scope: network_scope — 
- [ ] scope: volatile_evidence — 
- [ ] scope: containment_decision — 
- [ ] eradication: root_cause — 
- [ ] eradication: persistence_removed — 
- [ ] eradication: credentials_rotated — 
- [ ] eradication: vulnerabilities_addressed — 
- [ ] recovery: restore_verified — 
- [ ] recovery: service_owner_signoff — 
- [ ] recovery: enhanced_monitoring — 
- [ ] recovery: recurrence_checks — 
- [ ] lessons: timeline_review — 
- [ ] lessons: evidence_review — 
- [ ] lessons: report_approved — 
- [ ] lessons: control_improvements — 

## Action attempts

## Case activity timeline
- 2026-10-14T21:50:22+00:00 — case_created: {"title": "DEMO: Simulated Linux endpoint compromise", "asset": "lab-linux-example", "synthetic": true}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-5D603182E3", "module": "users", "sha256": "246eb2c8b8b998f077d0f062b85a6332509138af530f71591dd3306840841902", "findings": 1}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-7853ED3E2C", "module": "processes", "sha256": "afd91747c71a4684b98aac48227cb79d7ad893f18c24ddcbfd575de03564621c", "findings": 1}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-3946676C61", "module": "cron", "sha256": "7bf9107a3f316c7653050bfafb449c21f6f1137ad92f0cb98a6b05f20f6864b8", "findings": 1}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-80872E639C", "module": "ssh", "sha256": "43c2f1faa554a462c4a19bde9f2dcc269c317e28ee776b517764508073b19d96", "findings": 1}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-6096E167A3", "module": "network", "sha256": "dfbfec7adf61feb02bd8bf82893e830a52ef8fa85c20300f49f241d7f216601a", "findings": 1}
- 2026-10-14T21:50:22+00:00 — evidence_collected: {"scan_id": "SC-C9874FEBE7", "module": "readiness", "sha256": "35067c5e59ca8024442d78a9ffd7809b0d65723216e50ae6fd4e5cf04193aa4f", "findings": 1}

## Collection and evidentiary limitations
- Volatile state can change during collection; use external acquisition for evidentiary work.
- Sources may be unreadable or truncated. Verify coverage before concluding absence of activity.
- Local SHA-256 and chained audit hashes help detect changes but are not tamper-proof custody.
- No automatic threat attribution, business impact conclusion, or claim of full eradication.
