# Design Document
## Intelligent Network Intrusion Detection Agent
### FoAI Case Study

---

## 1. Problem Statement

Network traffic is a continuous stream of connections, the overwhelming
majority of which are legitimate. A small fraction show statistical
signatures of common attacks: repeated failed logins (brute-forcing),
contacting many hosts in a short window (scanning), unusually large
outbound transfers to unfamiliar ports (exfiltration), or an abnormal
connection rate (flooding/DoS). This project builds an **agent** that
inspects each connection's stats and decides how to respond, rather than
treating all traffic identically.

---

## 2. PEAS Description

| Element | Description |
|---|---|
| **Performance measure** | Correctly classifying attack vs. normal traffic; minimizing false positives (blocking legitimate users) |
| **Environment** | A stream of network connection records, each with observable stats |
| **Actuators** | Three possible actions: `ALLOW`, `FLAG` (log + alert, but permit), `BLOCK` (terminate + watch-list) |
| **Sensors** | Per-connection stats: duration, bytes sent/received, failed login count, distinct hosts contacted, connection rate, destination port |

**Environment properties:**
- Partially observable — the agent sees only the stats of the current connection, not the attacker's true intent
- Deterministic — the same stats always produce the same decision
- Episodic — each connection is classified independently in the base version (no memory across connections)
- Static — a connection's stats don't change mid-classification
- Discrete — a finite set of actions and a finite (bucketed) feature space

**Agent type:** Simple reflex / rule-based agent (per Russell & Norvig's
taxonomy) — rules are hand-specified based on known attack signatures, not
learned from data.

---

## 3. Architecture — Sense → Decide → Act

```
              ┌───────────────────────────────────────────┐
              │              ENVIRONMENT                    │
              │        (network connection stream)           │
              └────────────────────┬──────────────────────┘
                                    │ connection record
                                    ▼
              ┌───────────────────────────────────────────┐
STAGE 1        │  SENSE                                       │
              │  read: duration, bytes sent/received,        │
              │  failed logins, distinct hosts, conn. rate,   │
              │  destination port                              │
              └────────────────────┬──────────────────────┘
                                    │ percept
                                    ▼
              ┌───────────────────────────────────────────┐
STAGE 2        │  DECIDE (rule-based policy)                  │
              │  R1: failed logins ≥ 5           → BLOCK      │
              │  R2: distinct hosts ≥ 15          → FLAG       │
              │  R3: bytes sent ≥ 5MB, odd port   → FLAG       │
              │  R4: connection rate ≥ 20/s       → FLAG       │
              │  R5: otherwise (default)          → ALLOW      │
              └────────────────────┬──────────────────────┘
                                    │ chosen action
                                    ▼
              ┌───────────────────────────────────────────┐
STAGE 3        │  ACT                                          │
              │  ALLOW → permit, no alert                     │
              │  FLAG  → permit, log + raise alert            │
              │  BLOCK → terminate, add source to watch list  │
              └────────────────────┬──────────────────────┘
                                    │
                                    ▼
                          action taken + justification
```

---

## 4. AI Strategy: Rule-Based Decision Making

The "AI strategy" here is a **rule-based (production system / expert-system
style) policy** — a classical AI paradigm. Rules fire in a fixed priority
order, first match wins:

| Rule | Condition | Attack signature | Action |
|---|---|---|---|
| R1 | failed logins ≥ 5 | Brute-force login attempt — repeated credential guessing against one service | `BLOCK` |
| R2 | distinct hosts contacted ≥ 15 | Network/port scan — probing many destinations quickly, not typical single-destination traffic | `FLAG` |
| R3 | bytes sent ≥ 5 MB **and** destination port is uncommon | Possible data exfiltration — large outbound transfer avoiding standard service ports | `FLAG` |
| R4 | connection rate ≥ 20/s | Possible flood / DoS — abnormally high rate of new connections from one source | `FLAG` |
| R5 | none of the above (default) | Normal traffic | `ALLOW` |

These are the same four broad attack categories referenced throughout
intrusion-detection literature (credential attacks, reconnaissance,
exfiltration, denial-of-service) — the rules are simplified, threshold-based
proxies for each, not full signatures a production IDS would use.

---

## 5. Honest Note on the Thresholds

The specific threshold values (5 failed logins, 15 hosts, 5 MB, 20
connections/second) are **heuristic choices** for a small-scale, defensible
demonstration — not values derived from a formal optimization or fitted to
real traffic data. This is intentional and worth stating plainly in the
viva rather than defending them as precise: in a production system, these
thresholds would typically be tuned against a labeled dataset (e.g.
NSL-KDD, CICIDS) to balance detection rate against false-positive rate, or
replaced entirely by a learned classifier. That trade-off — rule-based
transparency and zero training-data dependency vs. a learned model's
adaptability — is itself a legitimate design discussion point for the viva.

---

## 6. Small-Scale Analysis (see `analysis_output/`)

Five synthetic connection records were constructed to each exercise a
different rule:

| Sample | Failed logins | Hosts | Bytes sent | Rate/s | Port | Rule fired | Action |
|---|---|---|---|---|---|---|---|
| `normal_browsing` | 0 | 1 | 1.5 KB | 0.4 | 443 | R5 | ALLOW |
| `brute_force_ssh` | 12 | 1 | 900 B | 1.2 | 22 | R1 | BLOCK |
| `port_scan` | 0 | 42 | 300 B | 8.0 | 80 | R2 | FLAG |
| `data_exfiltration` | 0 | 1 | 8.5 MB | 0.1 | 4444 | R3 | FLAG |
| `dos_flood` | 0 | 1 | 200 B | 48.0 | 80 | R4 | FLAG |

All five samples matched their expected classification (100% agreement).
Full CSV output and a summary chart are generated by running
`python/analysis.py` (outputs land in `analysis_output/`).

---

## 7. Possible Extensions (future work / stretch goals)

- Replace hand-written thresholds with values learned from a labeled
  traffic dataset (turning this into a supervised learning agent)
- Add memory across connections from the same source (episodic → sequential
  agent), so repeated borderline behavior over time can also be flagged
- Track false-positive rate against a larger, more realistic synthetic
  traffic sample to quantify the rule set's precision/recall trade-off

---

## 8. AI-Assisted Development Disclosure

This solution was developed with AI assistance (Claude). The prompts used
to arrive at this design are recorded in `prompts_used.md`, as required by
the assignment.
