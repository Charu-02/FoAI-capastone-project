"""
Intelligent Network Intrusion Detection Agent
================================================
FoAI Case Study — Rule-Based Agent for Network Traffic Classification

Architecture (PEAS):
    Performance measure : correctly classifying attack vs. normal traffic,
                           minimizing false positives (blocking normal users)
    Environment          : a stream of network connection records
    Actuators             : {ALLOW, FLAG, BLOCK}
    Sensors               : per-connection stats (failed logins, distinct hosts
                             contacted, connection rate, bytes sent, destination port)

Pipeline: SENSE -> DECIDE -> ACT
    Sense  -> read the raw stats of a connection record
    Decide -> a rule-based (expert-system style) policy classifies the connection
    Act    -> apply the resulting action (ALLOW / FLAG / BLOCK)

No external dataset or ML library is used — every rule is hand-specified,
based on well-known signatures of common attack patterns (brute-force login,
network/port scanning, data exfiltration, flooding/DoS).

Run this file directly for a small interactive demo:
    python agent.py
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Tuple

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432}


# ---------------------------------------------------------------------------
# 1. SENSE — a single connection record as perceived by the agent
# ---------------------------------------------------------------------------

@dataclass
class ConnectionRecord:
    """One network connection's observable stats."""
    duration_seconds: float
    bytes_sent: int
    bytes_received: int
    failed_logins: int
    distinct_hosts_contacted: int   # how many different destination hosts in this window
    connections_per_second: float   # rate of new connections opened by this source
    dest_port: int

    def sense(self) -> dict:
        """Derive a couple of extra features the decision layer needs."""
        d = asdict(self)
        d["is_common_port"] = self.dest_port in COMMON_PORTS
        return d


# ---------------------------------------------------------------------------
# 2. DECIDE — rule-based classification (the "AI strategy" layer)
# ---------------------------------------------------------------------------

# Thresholds are heuristic, chosen to be clearly-attack vs. clearly-normal for
# a demonstrable small-scale project — see design_document.md, section 6,
# for an honest discussion of this and how it could be replaced with
# thresholds learned from real traffic data.
FAILED_LOGIN_THRESHOLD = 5
SCAN_HOST_THRESHOLD = 15
EXFIL_BYTES_THRESHOLD = 5_000_000   # 5 MB
FLOOD_RATE_THRESHOLD = 20            # connections/second


def decide(percept: dict) -> Tuple[str, str, str]:
    """
    Rules fire in order — first match wins, like a production system.
    Returns (action, attack_label, justification).

      R1: many failed logins in this window       -> BLOCK  (brute-force login attempt)
      R2: many distinct hosts contacted quickly    -> FLAG   (network / port scan)
      R3: large outbound transfer on an unusual port -> FLAG (possible data exfiltration)
      R4: very high connection rate                -> FLAG  (possible flood / DoS)
      R5: otherwise                                -> ALLOW (normal traffic)
    """
    if percept["failed_logins"] >= FAILED_LOGIN_THRESHOLD:
        return (
            "BLOCK",
            "Brute-force login attempt",
            f"R1 fired: {percept['failed_logins']} failed login attempts in this window "
            f"(threshold {FAILED_LOGIN_THRESHOLD}) — consistent with credential guessing.",
        )

    if percept["distinct_hosts_contacted"] >= SCAN_HOST_THRESHOLD:
        return (
            "FLAG",
            "Network / port scan",
            f"R2 fired: {percept['distinct_hosts_contacted']} distinct hosts contacted "
            f"(threshold {SCAN_HOST_THRESHOLD}) in a short window — consistent with a host "
            f"or port sweep rather than normal single-destination traffic.",
        )

    if percept["bytes_sent"] >= EXFIL_BYTES_THRESHOLD and not percept["is_common_port"]:
        return (
            "FLAG",
            "Possible data exfiltration",
            f"R3 fired: {percept['bytes_sent']:,} bytes sent to an uncommon port "
            f"({percept['dest_port']}) — large outbound transfers on non-standard "
            f"ports are a common exfiltration signature.",
        )

    if percept["connections_per_second"] >= FLOOD_RATE_THRESHOLD:
        return (
            "FLAG",
            "Possible flood / DoS",
            f"R4 fired: {percept['connections_per_second']:.1f} connections/second "
            f"(threshold {FLOOD_RATE_THRESHOLD}) — abnormally high connection rate.",
        )

    return (
        "ALLOW",
        "Normal traffic",
        "R5 fired (default): no rule matched — stats fall within normal ranges.",
    )


# ---------------------------------------------------------------------------
# 3. ACT — apply the decided action (in a real system: firewall call, alert, etc.)
# ---------------------------------------------------------------------------

def act(action: str, record: ConnectionRecord) -> dict:
    """In a real deployment this would call a firewall API, raise a SIEM
    alert, etc. Here, we just report what would happen."""
    effect = {
        "ALLOW": "Connection permitted, no alert raised.",
        "FLAG": "Connection permitted but logged for analyst review; alert raised.",
        "BLOCK": "Connection terminated immediately; source added to watch list.",
    }[action]
    return {"action": action, "effect": effect}


# ---------------------------------------------------------------------------
# The Agent — ties Sense -> Decide -> Act together
# ---------------------------------------------------------------------------

class IntrusionDetectionAgent:
    """A simple reflex / rule-based agent (per Russell & Norvig's taxonomy)."""

    def run(self, record: ConnectionRecord) -> dict:
        percept = record.sense()
        action, label, justification = decide(percept)
        outcome = act(action, record)

        return {
            "percept": percept,
            "action": action,
            "attack_label": label,
            "justification": justification,
            "outcome": outcome,
        }


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agent = IntrusionDetectionAgent()

    demo_record = ConnectionRecord(
        duration_seconds=2.4,
        bytes_sent=1200,
        bytes_received=8400,
        failed_logins=0,
        distinct_hosts_contacted=1,
        connections_per_second=0.5,
        dest_port=443,
    )

    print("Demo connection record:")
    for k, v in asdict(demo_record).items():
        print(f"  {k}: {v}")
    print()

    output = agent.run(demo_record)
    print("----- SENSE -----")
    print(output["percept"])
    print("\n----- DECIDE -----")
    print(f"Action        : {output['action']}")
    print(f"Attack label  : {output['attack_label']}")
    print(f"Justification : {output['justification']}")
    print("\n----- ACT -----")
    print(f"Effect        : {output['outcome']['effect']}")
