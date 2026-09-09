"""
Small-scale analysis for the FoAI case study.

Runs the IntrusionDetectionAgent over five synthetic connection records,
each deliberately constructed to exercise a different rule (R1-R5), then
reports the agent's classification, and produces a summary chart.

Run with:
    python analysis.py
"""

import csv
import os
from agent import ConnectionRecord, IntrusionDetectionAgent

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "analysis_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


SAMPLES = {
    "normal_browsing": ConnectionRecord(
        duration_seconds=3.1, bytes_sent=1500, bytes_received=42000,
        failed_logins=0, distinct_hosts_contacted=1,
        connections_per_second=0.4, dest_port=443,
    ),
    "brute_force_ssh": ConnectionRecord(
        duration_seconds=18.0, bytes_sent=900, bytes_received=600,
        failed_logins=12, distinct_hosts_contacted=1,
        connections_per_second=1.2, dest_port=22,
    ),
    "port_scan": ConnectionRecord(
        duration_seconds=4.5, bytes_sent=300, bytes_received=150,
        failed_logins=0, distinct_hosts_contacted=42,
        connections_per_second=8.0, dest_port=80,
    ),
    "data_exfiltration": ConnectionRecord(
        duration_seconds=95.0, bytes_sent=8_500_000, bytes_received=2000,
        failed_logins=0, distinct_hosts_contacted=1,
        connections_per_second=0.1, dest_port=4444,
    ),
    "dos_flood": ConnectionRecord(
        duration_seconds=1.0, bytes_sent=200, bytes_received=0,
        failed_logins=0, distinct_hosts_contacted=1,
        connections_per_second=48.0, dest_port=80,
    ),
}

EXPECTED = {
    "normal_browsing": "ALLOW",
    "brute_force_ssh": "BLOCK",
    "port_scan": "FLAG",
    "data_exfiltration": "FLAG",
    "dos_flood": "FLAG",
}


def main():
    agent = IntrusionDetectionAgent()
    rows = []

    print(f"{'Sample':<20}{'Action':<10}{'Expected':<10}{'Match':<8}{'Label':<28}")
    print("-" * 76)

    for name, record in SAMPLES.items():
        out = agent.run(record)
        match = out["action"] == EXPECTED[name]
        rows.append({
            "sample": name,
            "action": out["action"],
            "expected": EXPECTED[name],
            "match": match,
            "attack_label": out["attack_label"],
            "justification": out["justification"],
        })
        print(f"{name:<20}{out['action']:<10}{EXPECTED[name]:<10}{str(match):<8}{out['attack_label']:<28}")

    accuracy = sum(r["match"] for r in rows) / len(rows) * 100
    print(f"\nAgreement with expected labels: {accuracy:.0f}% ({sum(r['match'] for r in rows)}/{len(rows)})")

    csv_path = os.path.join(OUTPUT_DIR, "results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved detailed results -> {csv_path}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        names = [r["sample"] for r in rows]
        actions = [r["action"] for r in rows]
        colors = {"ALLOW": "#4fb6a8", "FLAG": "#e7a33e", "BLOCK": "#c25a4a"}
        bar_colors = [colors[a] for a in actions]

        fig, ax = plt.subplots(figsize=(8, 5))
        y_pos = range(len(names))
        ax.barh(y_pos, [1] * len(names), color=bar_colors)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(names)
        ax.set_xticks([])
        ax.set_title("Agent decision per traffic sample")
        for i, (name, action, label) in enumerate(zip(names, actions, [r["attack_label"] for r in rows])):
            ax.text(0.02, i, f"{action} — {label}", va="center", fontsize=9, color="#10161a")
        plt.tight_layout()
        chart_path = os.path.join(OUTPUT_DIR, "decisions_chart.png")
        plt.savefig(chart_path, dpi=150)
        print(f"Saved chart             -> {chart_path}")
    except ImportError:
        print("\n(matplotlib not installed — skipping chart generation. "
              "`pip install matplotlib` to enable it.)")


if __name__ == "__main__":
    main()
