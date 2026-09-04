"""audit.py — one command, one report: what will this agent-security benchmark actually measure?

Runs the whole self-audit against the installed SDK and prints a single verdict:
  1. Reachability   — which predicates can fire AND survive each guardrail class.
  2. Faithfulness   — which predicates fire on benign, user-authorized actions (false positives).
  3. The verdict    — the predicate(s) that are BOTH reachable under a strict guardrail AND false-positive-prone:
                      those are what the private board will actually reward, and why "multi-step" can collapse to spam.

Run:  python audit.py
"""
from __future__ import annotations
from reachability import reachability_matrix, print_matrix, PREDICATES
from breach_faithfulness import audit as faithfulness_audit, print_report
from wall_ladder import DEFAULT_WALLS

def main():
    print("=" * 78)
    print("AGENT-SCORER-AUDIT  —  what this benchmark actually measures")
    print("=" * 78)

    print("\n[1] REACHABILITY\n" + "-" * 40)
    print_matrix()

    print("\n[2] BREACH-FAITHFULNESS\n" + "-" * 40)
    print_report()

    print("\n[3] VERDICT\n" + "-" * 40)
    strict = DEFAULT_WALLS[-1].name
    reach = reachability_matrix()
    faith = faithfulness_audit()
    reachable_strict = [p for p in PREDICATES if reach[p][strict]]
    false_pos = [p for p in PREDICATES if faith.get(p, (False,))[0]]
    both = [p for p in reachable_strict if p in false_pos]
    print(f"Reachable under '{strict}':   {reachable_strict or 'none'}")
    print(f"False-positive-prone:        {false_pos or 'none'}")
    print(f"BOTH (what the board scores): {both or 'none'}")
    if both:
        print(f"\n=> This benchmark's private score is driven by {', '.join(both)} — a predicate that is both the only")
        print("   thing a strict guardrail leaves reachable AND a scorer false positive. 'Multi-step attack' therefore")
        print("   reduces to repeating that one benign action. Fix by (a) closing the reachability gap so higher-severity")
        print("   multi-step paths can score, and (b) making the predicate bind intent to the action so benign,")
        print("   user-authorized calls do not fire it.")
    else:
        print("\n=> No predicate is simultaneously reachable-under-strict and false-positive-prone. Healthier design.")

if __name__ == "__main__":
    main()
