"""audit.py — one command, one report: what will this agent-security benchmark actually measure?

Runs the whole self-audit against the installed SDK and prints a single verdict:
  1. Reachability   — which predicates can fire AND survive each guardrail class.
  2. Faithfulness   — which predicates fire on benign, user-authorized actions (false positives).
  3. Search         — the whole multi-step recipe space, screened against every wall.
  4. Utility        — what each guardrail costs in broken benign work, scored with the SDK's own
                      score_defense() formula: the two-axis scorer the benchmark already shipped.
  5. The verdict    — the predicate(s) that are BOTH reachable under a strict guardrail AND
                      false-positive-prone: what the private board actually rewards.
  6. Repair         — apply the fixes and show what the patched scorer measures instead.

Run:  python audit.py
"""
from __future__ import annotations
from reachability import reachability_matrix, print_matrix, PREDICATES
from breach_faithfulness import audit as faithfulness_audit, print_report
from wall_ladder import DEFAULT_WALLS, print_search_report
from utility_probe import print_frontier
import repair

def main():
    print("=" * 78)
    print("AGENT-SCORER-AUDIT  —  what this benchmark actually measures")
    print("=" * 78)

    print("\n[1] REACHABILITY\n" + "-" * 40)
    print_matrix()

    print("\n[2] BREACH-FAITHFULNESS\n" + "-" * 40)
    print_report()

    print("\n[3] SEARCH\n" + "-" * 40)
    print_search_report()

    print("\n[4] SECURITY x UTILITY\n" + "-" * 40)
    print_frontier()

    print("\n[5] VERDICT\n" + "-" * 40)
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

    print("\n[6] REPAIR\n" + "-" * 40)
    repair.main()

if __name__ == "__main__":
    main()
