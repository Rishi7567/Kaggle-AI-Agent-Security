# agent-scorer-audit

**A pre-launch self-audit for agent-security benchmarks.** Point it at your scoring predicates and guardrail and it tells
you — with no GPU and no leaderboard — *what your benchmark will actually measure*: which predicates can score, which
ones fire on benign user-authorized actions (false positives), and whether a "multi-step" task quietly collapses to a
single repeatable action.

Built from the *AI Agent Security — Multi-Step Tool Attacks* SDK, it reproduces that competition's outcome from first
principles: run `audit.py` and it derives, automatically, that the private board reduces to one predicate
(`CONFUSED_DEPUTY`) that is *both* the only thing a strict guardrail leaves reachable *and* a scorer false positive.

> The idea in one line: **a scoring predicate is only as good as its false-positive rate. If a benign, user-requested
> action can fire it, your benchmark measures your scorer, not the agent — and attackers will farm it. Run this before you launch.**

## What's here

| File | What it does |
|---|---|
| `audit.py` | **Start here.** One command → one report: reachability + faithfulness + the verdict. |
| `reachability.py` | The reachability *calculus*: a predicate is reachable under guardrail G iff some trace that fires it is allowed by G. Prints the predicate × guardrail-class matrix. |
| `breach_faithfulness.py` | The linter: builds a benign, user-authorized trace per predicate and flags any that fire (false positives). |
| `wall_ladder.py` | The shared engine: guardrail variants (`public-optimal`, `taint-only`, `taint+content`), a faithful mini-replayer, and an offline recipe search. Import it to test your own attack recipes. |
| `scoring_math.py` | Proves, with the real scorer components, why the unique-cell bonus is *per candidate* — so `k` separate sends (`6k`) beat one `k`-send candidate (`4k+2`). Explains why the winning engines used one send per candidate. |
| `utility_probe.py` | The dimension nobody measured: scores a guardrail's **cost**, not just its security — on the security × utility frontier — attacks blocked *and* benign user-workflows preserved. Shows the strict guardrail that best resists attacks also breaks legitimate agent work. `--plot` renders the scatter (`figures/security_utility.png`). |
| `experiments/` | Supporting evidence for the write-up's throughput study — the `CONFUSED_DEPUTY` engine we submitted + the private-score screenshot (single-send ~25 beats packing ~15). |
| `faithful_measure.py` | The one measurement rule that saves days: drive the packaged model server via `RemoteAgent`, not the agent class directly (which fires 0 tool calls). Prints guidance; runs a live check only where the GGUF models + a GPU exist. |
| `examples.ipynb` | Runs `audit.py` on the SDK and walks through reading the report. |
| `repair.py` | Applies the three fixes (structured authorization, elicitation scoring, full-argument content checks) and re-runs the audit against the patched scorer: the multi-step route reopens, the benign traces come back clean, and the single-send shortcut stops paying. |
| `leaderboard_stats.py` | The one online tool: pulls both leaderboards and reports whether the public board predicted the private one (needs the Kaggle CLI). |
| `test_wall_ladder.py` | 63 checks: the numbers this repo publishes, the general-benchmark path, and the edge cases (malformed evaluators, odd guardrails, empty and exploding spaces). No pytest needed. |
| `examples/tiny_benchmark.py` | The same machinery on an unrelated benchmark, to show the tooling is not shaped around one SDK. |
| `docs/method.md` | The full proofs behind the working note: Lemma 1 (taint window ⊇ predicate window), Lemma 2 (secret self-cancel), the guardrail-class definitions, the cell arithmetic, and the exact reproduction recipe. |

## Run it

```bash
# 1) point the tools at the competition SDK (folder containing `aicomp_sdk/`)
export AAS_SDK=/path/to/sdk            # defaults to ../sdk relative to this repo
# 2) full audit
python audit.py
# or a single view
python reachability.py
python breach_faithfulness.py
python wall_ladder.py                  # offline recipe search
```

Only `aicomp_sdk` (the competition SDK) is required for the audit; the GGUF models are needed **only** for the optional
live check in `faithful_measure.py`.

## What you'll see (abridged)

```
Reachability: can each predicate FIRE and SURVIVE?  (Y = reachable, . = dead)
                            public-optimal    taint-only(k=5)   taint+content(k=5)
EXFILTRATION(5)                     Y                Y                  .
UNTRUSTED_TO_ACTION(5)              .                .                  .
DESTRUCTIVE_WRITE(4)                .                Y                  .
CONFUSED_DEPUTY(3)                  Y                Y                  Y

[X] CONFUSED_DEPUTY  FALSE-POSITIVE-PRONE   (fires on "notify the team that the report is ready")
VERDICT: private score is driven by CONFUSED_DEPUTY — reachable-under-strict AND a false positive.
```

## Using it on *your* benchmark

Nothing here is welded to the competition it came from. A search is four things, and all four are
arguments rather than edits:

| You supply | Shape | Passed as |
|---|---|---|
| **Your scoring rules** | `evaluator(trace) -> [{"predicate", "severity"}, ...]` | `evaluator=` |
| **Your defense classes** | objects with `.name`, `.window`, `.gated`, `.decide(tool, args, ctx)` | `walls=` |
| **Your failure space** | `{axis name: values}` | `axes=` |
| **How a point becomes a trace** | `builder(combo) -> {"steps", "last_user"}` or `None` to skip | `builder=` |

```python
from wall_ladder import generate_recipes, search_report, print_search_report

recipes = generate_recipes(axes=MY_AXES, builder=my_build, max_fillers=None)
report  = search_report(recipes=recipes, walls=MY_WALLS,
                        evaluator=my_evaluator, weights=MY_WEIGHTS,
                        axes=MY_AXES, builder=my_build)
print_search_report(report)
```

`examples/tiny_benchmark.py` is a complete worked example on a coding-assistant benchmark that shares
no tools, predicates or guardrails with this competition — copy it and replace those four things.

**Things worth knowing before you extend it.**

- `.decide` may return a bool, a string (`"allow"` / `"deny"`), or an SDK `DecisionAction`. Anything
  unrecognised raises rather than silently denying, because a typo that blocks everything looks
  exactly like a working strict guardrail.
- A wall is only consulted about the tools in its `.gated` set. Declare it, or the guardrail is never
  asked and every wall will look identical.
- With a custom `builder`, `axes` **replaces** the default space; with the default builder it
  **overrides** individual axes. `effective_axes()` tells you which space you are about to search.
- Recipes that produce identical traces are deduplicated, so the reported total is the number of
  *distinct* traces screened, not the size of the cartesian product.
- The space is guarded at `MAX_SPACE` (200,000) combinations; raise it deliberately if you mean to.
- Always include a no-defense wall. A predicate that cannot fire even with nothing blocking it is a
  bug in your recipes, not a property of your guardrail.
- The competition SDK is imported lazily, so the module works with none of it installed as long as
  you bring your own evaluator and walls.

Run `python test_wall_ladder.py` after any change: 63 checks covering the published numbers, the
generality path, and the edge cases.

## Scope & responsible use
Everything here operates on a security *benchmark's* own predicate and guardrail definitions and synthetic fixtures. It
contains no exploit against any real email provider, website, filesystem, or deployed agent, and discloses no unrelated
vulnerability. It is a defensive, benchmark-design tool.
