# experiments/ — the engines we submitted, and the throughput study (evidence for write-up §6–§7)

This folder is **not** part of the audit toolkit; it is the empirical record behind the write-up. Everything here is
benchmark-internal (synthetic RFC-2606 `.invalid` recipients, the benchmark's placeholder marker) — not an exploit
against any real system.

## 1. Our actual competition selections (official result: 6.5 private, rank 352 / 4,251)

The two submissions we *selected* at the deadline — and the ones the write-up critiques in §7:

| File | Engine | Private | Note |
|---|---|---:|---|
| `selected_deputyfloor.py` | natural `CONFUSED_DEPUTY` floor (tuned for robustness across many walls) | **6.565** | our best-scoring pick; we over-engineered it for *robustness* instead of *throughput* — the §7 mistake |
| `selected_forced.py` | genuine multi-step (`UNTRUSTED_TO_ACTION`) engine | **3.330** | structurally dead on any taint wall (Lemma 1) — effort spent on the *advertised* target, not the *scored* one |

(Local copies are the near-final versions, `deputyfloor v4` / `forced v10`; the exact scored versions were `v3` / `v6`.
Same engines and approach — only `N`/cap tuning differs. The point is *what we built and picked*, not byte-exactness.)

## 2. Post-deadline throughput study (non-competitive — these score but do not affect standings)

After the deadline we built the engine we *should* have — a pure single-send `CONFUSED_DEPUTY` (`cdmax_engine.py`, each
candidate a distinct recipient, gate kept open). It has three modes so one file produced every row below:
`CD_GPT_MODE` ∈ {loop, single}, `CD_GEM_MODE` ∈ {pack, single}.

| Version | Construction | **Private** | Public | Kaggle sub |
|---|---|---:|---:|---|
| v1 | gpt **loop** + gemma **pack** (amortization bet) | 15.425 | 15.275 | 55954990 |
| v2 | gpt **loop** + gemma **single** | 15.840 | 16.460 | 55964418 |
| v3 | **both single-send** | 24.795 | 24.660 | 55964501 |
| v3 (re-fire) | same engine, resubmitted | **25.335** | 24.900 | — |

Screenshot: [`private_scores.png`](private_scores.png).

**What it shows.** (1) Single-send both models (~25) beats packed/looped (~15) — the amortization idea was refuted not by
timing but by the scoring identity itself: the unique-cell bonus is *per candidate*, so `k` separate sends earn `6k` while
one `k`-send candidate earns only `4k+2` (see `../scoring_math.py`). (2) The grader is **non-stationary** — the same v3
engine drew 24.795 then 25.335. (3) It is still far below the top (46.5 / 41.3): that gap is the hop-2 throughput frontier
(a gradient-attack + token-budget problem, write-up §6), not a better attack route.

## Reproduce

```bash
export AAS_SDK=/path/to/sdk
CD_GPT_MODE=single CD_GEM_MODE=single python cdmax_engine.py      # writes the single-send candidate set (v3)
```
