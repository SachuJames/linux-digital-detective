# Correlation engine

The correlation engine (`src/correlation.rs`) pairs events that look
related and scores them. Scores are **heuristics with a reason breakdown**,
shown in reports as "Correlation signals". They are not verdicts: a high
score means "these events share context", not "this is malicious".

## Signals and weights

For two events within the time window (`DEFAULT_WINDOW_SECS` = 300):

| Signal | Weight | Condition |
|---|---|---|
| same user | +0.25 | both events name the same non-empty user |
| same pid | +0.25 | both events have the same pid |
| same process | +0.15 | both events name the same process |
| same src addr | +0.15 | both events have the same source address |
| same dst addr | +0.10 | both events have the same destination address |
| time proximity | +0.00..0.30 | linear decay: 0.30 at 0s apart, 0 at the window edge |

Pairs scoring below `MIN_SCORE` (0.30) are discarded. The weights are
deliberately simple and documented here so an investigator can sanity-check
any correlation by hand.

## Complexity

Pairwise comparison is O(n^2) within the window, which is fine for
investigation-sized inputs (thousands of events). The `EventStore` cap
(`DEFAULT_MAX_EVENTS` = 100,000) bounds the worst case. If you regularly
work with larger inputs, this is the stage to optimize first (sweep-line or
indexed join on shared keys).

## How correlations are used

- Rules may look at correlations, but no built-in rule requires them.
- Reports list, per finding, the correlation reasons of event pairs the
  finding touches — but only pairs that share at least one identifying
  signal ("same user", "same pid", ...). Pairs related only by time
  proximity are not shown, to keep reports readable.

## Limitations

- Correlation is purely syntactic: it matches on shared fields, not on
  causality. Two unrelated events from the same user within five minutes
  will correlate.
- NAT, shared service accounts, and DHCP churn can create misleading
  "same address" or "same user" signals. The reason breakdown exists so you
  can see exactly which signals fired and discount them.
