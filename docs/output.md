# Understanding output

Every check produces two things: a **value** (the text, e.g. `Full RELRO`) and a
**status** that drives the color. The status is the quickest way to read a
report at a glance.

## Color legend

| Swatch | Status (JSON/XML/YAML) | Meaning |
|:------:|:-----------------------|:--------|
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;background:#2e7d32"></span> **green** | `green` | **Good.** The mitigation is present and effective. |
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;background:#1b8a2b;border:2px solid #2e7d32"></span> **bold green** | `boldgreen` | **Best.** A posture above *good* — currently only the AArch64 CFI check awards it (backward CFI + fine-grained forward CFI + BTI). |
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;background:#f9a825"></span> **yellow** | `yellow` | **Warning.** Partial protection, or checksec **could not determine** the state (see [Unknown](#unknown-vs-na) below). |
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;background:#c62828"></span> **red** | `red` | **Bad.** The mitigation is missing/disabled, or an error occurred reading the binary. |
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;border:1px solid #888;background:transparent"></span> **plain** | `unset` | **Informational.** Neutral facts that aren't good or bad — counts, `DSO`, the active sanitizer set. |
| _italic_ | `italic` | **Not applicable.** The check doesn't apply to this kind of binary. |

In the terminal these map to ANSI colors; in `json`/`xml`/`yaml` they appear as
the literal status string shown above. Color can be forced or disabled with
`--color always|never`.

## Unknown vs N/A

These two look similar but mean different things — this is the most common point
of confusion (see [issue #346](https://github.com/slimm609/checksec/issues/346)).

!!! warning "`Unknown` (yellow) — checksec couldn't tell"

    The check ran, but the binary didn't carry enough information to reach a
    verdict. The classic example is **`FORTIFY Lvl → Unknown`**: the FORTIFY
    *level* is read from [annobin](https://sourceware.org/annobin/) compiler
    notes, and this binary was built **without annobin** (common outside
    RHEL/Fedora toolchains). checksec can't prove the level either way, so it
    reports `Unknown` rather than guessing.

    `Unknown` is **not** a failure — it means "indeterminate." Other checks that
    can report `Unknown` include [CFI](checks/binary.md#cfi),
    [Stack Clash](checks/binary.md#stack-clash), and
    [GLIBCXX assertions](checks/fortify.md#glibcxx-assertions).

!!! note "`N/A` (italic) — the check doesn't apply"

    The mitigation is meaningless for this binary type. For example,
    [W^X segment](checks/binary.md#wx-segment) reports `N/A` for relocatable
    object files (`.o`) that have no loadable segments to check.

## Status values

The machine-readable `status` field takes one of these literal values:

| `status` | Color | Source constant |
|----------|-------|-----------------|
| `boldgreen` | bold green | `StatusBoldGreen` |
| `green`  | green | `StatusGood` |
| `yellow` | yellow | `StatusWarn` |
| `red`    | red | `StatusBad` / `StatusError` |
| `unset`  | plain | `StatusInfo` |
| `italic` | italic | `StatusNA` |

Each check's report also has a stable **key** (the JSON/YAML map key, e.g.
`relro`, `fortify_level`). Those keys are what you pass to
[`--fail-if`](usage.md#ci-gating), and they're listed on every
[check reference](checks/binary.md) page.

## Reading a row

```text
RELRO       Stack Canary  CFI      ...
Full RELRO  Canary Found  Unknown  ...
   ▲             ▲           ▲
 green         green       yellow  → "good, good, couldn't determine CFI"
```

A healthy modern binary is mostly green with a few neutral/plain columns. Yellow
and red are the cells worth investigating — head to the relevant
[check reference](checks/binary.md) page to learn what the value means and how
to fix it.
