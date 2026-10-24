# Understanding output

Every check produces two things: a **value** (the text, e.g. `Full RELRO`) and a
**status** that drives the color. The status is the quickest way to read a
report at a glance.

## Color legend

| Swatch | Status (JSON/XML/YAML) | Meaning |
|:------:|:-----------------------|:--------|
| <span style="display:inline-block;width:1em;height:1em;border-radius:50%;background:#2e7d32"></span> **green** | `green` | **Good.** The mitigation is present and effective. |
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
| `green`  | green | `StatusGood` |
| `yellow` | yellow | `StatusWarn` |
| `red`    | red | `StatusBad` / `StatusError` |
| `unset`  | plain | `StatusInfo` |
| `italic` | italic | `StatusNA` |

Each check's report also has a stable **key** (the JSON/YAML map key, e.g.
`relro`, `fortify_level`). Those keys are what you pass to
[`--fail-if`](usage.md#ci-gating), and they're listed on every
[check reference](checks/binary.md) page.

## Multiple formats in one run

`checksec file`, `dir`, and `listfile` accept ELF and Mach-O, and a single run
may mix them. Each report carries its format (`elf` or `macho`) and, where
known, its architecture.

- **Universal (fat) Mach-O:** one report per slice, named `<path> [<arch>]`,
  for example `./app [arm64]` and `./app [x86_64]`.
- **Table:** rows are grouped by format in first-seen order. Each group prints
  its own header row (unless `--no-header`) with that format's columns, and
  column widths are computed per group. A single-format run looks the same as
  before.
- **CSV:** stays one rectangular table. The columns are the union of every
  format's checks plus a `Format` column and `Name`; a column that does not
  apply to a row is left empty.
- **JSON / YAML:** every report has `format` and `arch` keys next to `name`,
  and its `checks` map holds only that format's keys.
- **XML:** `<file name="..." format="macho" arch="arm64">` with its own
  `<checks>` list.

```text
RELRO           Stack Canary   NX           PIE           ...   Name
Full RELRO      Canary Found   NX enabled   PIE Enabled   ...   ./server

PIE           NX           Stack Canary   ...   Signature              Hardened   Name
PIE Enabled   NX enabled   Canary Found   ...   Signed [ABCDE12345]    Enabled    ./app [arm64]
PIE Enabled   NX enabled   Canary Found   ...   Signed [ABCDE12345]    Enabled    ./app [x86_64]
```

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
