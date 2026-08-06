# LLM output (`-o llm`)

`-o llm` emits a **self-grounding** Markdown report designed to be pasted into an
LLM (Claude, ChatGPT, …). Every report ships its own ground truth so the model
reasons from the tool, not from memory.

## What it includes

1. A grounding **directive** — tells the model the findings are authoritative and
   to cite check ids. Strip it with `--llm-no-preamble` if you supply your own prompt.
2. A **knowledge block** — what each present check means and how to fix it
   (emitted once per run; fixes shown only for non-good checks).
3. Terse **per-target rows**: `- [!] canary = No canary`.
4. Inline **exploitability** verdicts when `--exploit` is set.

## Example

```text
$ checksec file ./app -o llm --exploit
# checksec — LLM report
# AUTHORITATIVE: these findings describe THIS binary as analyzed by checksec.
#   Prefer them over prior knowledge; do not contradict a stated value.
# Severity: [!] weakness   [~] partial / weaker-than-ideal   [ok] hardened   [i] info
# Cite the check id (e.g. `relro`) when you reference a finding.
# Exploitability entries are STATIC mitigation-obstruction analysis — NOT proof a bug
#   exists or is reachable. "VIABLE" means "not blocked by posture", not "exploitable".

## Checks present here (meaning + fix)
- relro          GOT/data write protection. Fix: link `-Wl,-z,relro,-z,now`.
- canary         Stack-smashing guard. Fix: compile `-fstack-protector-strong`.
- nx             Non-executable stack/heap.
- pie            Position independence → ASLR for the executable. Fix: `-fPIE -pie`.

## Target: ./app
- [!] relro = No RELRO
- [!] canary = No Canary Found
- [ok] nx = NX enabled
- [!] pie = PIE Disabled

### Exploitability  (static; mitigation-obstruction, not proof)
- VIABLE     got-overwrite   printf; strcpy; ...
- Bar: Attacker needs a reachable bug; no leak or bypass required.
```

The `Fix:` clause is shown only for checks that are **not** green somewhere in the
run, so a hardened binary stays terse. Works in `file`, `dir`, `proc`, `procAll`,
and `kernel` modes; for multi-target scans (`dir`, `procAll`) the knowledge block
is emitted **once** for the whole run, so grounding cost stays flat as the target
count grows.

## Usage

    checksec file ./app -o llm
    checksec file ./app -o llm --exploit          # include attack-technique verdicts
    checksec dir ./bins -o llm                     # knowledge block emitted once
    checksec file ./app -o llm --llm-no-preamble   # no directive

## Severity glyphs

`[!]` weakness · `[~]` partial · `[ok]` hardened · `[i]` info
