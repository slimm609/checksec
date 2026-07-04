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

## Usage

    checksec file ./app -o llm
    checksec file ./app -o llm --exploit          # include attack-technique verdicts
    checksec dir ./bins -o llm                     # knowledge block emitted once
    checksec file ./app -o llm --llm-no-preamble   # no directive

## Severity glyphs

`[!]` weakness · `[~]` partial · `[ok]` hardened · `[i]` info
