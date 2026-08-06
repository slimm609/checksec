# checksec

**checksec** inspects the security properties of ELF executables, running
processes, and the Linux kernel — RELRO, stack canaries, NX, PIE, control-flow
integrity (CFI), FORTIFY_SOURCE, and more.

It was originally written as a bash script by Tobias Klein in 2011
([original site](http://www.trapkit.de/tools/checksec.html)). This project is a
modern rewrite in Go, distributed as a single static binary.

Beyond reporting the raw mitigation posture, checksec can reason about **which
attack techniques that posture fails to obstruct**
([exploitability reasoning](checks/exploitability.md), `--exploit`) and emit a
**self-grounding report you can paste straight into an LLM**
([`-o llm`](llm.md)).

## Install

=== "Binary release"

    Download a prebuilt binary from the
    [releases page](https://github.com/slimm609/checksec/releases) and place it
    on your `PATH`:

    ```bash
    install -m 0755 checksec /usr/local/bin/checksec
    ```

=== "Packages"

    `.deb`, `.rpm`, and `.apk` packages are attached to each
    [release](https://github.com/slimm609/checksec/releases).

=== "Docker"

    ```bash
    docker run --rm -v "$PWD:/data" slimm609/checksec:latest file /data/your-binary
    ```

=== "From source"

    ```bash
    go install github.com/slimm609/checksec/v3@latest
    ```

## Quick start

```bash
# Check a single binary
checksec file /bin/ls

# Recursively check a directory
checksec dir /usr/bin -r

# Check a running process by PID
checksec proc 1

# Inspect the running kernel's hardening configuration
checksec kernel

# Reason about which attack techniques the posture leaves unobstructed
checksec file /bin/ls --exploit

# Emit a self-grounding report to paste into an LLM assistant
checksec file /bin/ls -o llm
```

Example output:

```bash
$ checksec file /bin/ls
RELRO           STACK CANARY   NX           PIE          RPATH      RUNPATH    FILE
Full RELRO      Canary Found   NX enabled   PIE Enabled  No RPATH   No RUNPATH /bin/ls
```

## Where to go next

<div class="grid cards" markdown>

-   :material-console: **[Usage](usage.md)**

    Command-line flags, scan modes, and output formats (CLI, CSV, JSON, XML, YAML).

-   :material-palette: **[Understanding output](output.md)**

    What the colors mean, and how to read every status value — including
    `Unknown` and `N/A`.

-   :material-shield-check: **[Checks reference](checks/binary.md)**

    Every check explained: what it protects against, how it's detected, every
    possible value, and how to enable it.

-   :material-target: **[Exploitability](checks/exploitability.md)**

    `--exploit` reasons about which attack techniques the mitigation posture
    fails to obstruct — evidence-cited, honest tiers, never claims "exploitable."

-   :material-robot: **[LLM output](llm.md)**

    `-o llm` emits a self-grounding Markdown report designed to be pasted into an
    LLM assistant so it reasons from the tool, not from memory.

</div>

!!! question "Looking for what a specific value means?"

    If you saw something like `FORTIFY Lvl → Unknown` and aren't sure what it
    means, start with [Understanding output](output.md), then jump to the
    relevant [check reference](checks/binary.md) page.
