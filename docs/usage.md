# Usage

checksec is invoked as `checksec <command> [args] [flags]`. Each command
selects *what* to scan; the global flags control *how* results are rendered.

## Commands

| Command | Scans | Example |
|---------|-------|---------|
| `file <file>` | A single ELF binary | `checksec file /usr/bin/ls` |
| `dir <directory>` | Every ELF in a directory (add `-r` to recurse) | `checksec dir /usr/bin -r` |
| `proc <pid>` | The executable backing a running process | `checksec proc 1` |
| `procAll` | Every running process you can read | `checksec procAll` |
| `procLibs <pid>` | The shared libraries mapped into a process | `checksec procLibs 1` |
| `listfile <path\|->` | A newline-delimited list of paths (`-` = stdin) | `checksec listfile targets.txt` |
| `kernel` | The running kernel's hardening configuration | `checksec kernel` |
| `fortifyFile <file>` | FORTIFY_SOURCE breakdown for one binary | `checksec fortifyFile /usr/bin/ls` |
| `fortifyProc <pid>` | FORTIFY_SOURCE breakdown for a process | `checksec fortifyProc 1` |

## Global flags

These persistent flags apply to every command:

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output <format>` | `table` | Output format: `table`, `json`, `yaml`, `xml`, `csv`, `llm`. |
| `-l, --libc <path>` | _(auto)_ | Path to libc, used by the FORTIFY check for offline / embedded filesystems. See [Advanced](advanced.md). |
| `--color <mode>` | `auto` | Color output: `auto`, `always`, `never`. |
| `--no-banner` | off | Suppress the ASCII banner. |
| `--no-headers` | off | Suppress the column header row. |
| `--no-warnings` | off | Suppress non-fatal warnings (e.g. unreadable files during a scan). |
| `--fail-if <keys>` | _(none)_ | Exit non-zero if any listed check is not green. See [CI gating](#ci-gating). |

## Output formats

The same scan rendered in each format (columns trimmed for space):

=== "table (default)"

    ```bash
    $ checksec file ./myapp
    RELRO       Stack Canary  CFI      NX          PIE          ...  Name
    Full RELRO  Canary Found  Unknown  NX enabled  PIE Enabled  ...  ./myapp
    ```

=== "csv"

    ```bash
    $ checksec file ./myapp -o csv
    RELRO,Stack Canary,CFI,NX,PIE,...,Name
    Full RELRO,Canary Found,Unknown,NX enabled,PIE Enabled,...,./myapp
    ```

=== "json"

    ```bash
    $ checksec file ./myapp -o json
    ```

    ```json
    [
      {
        "name": "./myapp",
        "checks": {
          "relro":  { "value": "Full RELRO",  "status": "green" },
          "canary": { "value": "Canary Found", "status": "green" },
          "cfi":    { "value": "Unknown",      "status": "yellow" }
        }
      }
    ]
    ```

=== "xml"

    ```bash
    $ checksec file ./myapp -o xml
    ```

    ```xml
    <checksec>
      <file name="./myapp">
        <checks>
          <relro status="green">Full RELRO</relro>
          <canary status="green">Canary Found</canary>
          <cfi status="yellow">Unknown</cfi>
        </checks>
      </file>
    </checksec>
    ```

=== "yaml"

    ```bash
    $ checksec file ./myapp -o yaml
    ```

    ```yaml
    - name: ./myapp
      checks:
        relro:
          value: Full RELRO
          status: green
        cfi:
          value: Unknown
          status: yellow
    ```

=== "llm"

    Self-grounding Markdown report for pasting into LLM assistants (Claude, ChatGPT, …).
    See [LLM output](llm.md) for full documentation.

!!! tip "Machine-readable output carries the color too"

    `json`, `yaml`, and `xml` emit a list of files, and every check reports both
    a `value` (the text) and a `status` (`green`, `yellow`, `red`, `unset`,
    `italic`). See [Understanding output](output.md) for what each status means.

## CI gating

`--fail-if` turns checksec into a build/CI gate. Pass a comma-separated list of
[check keys](output.md#status-values); checksec exits non-zero if any of them is
not green:

```bash
# Fail the pipeline unless the binary has RELRO, a stack canary, and PIE
checksec file ./myapp --fail-if=relro,canary,pie
```

The keys are the JSON/YAML keys from the report (`relro`, `canary`, `cfi`, `nx`,
`pie`, `rpath`, `runpath`, `fortify_source`, …). See each
[check reference](checks/binary.md) page for the key of a given check.
