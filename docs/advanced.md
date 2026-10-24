# Advanced

## FORTIFY breakdown

`fortifyFile` and `fortifyProc` print the per-function FORTIFY picture: which
fortifiable libc calls the binary uses, and which were routed through the
bounds-checked `*_chk` variants.

```bash
$ checksec fortifyProc 1
* Process name (PID)                         : init (1)
* FORTIFY_SOURCE support available (libc)    : Yes
* Binary compiled with FORTIFY_SOURCE support: Yes

------ EXECUTABLE-FILE ------- . -------- LIBC --------
FORTIFY-able library functions | Checked function names
-------------------------------------------------------
read                           | __read_chk
memcpy                         | __memcpy_chk
...

SUMMARY:
* Number of checked functions in libc                : 78
* Number of FORTIFY-able functions in the executable : 13
* Number of checked functions in the executable      : 7
```

!!! note "Determining the FORTIFY level"
    There is no fully reliable way to recover whether a binary was compiled at
    `_FORTIFY_SOURCE` level 1, 2, or 3 unless it carries
    [annobin](https://sourceware.org/annobin/) notes (see
    [FORTIFY Lvl](checks/fortify.md#fortify-lvl)). Some binaries embed the
    compile command in a string, which you can grep for:

    ```bash
    $ strings /usr/bin/vim | grep FORTIFY
    ... -D_FORTIFY_SOURCE=1
    ```

    Most binaries don't include this, which is why `FORTIFY Lvl` reports
    `Unknown` so often outside annobin toolchains.

## Cross-compiled / offline filesystems

checksec can inspect a cross-compiled target's filesystem offline, with two
caveats:

- **Kernel checks** read live kernel resources, so they must run on the target
  system — or you must point checksec at the target's kernel config file.
- **FORTIFY** resolves libc from the *running* system by default. For an offline
  rootfs, point checksec at the target's libc:

    ```bash
    checksec file /mnt/target/usr/bin/app --libc /mnt/target/lib/libc.so.6
    ```

  Alternatively run inside a `chroot` of the target rootfs. All other checks
  work directly against the offline files.

## OSX and BSD

File checks support ELF and Mach-O (thin and universal). Kernel, sysctl, and
process checks read Linux interfaces and remain Linux-only. BSD is not
officially supported.

## Verifying a release signature

Releases are signed with [cosign](https://docs.sigstore.dev/) using **keyless**
signing — there is no long-lived public key to distribute. Each release's
checksums file is signed in CI, and the signature is tied to the project's
GitHub Actions identity and recorded in the public [Rekor](https://docs.sigstore.dev/logging/overview/)
transparency log.

You'll need [cosign installed](https://docs.sigstore.dev/system_config/installation/).

### 1. Download the checksums file and its signature

From the [release page](https://github.com/slimm609/checksec/releases) (or with
`gh release download <tag>`), grab:

- `checksec_checksums.sha512` — the checksums of every artifact
- `checksec_checksums.sha512.sig` — its cosign signature
- `checksec_checksums.sha512.pem` — the signing certificate

### 2. Verify the checksums file is authentic

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/slimm609/checksec/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate checksec_checksums.sha512.pem \
  --signature checksec_checksums.sha512.sig \
  checksec_checksums.sha512
```

A successful check prints `Verified OK`. This proves the checksums file was
produced by the project's release workflow and hasn't been tampered with.

### 3. Verify your downloaded artifact against the checksums

```bash
# Run from the directory containing both the artifact and the checksums file
sha512sum --ignore-missing -c checksec_checksums.sha512
```

This confirms the binary or package you downloaded matches the authenticated
checksums.

!!! note "Older releases"
    Releases prior to cosign signing used an OpenSSL-based `checksec.sig` /
    `checksec.pub` scheme. That method is no longer used.
