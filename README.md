# ReleaseGate ELF

**Catch predictable Linux release failures before users download the archive.**

ReleaseGate checks the **finished artifact**, independent of whether it was built with CMake, Cargo, Go, Python packaging, or a custom script. It compares ELF metadata and archive contents to a small JSON policy. No target binary is executed, no archive is extracted, and no third-party Python package is needed at runtime.

This is an **alpha implementation**, not a compatibility certification service. It has not been published to PyPI or the GitHub Marketplace, and no external adoption is claimed. The CLI is called `releasegate`; this repository uses `releasegate-elf` to distinguish it from unrelated projects with similar names.

## What it catches

- An x86_64 release accidentally containing an ARM binary.
- A binary requiring `GLIBC_2.34` when the release policy promises `2.28`.
- A C++ dependency requiring a newer `GLIBCXX` symbol version than allowed.
- Missing named assets, licenses, configuration files, or launchers.
- A launcher losing its executable permissions during packaging.
- An undeclared `DT_NEEDED` library when an explicit dependency allowlist is supplied.

## Try it

Requires Python 3.10+. From this checkout, without installing anything:

```sh
python -m releasegate dist/myapp-linux.tar.gz --policy examples/policy.json
python -m releasegate dist/myapp-linux.tar.gz --policy examples/policy.json --format json
```

Or install this source locally:

```sh
python -m pip install .
releasegate dist/myapp-linux.zip --policy release-policy.json
```

Exit codes: **0** passes, **1** policy violations, **2** invalid policy/archive or I/O error. JSON output has `schema_version: 1` and `ok`; successful inspection also includes `files_checked`, `binaries`, and `issues`. Input errors instead include `error`.

A minimal policy:

```json
{
  "schema_version": 1,
  "architecture": "x86_64",
  "max_glibc": "2.28",
  "max_glibcxx": "3.4.25",
  "required_files": ["myapp/assets/default.cfg"],
  "executables": ["myapp/bin/myapp"]
}
```

Paths are exact, normalized, case-sensitive archive member paths. Include the top-level release directory if the archive has one. There are no globs. `executables` also implies file existence, and checks that at least one execute bit was preserved. ZIP packagers must preserve Unix mode attributes for this check to pass.

Optional `runtime_dependencies` is an **explicit allowlist of SONAME strings**, checked against every ELF file's direct `DT_NEEDED` entries. Include dependencies intentionally supplied by the OS or bundled with the archive. A matching bundled basename does **not** automatically satisfy the rule. An omitted list disables this check; an empty list rejects every dynamic dependency. This is declaration auditing, **not library resolution**.

`architecture` is required: `x86`, `x86_64`, `arm`, `aarch64`, or `riscv` (either 32/64-bit RISC-V). `require_elf` defaults to `true`. Omitted version ceilings disable their respective checks. Unknown keys and invalid types are errors so policy typos do not silently disable checks.

## GitHub Actions

The action needs Python 3.10+ on the runner. Vendor this source at `tools/releasegate` for the example below:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
- name: Build archive
  run: ./scripts/build-release.sh
- uses: ./tools/releasegate
  with:
    artifact: dist/myapp-linux.tar.gz
    policy: release-policy.json
```

If ReleaseGate itself is the checked-out repository, use `uses: ./`. To use the hosted action, replace `./tools/releasegate` with `SKYRPG8957/releasegate-elf@<reviewed-commit-sha>`. Pin a full commit SHA rather than a moving branch. Input paths are passed through quoted environment variables, not interpolated into shell source. The action uses Python isolated mode and does not install dependencies.

## Scope and honest limits

ReleaseGate reads program headers, dynamic strings, `DT_NEEDED`, and **version requirements** (`DT_VERNEED`), not arbitrary strings and not exported version definitions. It works without section headers and with stripped ELF files. ELF32/ELF64 and little/big endian are supported; extended program-header numbering and the x32 ABI are not.

A passing result does **not** establish that a program runs on a distribution. In particular it does not detect or resolve:

- `dlopen` / plugin-loaded libraries. Declare their known files under `required_files`, but still run integration tests.
- Transitive dependencies outside the archive, loader search paths, SONAME resolution, or versioned symbol availability on the target host.
- Missing CPU instructions, kernel features, GPU/audio drivers, system services, data correctness, or desktop integration.
- Compatibility problems in non-ELF payloads, nested archives, AppImages, RPMs, or DEBs.
- Every malformed ELF: this is a deliberately scoped metadata reader, not a full ELF validator or malware scanner.

A bundled library is checked as another ELF file; its requirements can still violate the baseline. Unknown nonnumeric GLIBC/GLIBCXX requirements fail closed when that family's ceiling is enabled. Static binaries have no dynamic version requirements; that is not evidence of full portability.

## Safety model

Only ZIP and tar/tar.gz/tar.bz2/tar.xz archives are supported (as provided by Python's standard library). No extraction, target execution, `ldd`, subprocess inspection, or network calls occur in the checker. Absolute/traversal paths, control characters, duplicate normalized paths, symlinks, hardlinks, and special files are rejected. **Real releases containing symlinks must currently be repackaged as regular files**; link support is intentionally deferred.

Defaults: 10,000 entries, 128 MiB per file, 512 MiB total expanded regular-file content; ELF dynamic tables and version chains also have explicit bounds. Contents are held in memory. These are application limits, not a security sandbox: hostile archives can still consume CPU or memory through decompression or archive metadata. Use isolated CI with resource limits for untrusted inputs. Keep Python updated.

## Development

```sh
python -m unittest discover -s tests -v
python -m compileall -q releasegate tests
```

The suite includes synthetic GLIBC/GLIBCXX regression fixtures, architecture and permission failures, malformed ELF truncations, hostile paths, links, limits, CLI status codes, and a GCC-built ELF compared with `readelf` when those tools are available. Test binaries are never executed. See [evidence and positioning](docs/evidence.md).

License: MIT. Contributions should include a failing fixture, an expected diagnostic, and a test. See [CONTRIBUTING.md](CONTRIBUTING.md).
