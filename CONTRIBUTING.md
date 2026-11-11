# Contributing

Run `python -m unittest discover -s tests -v` on Python 3.10 or newer. GCC and GNU readelf enable an additional real-ELF integration test; install them in CI. Keep runtime dependencies at zero unless the benefit and supply-chain tradeoff are justified.

For bug reports include your OS, Python version, policy, diagnostic, and a minimal redistributable fixture where possible. Do not attach private executables or secrets. New checks need positive and negative tests. Parser changes need malformed-input tests. Never execute inspected binaries or use `ldd` in the checker.

Changes to schema, exit-code semantics, limits, and unsupported features must be documented. Do not describe static inspection as a guarantee of runtime compatibility.
