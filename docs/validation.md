# Local validation record

Executed on Python 3.12.14, Linux, for this 0.1.0 source candidate:

- `python -m unittest discover -s tests -v`: 22 tests passed, including 1,024 truncation subcases and 5,000 deterministic mutated-ELF inputs.
- GCC-built executable parsed and its dependency/version names compared with GNU `readelf`; the executable was not run.
- A real compiled release archive failed a GLIBC 2.28 ceiling because it required GLIBC 2.34, with exit code 1 and JSON diagnostic.
- The same archive passed a policy with no GLIBC ceiling, with exit code 0.
- `python -m compileall -q releasegate tests`: passed.
- `python -m pip wheel . --no-deps --no-build-isolation`: built wheel successfully using locally available build tools.
- Wheel installed in a fresh virtual environment with `--no-index`; installed CLI help succeeded.
- Composite Action's isolated Python invocation was run locally against a real archive and passed.

Not run: GitHub-hosted Actions, other Python versions in the declared CI matrix, real historical issue artifacts, or user adoption testing. No full compatibility, fuzzing-security, performance, or supply-chain audit is claimed. Deterministic mutations are regression testing, not a substitute for coverage-guided fuzzing.
