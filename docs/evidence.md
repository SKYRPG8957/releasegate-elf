# Motivation, evidence, and differentiation

Public issue references motivating investigation of Linux binary-distribution failures:

- https://github.com/trycua/cua/issues/1925
- https://github.com/diasurgical/DevilutionX/issues/8702

These are contextual leads, not claimed reproductions or endorsements. Tests here use generated, minimal ELF fixtures representing newer-than-policy GLIBC / GLIBCXX requirements. They do **not** redistribute those projects' releases or claim to establish the cause, fix, or current status of either issue. Real historical-artifact reproduction remains future validation work.

## Why another checker?

- **cargo-dist** helps build and distribute Rust releases. ReleaseGate audits the already-packaged output and is not a release orchestrator.
- **cargo-zigbuild** helps build Rust artifacts with Zig, including glibc target control. ReleaseGate is a post-build check, not a compiler or cross-compilation solution.
- **PyBinaryGuard** occupies adjacent binary compatibility checking territory. ReleaseGate does not claim this idea is novel or that existing tools lack ELF checks. Its proposed focus is a small build-system-independent archive gate combining ABI ceilings, expected content, permission checks, and explicit dependency declarations.

Those are positioning statements, not a feature-by-feature benchmark. Demand is a hypothesis. The next useful validation is to ask maintainers to run this against real Linux release archives and record false positives, missed failures, and integration cost.

## Acceptance boundaries

A policy defines what a maintainer intends to ship. ReleaseGate verifies only metadata it can observe in the archive. It should complement a clean-target runtime smoke test, not replace one. A future feature must not claim dynamic loader coverage without actually modeling and testing the loader or running the artifact in a suitable isolated target environment.
