# HANDOFF

State of this repository for the next teammate. Update it in the same push as
the work.

## Current state

- Version: 0.1.2 (Cargo.toml; the binary reports it via `CARGO_PKG_VERSION`).
- Public release: v0.1.2, tag `v0.1.2`, created with the release.
- Paper v1.1.2 re-audited and deposited: version DOI 10.5281/zenodo.24146345,
  concept DOI 10.5281/zenodo.24146344. The return-downloaded PDF hash matched
  the consented bytes exactly at deposit time.
- Evidence: `docs/EVIDENCE.md` plus the runs in `lab/`. Numbers there are
  measurements; BLA's published multipliers are modeled estimates and are cited
  as BLA's, never as ThoxShield results.

## Verified before this release

Measured 2026-11-11 on Linux x86-64 (KnightHub WSL, rustc 1.99.1), release
profile, at the released commit:

| Check | Result |
|---|---|
| `cargo build --release` | clean, 477 KB binary, zero crates fetched |
| `thoxshield --version` | `thoxshield 0.1.2` |
| `audit fixtures` | 3 artifacts, 3 formats, 0 lint findings, exit 0 |
| `harden fixtures` | 3 hardened, 0 sealed, 0 skipped, 0 failed |
| growth | GGUF +736 B, Safetensors +600 B, WASM +303 B |
| `verify` GGUF | 6/6 checks PASS, exit 0 |
| `verify` Safetensors | 2/2 checks PASS, exit 0 |
| `verify` WASM | 2/2 checks PASS, exit 0 |
| `manifest` | version 0.1.2, correct SHA-256 per artifact |
| `team fixtures` | SUCCESS in 1 loop, exit 0, report version 0.1.2 |
| `team` on a lint-blocked tree | STOPPED, exit 1 |
| `audit` on a missing path | exit 1 |

Defect found and fixed in this release cycle: `const VERSION` was hardcoded to
`0.1.0`, so a 0.1.2 build reported the wrong version in `--version`, `audit`
JSON and `team-report.json`. Now `env!("CARGO_PKG_VERSION")`.

## Binary provenance (read before quoting a hash)

The paper v1.1.2 measures the v0.1.2 build it was written against:
**486,808 bytes, SHA-256 `34592b6d1f13e40849…`** (see
`exp/results/summary.json` → `thoxshield_v0_1_2`). The binary attached to the
GitHub release v0.1.2 is **488,072 bytes, SHA-256
`1a53a617c3a80c7c724885c43f43b3373e0aabcbc8b98648ad97556c28ff1abe`**.

They are not byte-identical, on purpose and by chronology: this release was
built from the same v0.1.2 source after two pre-release changes that the paper's
recorded build predates — the `CARGO_PKG_VERSION` fix and 17 mechanical clippy
fixes under rustc 1.99. Hardened output is unaffected: the three fixture
artifacts harden to the same three SHA-256 values before and after those
changes, which is how the refactor was proven behavior-preserving.

So: quote `34592b6d…` when citing the paper's measurements, and `1a53a617…`
when verifying the release download. Do not present them as the same build.


## Known limitations (do not soften)

A ~60-line stripper written from the public format specs removes every shield
and recovers GGUF and WASM payloads byte-exactly, Safetensors payload-exactly,
in under a millisecond per artifact. The shields are budget tripwires and
attribution canaries. The embedded origin hash also confirms a correct strip.
Not tamper resistance, not secrecy, not an enclave. Full list in
`docs/EVIDENCE.md`.

## Open work

- Streaming verification: the tool loads artifacts fully in memory (peak RSS
  about 2x artifact size). A 512 MiB GGUF peaks near 1,026 MiB. This is the
  main blocker for multi-GB model workflows.
- Live REA run: the nesting-breaker evidence is SIMULATED against a budgeted
  walker. A recorded live reverse-engineering-agent run remains future work and
  would upgrade that classification.
- The bloat-cap refusal path cannot trigger with the current lite shields; it
  is a guardrail for future shields. Add a test that exercises it when a shield
  that can actually approach the cap lands.

## Rules for the next agent

- Defensive use only, on artifacts you own. No offensive capability, no
  prompt-injection layers, no fake legal or regulatory notices in shields.
- Zero dependencies stays zero.
- Never hardcode the version.
- Any change to shield behavior ships with a `lab/` measurement and an updated
  `docs/EVIDENCE.md`, limitations included.
- THOX.ai LLC maintains this repository. Canonical legal block stays in
  `NOTICE`: "© 2026 THOX.ai LLC. All rights reserved, subject to applicable
  licenses." Product names keep exact casing (ThoxShield, ThoxKey, ThoxAir,
  ThoxMini, ThoxClip, ThoxOS, MeshStack). Tagline: Your AI. Your Data.
  Your Rules.™
