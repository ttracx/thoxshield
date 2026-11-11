# ThoxShield

[![License: MIT](https://img.shields.io/badge/license-MIT-05A451.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.2-05A451.svg)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-zero%20dependencies-0A0A0A.svg)](Cargo.toml)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.24146345-05A451.svg)](https://doi.org/10.5281/zenodo.24146345)

**Your AI. Your Data. Your Rules.™**

ThoxShield is an open-source, defensive counter-REA (reverse-engineering agent) tool by [THOX.ai](https://thox.ai). It protects **your own** software releases — AI model files, WebAssembly modules, and release trees — against autonomous AI reverse-engineering pipelines that can unpack, summarize, and clone an unprotected artifact in seconds.

ThoxShield is the *light* end of counter-REA defense, in a single zero-dependency Rust binary:

- **Audit everything.** Inventory a release tree by magic bytes, SHA-256 every artifact, and lint for plaintext secrets and shipped source maps.
- **Shield lightly.** For GGUF and Safetensors models and WASM modules, add self-identifying canary metadata, a metadata-nesting breaker that trips known analyzer limits, and a SHA-256 binding to the original bytes — inside a hard **bloat cap** (default: at most 4 KiB or 5% added, whichever is larger). No exhaustion flooding, no megabyte tarpits in your app bundle.
- **Verify independently.** Prove the hardened artifact preserves the original payload byte-for-byte where it matters (tensor data, WASM body) and carries the seal.
- **Run it as a team.** The built-in agent-team loop harness coordinates five generic roles — coordinator, auditor, hardener, verifier, reporter — in a resumable audit → harden → verify → report loop, with the producer never verifying its own output.

```bash
cargo build --release          # one binary, zero crates, ~470 KB

thoxshield audit ./release --json
thoxshield harden ./release --out ./release-shielded
thoxshield verify ./release/model.gguf ./release-shielded/model.gguf
thoxshield manifest ./release
thoxshield team ./release --out ./team-run        # the full loop, as a team
```

## Why bloat-capped?

The counter-REA field's heavy tools work — and their own published fixtures show the cost: hardening a 93-byte JavaScript file to 134 KB (1,440×), or an 8-byte WASM module to 3.9 MB. That trade is right for some releases and wrong for apps, devices, and model downloads. ThoxShield's position: the highest-value trips (model metadata nesting, canary attribution, origin binding) cost **hundreds of bytes**, so they should never cost megabytes. Everything heavier stays opt-in and out of this tool. The measurements behind this position are in the accompanying paper (see below).

## The agent-team harness

Modern releases are built by teams of agents, so the defense runs as one too — without shipping any proprietary agent system. The harness is a deterministic loop over the same CLI verbs, driven by a shared workorder and a state file any agent can resume:

| Role | Job |
|---|---|
| coordinator | owns the loop, the state file, and the stop conditions |
| auditor | inventories, hashes, and lints the tree |
| hardener | applies light shields inside the bloat cap, from the original inputs every iteration |
| verifier | independently re-checks every shielded artifact; its verdict, not the hardener's, closes the loop |
| reporter | writes `team-report.json` and `team-log.md` |

Stop conditions are explicit: everything verified (success), a blocking lint finding such as a plaintext secret (stop — that is not a shielding problem), or the iteration budget (default 3) running out (reported as failure). External agents — an LLM coding agent, CI, a human — can drive the identical loop by following [harness/WORKORDER.md](harness/WORKORDER.md). See [docs/LOOP-HARNESS.md](docs/LOOP-HARNESS.md).

## Formats

| Format | Audit + lint | Light shield | Verify |
|---|:---:|:---:|:---:|
| GGUF models | ✓ | ✓ canary KV + 35-deep array nesting breaker | ✓ KV preserved, tensor bytes identical |
| Safetensors models | ✓ | ✓ canary metadata + nesting breaker | ✓ payload identical, header valid |
| WebAssembly | ✓ | ✓ inert custom section with canary + origin hash | ✓ original bytes are a prefix |
| JS/TS, Python, SQLite, ASAR, ELF/PE/Mach-O, DEX, BEAM, PCAP, ZIP, plist, source maps | ✓ | — (audit-only in this tool) | — |

## Safety and honesty

- **Defensive use only.** Run ThoxShield on software you own or are explicitly authorized to modify. See [DISCLAIMER](docs/DISCLAIMER.md).
- **No secrets in shields.** Client-side protection buys cost and time; it does not create secrecy. Keep real keys server-side. ThoxShield's canaries are synthetic and self-identifying; its enclave-manifest canary states plainly that no enclave is present.
- **No prompt-injection layers.** ThoxShield does not plant instructions aimed at other people's agents, and it does not ship fake legal or regulatory notices.
- **Measured, not modeled.** Every number in the paper's evidence file is a measurement from the recorded environment. Modeled token-amplification estimates are labeled as such wherever they appear.

## Paper

*ThoxShield: Bloat-Capped Counter-REA Defense for Local-First AI Artifacts* — THOX.ai Research.

- Version of record: **DOI [10.5281/zenodo.24146345](https://doi.org/10.5281/zenodo.24146345)** (concept DOI [10.5281/zenodo.24146344](https://doi.org/10.5281/zenodo.24146344))
- Paper v1.1.2, deposited 2026-11-11 with a return-download byte-for-byte hash check against the consented edition
- Evidence file `exp/results/summary.json` and the experiment code in `lab/` ship with the paper; every number in it is a measurement from the recorded environment, and modeled estimates are labeled as modeled

## Documentation

- [Quickstart](docs/QUICKSTART.md) — build, run the fixtures, harden your own release
- [User guide](docs/USER_GUIDE.md) — every verb, its JSON, and its exit code
- [Evidence and limitations](docs/EVIDENCE.md) — what the shields are proven to do, and what they are not
- [Loop harness](docs/LOOP-HARNESS.md) — driving the team loop from an external agent or CI
- [Development](docs/DEVELOPMENT.md) — build, test, evidence rules, release checklist
- [Previews](docs/previews/) — verbatim terminal captures from the released binary

## License and credit

MIT — see [LICENSE](LICENSE). The counter-REA concept and the format-budget research this tool builds on are credited to **BLA (Blind LLM Agents)**, `qybaihe/bla`, MIT — see [NOTICE](NOTICE). ThoxShield's code is an original Rust implementation of the light subset; it is not a fork.

Governance: THOX.ai LLC maintains this repository. Defensive use only, on artifacts you own or are authorized to modify. Contributions adding offensive capability, prompt-injection layers, or fake legal notices are out of scope. A full legal block is carried in [NOTICE](NOTICE): © 2026 THOX.ai LLC. All rights reserved, subject to applicable licenses. THOX.ai™ and THOX product names and logos are trademarks of THOX.ai LLC. Other marks belong to their respective owners.

Your AI. Your Data. Your Rules.™
