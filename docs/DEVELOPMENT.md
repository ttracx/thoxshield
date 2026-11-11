# Development

How ThoxShield is built, tested, and kept honest.

## Layout

```
src/main.rs       entry point, verb dispatch, audit / harden / verify / manifest
src/team.rs       the five-role agent-team loop and its state/report writers
src/detect.rs     magic-byte format detection
src/json.rs       minimal JSON writer and parser (no serde, by design)
src/sha256.rs     SHA-256, self-contained
harness/          WORKORDER.md for external agent drivers
lab/              experiment suite and its README
examples/         make_fixtures.py, the deterministic fixture generator
docs/             user guide, quickstart, evidence, limitations, loop harness
```

Zero dependencies is a hard rule, not a preference. The tool ships inside
release pipelines and onto devices; every crate added is an audit surface and a
supply-chain edge. `Cargo.toml` must stay free of `[dependencies]`. If a change
appears to need a crate, write the 60 lines instead.

## Build

```bash
cargo build --release
cargo build --release --locked
```

The binary is ~477 KB stripped. `cargo clippy -- -D warnings` must be clean
before a release. Release profile is `opt-level = 3`, `lto = true`,
`codegen-units = 1`, `strip = true`, `panic = "abort"`.

Version discipline: the version string comes from `env!("CARGO_PKG_VERSION")`.
Never hardcode it — a binary that misreports its own version against a
CHANGELOG is a release defect, and it has happened once (v0.1.2 staging shipped
`const VERSION = "0.1.0"` until it was caught in a pre-release smoke test).

## Test

```bash
python3 examples/make_fixtures.py
./target/release/thoxshield audit    fixtures
./target/release/thoxshield harden   fixtures --out shielded
./target/release/thoxshield verify   fixtures/model.gguf shielded/model.gguf
./target/release/thoxshield manifest shielded
./target/release/thoxshield team     fixtures --out teamrun
```

The release gate is behavioral, not a unit-test count: audit identifies all
three fixture formats with 0 lint findings; harden produces the measured
growth; verify passes every check on all three formats; manifest reports the
correct version; team reaches SUCCESS in one loop. Any verb that silently
changes exit-code semantics is a breaking change and needs a CHANGELOG entry.

Exit codes are part of the interface. Verify them without a shell pipeline —
`cmd | tail` reports the tail's status, not the tool's.

```bash
./target/release/thoxshield team linttree --out lt >/dev/null 2>&1; echo $?  # expect 1
```

The full experiment suite lives in `lab/` and is what produces the numbers in
`docs/EVIDENCE.md` and the paper. Run it before changing any shield:

```bash
python3 lab/lab.py --help
```

## Evidence rules

Every performance or size claim must be reproducible from a recorded run in the
recorded environment, classified MEASURED, STRUCTURAL, or SIMULATED, and labeled
as such wherever it prints. A modeled estimate is never cited as a ThoxShield
result. New shielding behavior ships with its own measurement in `lab/` and an
updated `docs/EVIDENCE.md`, including the limitations section — the limitations
are part of the product, not fine print.

## Style

- Rust 2021, `rustfmt` clean, no `unsafe` unless the reason is written at the
  call site.
- Errors are explicit: a file that cannot be read produces an error finding and
  a stderr note. Never hash empty input and call it a result.
- Parsers cap depth (GGUF metadata nesting is capped at 512 in the parser as
  well as broken at 35 on write) so adversarial input cannot overflow the stack.
- Output that a machine consumes (`--json`, `manifest`, `team-report.json`) is
  stable in key order and safe to diff.

## Release checklist

1. `cargo clippy -- -D warnings` clean, `cargo build --release --locked` clean.
2. Behavioral gate above re-run at the release commit; record the output.
3. `CHANGELOG.md` entry with the version and the date.
4. Version bumped in `Cargo.toml` only; binary reports it automatically.
5. Tag `vX.Y.Z`, publish the release with the built binary and the manifest.
6. If shields changed, `docs/EVIDENCE.md` and `lab/` updated in the same commit.

## Governance

THOX.ai LLC maintains this repository. Defensive use only. Contributions that
add offensive capability, prompt-injection layers, fake legal notices, or that
weaken the limitations language in `docs/EVIDENCE.md` are out of scope and will
be declined. Security reports: see `SECURITY.md`.
