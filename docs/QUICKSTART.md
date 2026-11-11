# Quickstart

ThoxShield is a single zero-dependency Rust binary. Build it, or drop in the
release binary, then point it at a release tree you own.

## Build

```bash
git clone https://github.com/ttracx/thoxshield.git
cd thoxshield
cargo build --release
```

No crates are fetched. `cargo build --release` produces one binary
(`target/release/thoxshield`, ~477 KB on macOS aarch64 and Linux x86-64).

## Prove it works on the bundled fixtures

```bash
python3 examples/make_fixtures.py   # writes fixtures/{model.gguf,model.safetensors,core.wasm}
./target/release/thoxshield audit    fixtures
./target/release/thoxshield harden   fixtures --out shielded
./target/release/thoxshield verify   fixtures/model.gguf shielded/model.gguf
./target/release/thoxshield team     fixtures --out teamrun
```

Expected on the shipped fixtures (v0.1.2, measured):

```
audit:  3 artifact(s), 0 lint findings
harden: 3 hardened, 0 already sealed, 0 skipped, 0 failed
verify: PASS on all three formats, exit 0
team:   SUCCESS after 1 loop(s) — all hardenable artifacts verified
```

## Use it on your own release

```bash
# 1. Inventory and lint first. Never shield a tree you have not looked at.
thoxshield audit ./dist --json > audit.json

# 2. Harden into a NEW output directory. Inputs are never modified in place.
thoxshield harden ./dist --out ./dist-shielded --max-add-pct 5

# 3. Verify independently. This is the verdict that counts.
thoxshield verify ./dist/model.gguf ./dist-shielded/model.gguf

# 4. Record what shipped.
thoxshield manifest ./dist-shielded > manifest.json
```

## Decide whether the shields are worth it for you

The added cost is measured and small:

| Format | Added bytes (measured, shipped fixtures) | What it buys |
|---|---|---|
| GGUF | +736 B | canary KV pair + 35-deep metadata nesting breaker + origin SHA-256 |
| Safetensors | +600 B (fixture-dependent, header rewrite) | canary metadata + nesting breaker + origin header binding |
| WASM | +303 B | inert custom section: canary, origin hash, original byte length |

Read [docs/EVIDENCE.md](../EVIDENCE.md) before you rely on the shields. They are
tripwires and attribution canaries, not tamper resistance. A short stripper
written from the format specs recovers the payload.

## Requirements

- Rust 1.75 or newer to build. No runtime dependencies, no network calls.
- Memory: the tool loads artifacts fully in memory; budget about 2x the artifact
  size (a 512 MiB GGUF peaks near 1,026 MiB).
- Python 3.10+ only for `examples/make_fixtures.py` and the `lab/` suite.
