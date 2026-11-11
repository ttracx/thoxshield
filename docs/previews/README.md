# Previews

Terminal captures from the released binary. These are verbatim transcripts of
real runs, not mockups and not fixture screens.

- `audit-harden-verify.txt` — inventory, hardening with measured growth, and the
  independent verification checks for all three formats.
- `team-loop.txt` — the five-role agent-team loop reaching success, then
  stopping correctly on a lint-blocked tree.

Environment for every capture: Linux x86-64 (KnightHub WSL), rustc 1.99.1,
`cargo build --release`, artifacts from `examples/make_fixtures.py`.

Regenerate:

```bash
cargo build --release
python3 examples/make_fixtures.py
./target/release/thoxshield audit  fixtures
./target/release/thoxshield harden fixtures --out shielded
./target/release/thoxshield verify fixtures/model.gguf shielded/model.gguf
./target/release/thoxshield team   fixtures --out teamrun
```
