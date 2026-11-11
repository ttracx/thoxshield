# Changelog

## 0.1.2 — 2026-11-10

Systems-review fixes (THOX Research Team, systems seat):
- **Idempotent harden:** an already lite-sealed artifact is copied
  unchanged and reported as `sealed`, uniformly across GGUF,
  Safetensors, and WASM (previously GGUF/WASM refused and Safetensors
  silently re-sealed, which also broke the team loop on sealed trees).
  The team loop now succeeds on an already-sealed release tree.
- **Verify:** identity case (original already sealed) verifies
  explicitly; Safetensors gains a structural original-header-keys
  check via the JSON parser (key order was never guaranteed; a
  text-scan predecessor was removed).
- **GGUF parser depth cap (512):** adversarial ARRAY nesting can no
  longer overflow the stack in audit/harden/verify.
- **Audit:** unreadable files produce an explicit error finding and a
  stderr note instead of a silent hash of empty input.
- Known limitation (documented, not yet fixed): the tool loads
  artifacts fully in memory; peak RSS is about 2x the artifact size,
  so multi-GB models need matching RAM. Streaming is future work.

## 0.1.1 — 2026-11-10

- **Critical GGUF fix (found by the virtual test lab v2):** `harden`
  inserted metadata KVs and copied the remaining bytes verbatim, which
  shifted the tensor data section off its alignment boundary
  (`general.alignment`, default 32). Reference readers (gguf-py,
  llama.cpp) locate tensor data on that boundary, so a hardened real
  model read misaligned tensor bytes. The hardener now parses the
  tensor-info region and re-pads so the data section stays aligned;
  `verify` additionally checks tensor-info identity, data-section
  identity, and data-start alignment on both files. Verified end to
  end: a production 380 MB GGUF (290 tensors) loads in gguf-py after
  hardening with every tensor byte stream identical.
- Added `lab/`: the virtual test lab (spec-correct fixtures, reference
  readers, evidence classes, strip test reported as a limitation).
- Documentation: evidence and limitations write-up in
  `docs/EVIDENCE.md`; GGUF growth is now stated as 746 B of metadata
  adjusted by alignment re-padding (±31 B).

## 0.1.0 — 2026-11-10

- Initial release: `audit`, `harden`, `verify`, `manifest`, and the
  `team` loop harness. Light shields for GGUF, Safetensors, and WASM
  under a hard bloat cap (default max(4096 B, 5%)).
