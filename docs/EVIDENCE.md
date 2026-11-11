# Evidence and limitations

What the shields are proven to do, and what they are not. Full method:
the paper, Section 7, and the runnable suite in `lab/`.

Evidence classes: **MEASURED** (observed quantity), **STRUCTURAL**
(proven by independent parsing with reference implementations),
**SIMULATED** (a budgeted-analyzer model, labeled; not a live
reverse-engineering-agent run).

Highlights (thoxshield v0.1.1, virtual test lab v2):

- A production 380 MB GGUF (290 tensors) hardened and re-loaded with
  gguf-py: tensor table unchanged, every tensor byte stream identical,
  growth +736 B. A 1.7 MB vocab GGUF: +777 B. Growth is 746 B of
  metadata adjusted by alignment re-padding (±31 B).
- Safetensors hardened output loads in the reference safetensors
  library with all tensors numerically identical. Added bytes are
  fixture-dependent (578–619 B observed) because the header is
  rewritten; unlike GGUF/WASM this is not a constant.
- WASM: original bytes are a strict prefix; the module validates
  before and after. +303 B.
- Determinism: repeated hardening of the production GGUF is
  byte-identical.
- Simulated analyzer (SIMULATED): a GGUF walker that enforces a
  32-level nesting budget during traversal aborts on the nesting
  breaker at depth 33. A live REA run remains future work.

## Limitations, measured and stated plainly

- **Not tamper resistance.** A ~60-line stripper written from the
  format specs (no ThoxShield code) removes the shields and recovers
  the original payload — GGUF and WASM byte-exactly, Safetensors
  payload-exactly — in under a millisecond per artifact. The shields
  are budget tripwires for automated analyzers and attribution
  canaries. Anyone who tells you a client-side metadata shield is
  more than that is selling something.
- **The binding is also an oracle.** The embedded origin SHA-256 lets a
  stripper confirm a recovery is correct, and lets anyone match a
  shielded file against public unshielded models. Attribution and
  fingerprint are the same bytes; that is the accepted trade.
- **Visible margin.** The nesting breaker sits 3 levels above the
  published analyzer limit, in plain sight; analyzer authors can
  raise their budgets at zero cost. Open-sourcing accepts that
  bounded half-life deliberately.
- **Not secrecy.** A determined human analyst is unaffected.
  Real secrets belong on trusted infrastructure.
- **Cap note.** The bloat cap's refusal path cannot trigger with the
  current lite shields (their additions are always far below the
  4 KiB floor); it is a guardrail for future shields, not an active
  control today.

- **Memory.** The tool loads artifacts fully in memory; measured peak
  RSS is about 2x the artifact size (a 512 MiB GGUF peaks near
  1,026 MiB across audit/harden/verify). Budget RAM accordingly for
  multi-GB models; a streaming implementation is future work.
