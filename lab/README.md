# ThoxShield Virtual Test Lab

The empirical validation suite for the shields in the paper
"ThoxShield: Bloat-Capped Counter-REA Defense for Local-First AI
Artifacts" (v1.1.0, Section 7). It is deliberately independent of
ThoxShield's own code: fixtures are spec-correct (the synthetic GGUF
carries real tensor-info records), hardened outputs are re-read with
the reference implementations (gguf-py, the safetensors library, Node's
WebAssembly.validate), and every evidence item is computed — including
the strip test, which measures how cheaply the shields can be removed
and reports it as a limitation.

Run (needs a venv with gguf, safetensors, numpy, plus node):

    python3 -m venv .venv && .venv/bin/pip install gguf safetensors numpy
    cargo build --release
    .venv/bin/python lab/lab.py target/release/thoxshield ./lab-run

Optional: set THOXSHIELD_LAB_GGUF_SMALL / THOXSHIELD_LAB_GGUF_LARGE to
GGUF files you own for the production-scale items, and
THOXSHIELD_LAB_UPSTREAM_CLI to an upstream bla-agents CLI for the
same-fixture comparison. Unset items are recorded as skipped.

Evidence classes: MEASURED (observed quantity), STRUCTURAL (proven by
independent parsing), SIMULATED (a budgeted analyzer model; a live REA
run is future work and is not claimed). thoxshield's own `verify` is
labeled SELF-CHECK wherever it appears.
