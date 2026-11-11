# User guide

Reference for every ThoxShield command, the JSON each one emits, and the exit
code you can gate CI on. Everything here is observed behavior of v0.1.2 on the
shipped fixtures; nothing is projected.

## Command surface

```
thoxshield <verb> [args]

audit    <path> [--json]                       inventory, hash, secret-lint a tree
harden   <path> --out <dir> [--max-add-pct <n>] apply light shields into a new dir
verify   <original> <hardened>                 independent check of one artifact pair
manifest <path>                                deterministic JSON inventory + SHA-256
team     <path> --out <dir> [--loops <n>]      audit -> harden -> verify -> report loop
```

`thoxshield --help` and `thoxshield --version` print and exit 0. `--version`
reports the compiled package version (`CARGO_PKG_VERSION`), so a binary always
identifies itself truthfully against the release it came from.

Run it on software you own or are explicitly authorized to modify. That is the
only supported use.

## audit

Walks the tree (skipping `.git`, `node_modules`, and any prior `.bla-hardened`
output), identifies each file by magic bytes, SHA-256s it, and lints it.

Formats recognized: GGUF, Safetensors, WebAssembly, JS/TS, source maps, Python,
SQLite, ASAR, ELF, PE, Mach-O, DEX, BEAM, PCAP, ZIP, plist. Anything else is
reported as `unknown` — still hashed, never guessed.

Lint patterns include PEM private keys, AWS access-key prefixes, and capture
flags. A finding is reported per file with its pattern name.

```
thoxshield audit fixtures
thoxshield audit fixtures --json > audit.json
```

Exit code: 0 even when lint findings exist. Audit is an inventory verb; the
findings are in the output and in the JSON for a caller to gate on. A path that
cannot be read exits 1.

## harden

Copies the tree into `--out` and applies the light shields to the hardenable
formats, reading from the original inputs every time. Inputs are never modified.

| Format | Shield applied |
|---|---|
| GGUF | canary KV pair, 35-deep metadata array nesting breaker, origin SHA-256 binding |
| Safetensors | canary metadata, nesting breaker, origin header binding |
| WASM | inert custom section carrying canary, origin hash, original byte length |

Measured cost on the shipped fixtures: GGUF +736 B, Safetensors +600 B,
WASM +303 B. The bloat cap (`--max-add-pct`, default 5, with a 4 KiB floor)
is a guardrail for future shields; the current lite shields never approach it.

Already-sealed artifacts are copied unchanged and reported as `sealed`. That is
idempotent by design: hardening a sealed tree succeeds instead of refusing.

Audit-only formats are copied through untouched and reported as `skipped`.

Exit code: 0 on success, 1 on any failure.

## verify

Takes one original and one hardened file and checks the properties that matter
for that format. This is the verdict that closes a loop — the hardener never
certifies its own output.

GGUF checks: tensor count unchanged, original metadata keys preserved in order,
nesting breaker present, tensor-info records identical, tensor data bytes
identical, tensor data start aligned in both files.

Safetensors checks: tensor payload bytes identical, original header keys
preserved.

WASM checks: original bytes preserved as a strict prefix, seal present.

```
thoxshield verify dist/model.gguf dist-shielded/model.gguf
```

Exit code: 0 when every check passes, 1 otherwise.

## manifest

Emits deterministic JSON: tool, version, root, and per-artifact path, format,
byte size and SHA-256. Use it as the record of what actually shipped.

```json
{"tool":"thoxshield","version":"0.1.2","root":"shielded","artifacts":[
  {"path":"shielded/core.wasm","format":"wasm","bytes":334,"sha256":"44dad7b7…"},
  {"path":"shielded/model.gguf","format":"model-gguf","bytes":976,"sha256":"6e0fb641…"}
]}
```

Exit code: 0 on success, 1 if the tree cannot be read.

## team

The agent-team loop: coordinator, auditor, hardener, verifier, reporter, over
the same CLI verbs, with a resumable state file. It runs audit, hardens into
`<out>/hardened`, verifies every artifact, and writes `team-report.json`,
`team-log.md` and `team-state.json`.

Stop conditions, exactly three:

| Condition | Meaning | Exit |
|---|---|---|
| all hardenable artifacts verified | success | 0 |
| blocking lint finding (for example a plaintext secret) | stop; this is not a shielding problem | 1 |
| iteration budget exhausted (`--loops`, default 3) | failure, reported as such | 1 |

An external agent, a CI job, or a human can drive the identical loop by
following `harness/WORKORDER.md`. See [LOOP-HARNESS.md](LOOP-HARNESS.md).

## Reading the results honestly

The shields are tripwires and attribution canaries inside a hard bloat cap.
They are not tamper resistance, not secrecy, and not an enclave. A short
stripper written from the public format specs removes them and recovers the
payload in under a millisecond per artifact. The embedded origin hash doubles
as a correctness oracle for that stripper. This trade is deliberate and
documented in [EVIDENCE.md](EVIDENCE.md) — read it before quoting the tool as
protection of any stronger kind.

Memory: artifacts are loaded fully in memory, peak RSS about 2x artifact size.
A streaming implementation is future work.

## Troubleshooting

- `thoxshield: cannot read <path>` — the path does not exist or is not readable;
  audit continues past other files and exits 1.
- `verify` fails on an unsealed original against itself — expected, there is no
  seal to confirm. Verify the hardened copy, not the input.
- `team` reports `already sealed` — the output tree was hardened in a previous
  run; that is success, not a skip.
