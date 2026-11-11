# Security Policy

ThoxShield is a defensive tool. Report vulnerabilities in ThoxShield itself
through GitHub's private vulnerability reporting on this repository. Do not
open public issues for security reports.

Scope notes:
- ThoxShield never makes network connections and never executes the
  artifacts it processes. It reads bytes, rewrites three formats
  (GGUF, Safetensors, WASM) under a bloat cap, and hashes the rest.
- Always run `thoxshield verify <original> <hardened>` (or the `team`
  loop, which verifies for you) and your own test suite before shipping a
  shielded artifact.
- Shielding is defense-in-depth, not secrecy: do not embed real secrets
  in client artifacts, shielded or not.
