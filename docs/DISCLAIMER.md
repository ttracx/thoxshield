# Disclaimer

ThoxShield is a defensive software-protection toolkit for software you own
or are explicitly authorized to modify and distribute. It is not a tool
for attacking, probing, or reverse-engineering third-party software.

Protective payloads (canary metadata, nesting breakers, origin-hash
bindings) are inert under normal execution and preserve the original
artifact's payload. No client-side protection can guarantee secrecy
against a dedicated analyst with unlimited time; keep high-value secrets
on trusted server infrastructure. Verify shielded artifacts in staging
before shipping (`thoxshield verify`, plus your own test suite).
