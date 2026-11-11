# Contributing

Issues and pull requests are welcome.

Ground rules:
- Zero dependencies. ThoxShield builds with `cargo build --release` and
  nothing else; PRs that add crates will be asked to justify why the
  standard library cannot do the job.
- Every shield change ships with a verify path and a fixture. Producer
  code never verifies itself in tests: assert against an independent
  parse (another tool, another language, or the format spec).
- Keep added-bytes honest: state the size delta of your change on the
  bundled fixtures in the PR description.
- Defensive use only; no features that target third-party software.
