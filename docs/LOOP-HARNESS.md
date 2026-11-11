# The agent-team loop harness

`thoxshield team <target> --out <dir> [--loops <n>]` runs the full
defense loop as a small team of generic roles in one deterministic
process (source: `src/team.rs`):

audit → gate on lint → harden → independent verify → report, repeated
until success, a blocking finding, or the iteration budget (default 3).

Design notes:

- **Loop engineering, not a framework.** No agent runtime, no model
  calls, no plug-in system. The harness shells its own CLI verbs as
  separate processes, so each role's work is the same work a human or
  an external agent would do by hand — see `harness/WORKORDER.md` for
  the protocol form.
- **Separation of duties is the point.** The verifier role re-runs the
  verify verb in a fresh process and its verdict alone closes the loop.
  The hardener's success line is treated as a claim, not a result.
- **State is a file, not a session.** `team-state.json` is rewritten
  after every loop; `team-report.json` and `team-log.md` close the run.
  Any agent can pick up, resume, or audit the run from those files.
- **Failure is a first-class output.** A stopped loop (lint block,
  verify failure, budget exhausted) still writes its report and exits
  non-zero. Silence is the only unacceptable result.
