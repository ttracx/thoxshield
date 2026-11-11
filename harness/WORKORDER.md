# ThoxShield loop workorder — for external agents

Any agent (LLM coding agent, CI system, human) can run the ThoxShield
team loop without the built-in harness by following this protocol. The
built-in `thoxshield team` command executes exactly these steps.

## Roles

coordinator, auditor, hardener, verifier, reporter. One agent may hold
several roles, except: **the verifier must not be the hardener.** Verify
with fresh eyes or a fresh process, every time.

## The loop (budget: 3 iterations unless the coordinator sets otherwise)

1. **auditor** — `thoxshield audit <target> --json`. Save the output.
   Build the workorder: one row per artifact (path, format, hardenable,
   lint findings).
2. **coordinator gate** — if any artifact carries a blocking lint
   finding (plaintext secret, shipped source map), STOP. Report the
   finding. Do not harden over a secret.
3. **hardener** — `thoxshield harden <target> --out <out>/hardened`.
   Always harden from the original inputs, never from a previous
   iteration's output.
4. **verifier** — for each hardenable artifact:
   `thoxshield verify <original> <hardened>`. All must print OK.
5. **coordinator** — all verified: exit the loop (success). Any failure:
   record the reason in the state file and run the next iteration. Out
   of iterations: report failure as failure.
6. **reporter** — write `team-report.json` (target, loops run, success,
   stop reason, per-artifact states) and `team-log.md` (what each role
   did, in order). A run without a report did not happen.

## Rules

- Defensive use only, on the operator's own artifacts.
- Never widen the bloat cap to make a failure pass; record it instead.
- Never quote modeled token-amplification numbers as measurements.
