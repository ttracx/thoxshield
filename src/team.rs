//! Agent-team loop harness.
//!
//! A lightweight loop-engineering system: five generic *roles* (not
//! personas, no model code, no agent framework) cooperate over a shared
//! workorder to take a release tree from audit to independently verified
//! shields. The harness itself is deterministic Rust; any external agent
//! (an LLM coding agent, a CI job, a human) can also drive the same loop
//! by following `harness/WORKORDER.md` and calling the same CLI verbs.
//!
//! Roles:
//!   coordinator — owns the loop, the state file, and the stop conditions
//!   auditor     — `audit --json`: inventory, hashes, lint findings
//!   hardener    — `harden`: applies light shields inside the bloat cap
//!   verifier    — `verify`: independent re-check; the hardener's output
//!                 is never taken on trust (producer != verifier)
//!   reporter    — writes team-report.json + team-log.md from the state
//!
//! Loop engineering rules:
//!   * Work is a workorder: a list of artifacts with a state per stage.
//!   * Each loop iteration runs audit -> harden -> verify over the
//!     ORIGINAL inputs (hardening is from-source every time, never
//!     stacked on a previous iteration's output).
//!   * The loop stops on: all artifacts verified (success), a lint
//!     finding that blocks release (stop, human/agent decision), or the
//!     iteration budget running out (failure, reported as such).
//!   * Everything the loop did is in the state file and the report, so
//!     any other agent can resume or audit the run afterwards.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn esc(s: &str) -> String { crate::json::escape(s) }

fn run_self(args: &[String]) -> (bool, String) {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("thoxshield"));
    match Command::new(exe).args(args).output() {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned()
            + &String::from_utf8_lossy(&o.stderr)),
        Err(e) => (false, format!("spawn failed: {e}")),
    }
}

#[derive(Default, Clone)]
struct ArtifactState {
    rel: String,
    format: String,
    hardenable: bool,
    lint_blocked: bool,
    hardened: bool,
    verified: bool,
    note: String,
}

pub fn cmd_team(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("team needs a path")?);
    let out_dir = args.windows(2).find(|w| w[0] == "--out").map(|w| PathBuf::from(&w[1]))
        .ok_or("team needs --out <dir>")?;
    let max_loops: usize = args.windows(2).find(|w| w[0] == "--loops")
        .and_then(|w| w[1].parse().ok()).unwrap_or(3);
    if max_loops == 0 || max_loops > 10 { return Err("--loops must be 1..=10".into()); }
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let hardened_dir = out_dir.join("hardened");
    let state_path = out_dir.join("team-state.json");
    let started = now_ms();

    let mut log: Vec<String> = vec![
        "# ThoxShield team loop log".into(),
        "".into(),
        format!("Target: `{}`  ", root.display()),
        format!("Started (unix ms): {started}"),
        "".into(),
    ];
    let mut artifacts: Vec<ArtifactState> = Vec::new();
    let mut loops_run = 0usize;
    let mut success = false;
    let mut stop_reason = String::new();

    for iteration in 1..=max_loops {
        loops_run = iteration;
        log.push(format!("## Loop {iteration}"));
        log.push("".into());

        // ---- Role: auditor -------------------------------------------------
        let (ok, audit_out) = run_self(&["audit".into(), root.display().to_string(), "--json".into()]);
        if !ok { stop_reason = "auditor stage failed".into(); log.push(format!("- auditor: FAILED\n```\n{audit_out}\n```")); break; }
        fs::write(out_dir.join(format!("audit-loop{iteration}.json")), &audit_out).map_err(|e| e.to_string())?;
        if iteration == 1 {
            // Parse the (machine-stable) audit JSON lines into the workorder.
            for line in audit_out.lines() {
                let line = line.trim().trim_end_matches(',');
                if !line.starts_with('{') { continue; }
                let get = |k: &str| -> String {
                    let pat = format!("\"{k}\":");
                    line.split(&pat).nth(1).map(|rest| {
                        let rest = rest.trim_start_matches('"');
                        rest.split('"').next().unwrap_or("").to_string()
                    }).unwrap_or_default()
                };
                let path = get("path");
                let rel = Path::new(&path).strip_prefix(&root).map(|p| p.display().to_string()).unwrap_or(path.clone());
                let fmt = get("format");
                let hardenable = line.contains("\"lite_sealed\":false") && matches!(fmt.as_str(), "model-gguf" | "model-safetensors" | "wasm")
                    || matches!(fmt.as_str(), "model-gguf" | "model-safetensors" | "wasm");
                let lint_blocked = line.contains("secret-lint") || line.contains("\"format\":\"sourcemap\"");
                artifacts.push(ArtifactState { rel, format: fmt, hardenable, lint_blocked, ..Default::default() });
            }
        }
        log.push(format!("- auditor: {} artifact(s) inventoried", artifacts.len()));

        // Blocking lint findings stop the loop before anything is hardened:
        // a release with a plaintext secret in it is not a shielding problem.
        let blocked: Vec<&ArtifactState> = artifacts.iter().filter(|a| a.lint_blocked).collect();
        if !blocked.is_empty() {
            stop_reason = format!("blocked by lint on {} artifact(s): {}", blocked.len(),
                blocked.iter().map(|a| a.rel.clone()).collect::<Vec<_>>().join(", "));
            log.push(format!("- coordinator: STOP — {stop_reason}"));
            break;
        }

        // ---- Role: hardener ------------------------------------------------
        let (ok, harden_out) = run_self(&["harden".into(), root.display().to_string(),
            "--out".into(), hardened_dir.display().to_string()]);
        for a in artifacts.iter_mut() {
            // "ok" = newly shielded this run; "sealed" = already sealed,
            // copied unchanged (idempotent re-runs of the loop on a sealed
            // tree are success, not failure).
            a.hardened = harden_out.lines().any(|l| {
                let t = l.trim_start();
                (t.starts_with("ok") || t.starts_with("sealed")) && l.contains(&a.rel)
            });
            if !a.hardened && a.hardenable { a.note = "hardener did not report success for this artifact".into(); }
        }
        log.push(format!("- hardener: {} ({} artifact(s) shielded)", if ok { "ok" } else { "FAILED" },
            artifacts.iter().filter(|a| a.hardened).count()));
        if !ok { stop_reason = "hardener stage failed".into(); log.push(format!("```\n{harden_out}\n```")); break; }

        // ---- Role: verifier (independent of the hardener) ------------------
        let mut all_verified = true;
        for a in artifacts.iter_mut() {
            if !a.hardenable { a.verified = true; continue; } // audit-only formats: nothing to verify
            let (vok, vout) = run_self(&["verify".into(),
                root.join(&a.rel).display().to_string(),
                hardened_dir.join(&a.rel).display().to_string()]);
            a.verified = vok && vout.contains("verify: OK");
            if !a.verified { all_verified = false; a.note = "verifier rejected the hardened artifact".into(); }
        }
        log.push(format!("- verifier: {}", if all_verified { "ALL VERIFIED" } else { "some artifacts failed verification" }));

        write_state(&state_path, &artifacts, iteration, started)?;
        if all_verified { success = true; stop_reason = "all hardenable artifacts verified".into(); break; }
        if iteration == max_loops { stop_reason = "iteration budget exhausted without full verification".into(); }
    }

    // ---- Role: reporter ------------------------------------------------------
    let ended = now_ms();
    let mut report = String::from("{\n");
    report.push_str(&format!("  \"tool\": \"thoxshield-team\", \"version\": \"{}\",\n", crate::VERSION));
    report.push_str(&format!("  \"target\": {}, \"loops_run\": {}, \"success\": {}, \"stop_reason\": {},\n",
        esc(&root.display().to_string()), loops_run, success, esc(&stop_reason)));
    report.push_str(&format!("  \"started_unix_ms\": {}, \"ended_unix_ms\": {},\n", started, ended));
    report.push_str("  \"artifacts\": [\n");
    for (i, a) in artifacts.iter().enumerate() {
        report.push_str(&format!("    {{\"path\": {}, \"format\": {}, \"hardenable\": {}, \"lint_blocked\": {}, \"hardened\": {}, \"verified\": {}, \"note\": {}}}{}\n",
            esc(&a.rel), esc(&a.format), a.hardenable, a.lint_blocked, a.hardened, a.verified, esc(&a.note),
            if i + 1 < artifacts.len() { "," } else { "" }));
    }
    report.push_str("  ]\n}\n");
    fs::write(out_dir.join("team-report.json"), &report).map_err(|e| e.to_string())?;
    log.push("".into());
    log.push(format!("## Result: {} — {}", if success { "SUCCESS" } else { "STOPPED" }, stop_reason));
    fs::write(out_dir.join("team-log.md"), log.join("\n")).map_err(|e| e.to_string())?;

    println!("thoxshield team: {} after {} loop(s) — {}", if success { "SUCCESS" } else { "STOPPED" }, loops_run, stop_reason);
    println!("  report: {}", out_dir.join("team-report.json").display());
    println!("  log:    {}", out_dir.join("team-log.md").display());
    println!("  shields: {}", hardened_dir.display());
    if success { Ok(()) } else { Err(stop_reason) }
}

fn write_state(path: &Path, artifacts: &[ArtifactState], iteration: usize, started: u128) -> Result<(), String> {
    let mut s = format!("{{\"loop\": {iteration}, \"started_unix_ms\": {started}, \"artifacts\": [");
    for (i, a) in artifacts.iter().enumerate() {
        s.push_str(&format!("{{\"path\": {}, \"hardened\": {}, \"verified\": {}}}{}",
            esc(&a.rel), a.hardened, a.verified, if i + 1 < artifacts.len() { "," } else { "" }));
    }
    s.push_str("]}");
    fs::write(path, s).map_err(|e| e.to_string())
}
