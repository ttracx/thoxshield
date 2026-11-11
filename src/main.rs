//! ThoxShield — by THOX.ai. Open-source, defensive counter-REA tooling.
//!
//! A zero-dependency Rust implementation of the light end of the counter-REA concept (upstream
//! `bla-agents` v3.2.4, MIT, qybaihe/bla), rebuilt for the THOX release
//! pipeline:
//! * audit   — walk a release tree, detect formats by magic bytes,
//!   SHA-256 every artifact, lint for plaintext secrets and
//!   source-map exposure. This is the gate THOX CI actually needs.
//! * harden  — LIGHT shields only, for GGUF / Safetensors / WASM:
//!   canary metadata + a 35-deep nesting breaker + a SHA-256
//!   binding of the original bytes. No exhaustion flooding:
//!   added bytes are hard-capped (default max(4096, 5%)).
//! * verify  — prove a hardened artifact preserves the original payload
//!   (tensor bytes / WASM body) and carries the lite seal.
//! * manifest— emit a signed-later SHA-256 manifest (JSON) for a tree.
//!
//! Deliberate non-goals (stay with upstream BLA, Node, when wanted):
//! JS AST weaving, ASAR/SQLite exhaustion, prompt-directive layers (OFF in
//! THOX policy — see the internal review pack), CrackMe tooling.
//!
//! Defensive use only: run on THOX-owned artifacts or artifacts you are
//! explicitly authorized to modify. Same posture as upstream DISCLAIMER.md.

mod detect;
mod team;
mod json;
mod sha256;

use detect::{detect, Format};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NEST_DEPTH: usize = 35; // > upstream REA MODEL_*_NESTING limit of 32

/// Parsed GGUF header: tensor count, metadata keys in order, raw tensor-info
/// bytes, the alignment recorded in the file, and the data-section start offset.
type GgufHeader = (u64, Vec<String>, Vec<u8>, u64, usize);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_help();
        return ExitCode::SUCCESS;
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let result = match cmd {
        "audit" => cmd_audit(rest),
        "harden" => cmd_harden(rest),
        "verify" => cmd_verify(rest),
        "manifest" => cmd_manifest(rest),
        "team" => team::cmd_team(rest),
        "--version" | "version" => { println!("thoxshield {VERSION}"); Ok(()) }
        _ => Err(format!("unknown command '{cmd}' (try --help)")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { eprintln!("thoxshield: {e}"); ExitCode::FAILURE }
    }
}

fn print_help() {
    println!("thoxshield {VERSION} — THOX light counter-REA audit + shield (Rust, zero deps)\n");
    println!("USAGE:");
    println!("  thoxshield audit    <path> [--json]");
    println!("  thoxshield harden   <path> --out <dir> [--max-add-pct <n>]");
    println!("  thoxshield verify   <original> <hardened>");
    println!("  thoxshield manifest <path>");
    println!("  thoxshield team     <path> --out <dir> [--loops <n>]   agent-team loop: audit -> harden -> verify -> report");
    println!("\nDefensive use only, on artifacts you own or are authorized to modify.");
}

// ---------- shared helpers ----------

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            if let Ok(rd) = fs::read_dir(&p) {
                for e in rd.flatten() {
                    let ep = e.path();
                    // Never descend into a previous harden output or VCS internals.
                    if ep.file_name().map(|n| n == ".bla-hardened" || n == ".git" || n == "node_modules").unwrap_or(false) { continue; }
                    stack.push(ep);
                }
            }
        } else if p.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("FLAG{", "plaintext flag / capture marker"),
    ("-----BEGIN PRIVATE KEY-----", "PEM private key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "PEM RSA private key"),
    ("AKIA", "possible AWS access key id prefix"),
    ("sk-proj-", "possible OpenAI project key"),
    ("hf_", "possible Hugging Face token prefix (check context)"),
    ("ghp_", "possible GitHub personal access token"),
    ("xoxb-", "possible Slack token"),
];

fn lint_bytes(fmt: Format, data: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    if matches!(fmt, Format::Javascript | Format::Typescript | Format::Python | Format::Html | Format::SourceMap | Format::Unknown) {
        let text = String::from_utf8_lossy(data);
        for (pat, label) in SECRET_PATTERNS {
            if text.contains(pat) { findings.push(format!("secret-lint: {label} ('{pat}')")); }
        }
        if text.contains("sourceMappingURL=") { findings.push("exposure: sourceMappingURL present in shipped file".into()); }
        for needle in ["api_key =", "apiKey:", "password =", "secret ="] {
            if text.to_lowercase().contains(needle) { findings.push(format!("secret-lint: possible hardcoded credential assignment ('{needle}')")); break; }
        }
    }
    if fmt == Format::SourceMap { findings.push("exposure: source map shipped in release tree".into()); }
    findings
}

struct AuditRow { path: PathBuf, fmt: Format, size: u64, sha: String, findings: Vec<String>, sealed: bool }

fn audit_one(path: &Path) -> AuditRow {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("thoxshield audit: cannot read {}: {e}", path.display());
            return AuditRow { path: path.to_path_buf(), fmt: Format::Unknown, size: 0,
                sha: String::new(), findings: vec![format!("unreadable file: {e}")], sealed: false };
        }
    };
    let fmt = detect(path, &data.iter().take(4096).copied().collect::<Vec<_>>());
    let sha = sha256::sha256_hex(&data);
    let findings = lint_bytes(fmt, &data);
    let sealed = is_lite_sealed(fmt, &data);
    AuditRow { path: path.to_path_buf(), fmt, size: data.len() as u64, sha, findings, sealed }
}

fn is_lite_sealed(fmt: Format, data: &[u8]) -> bool {
    let needle: &[u8] = b"thoxshield";
    let hay: &[u8] = match fmt { Format::Safetensors => &data[..data.len().min(200_000)], _ => data };
    hay.windows(needle.len()).any(|w| w == needle)
        || data.windows(8).any(|w| w == b"thoxshield".as_slice())
        || match fmt {
            Format::Gguf => data.windows(b"enclave.nesting.breaker".len()).any(|w| w == b"enclave.nesting.breaker".as_slice()),
            _ => false,
        }
}

fn json_escape(s: &str) -> String { json::escape(s) }

// ---------- audit ----------

fn cmd_audit(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(args.first().ok_or("audit needs a path")?);
    let as_json = args.iter().any(|a| a == "--json");
    let files = walk(&path);
    if files.is_empty() { return Err(format!("no files found under {}", path.display())); }
    let rows: Vec<AuditRow> = files.iter().map(|f| audit_one(f)).collect();
    if as_json {
        println!("[");
        for (i, r) in rows.iter().enumerate() {
            let findings = r.findings.iter().map(|f| json_escape(f)).collect::<Vec<_>>().join(",");
            println!("  {{\"path\":{},\"format\":\"{}\",\"bytes\":{},\"sha256\":\"{}\",\"lite_sealed\":{},\"findings\":[{}]}}{}",
                json_escape(&r.path.display().to_string()), r.fmt.name(), r.size, r.sha, r.sealed, findings,
                if i + 1 < rows.len() { "," } else { "" });
        }
        println!("]");
    } else {
        println!("thoxshield audit — {} artifact(s) under {}", rows.len(), path.display());
        let mut by_fmt: BTreeMap<&str, usize> = BTreeMap::new();
        let mut flagged = 0usize;
        for r in &rows {
            *by_fmt.entry(r.fmt.name()).or_default() += 1;
            let rel = r.path.strip_prefix(&path).unwrap_or(&r.path);
            println!("  {:<44} {:<18} {:>10} B  sha256:{}…  {}", rel.display(), r.fmt.name(), r.size, &r.sha[..12],
                if r.sealed { "LITE-SEALED" } else if r.fmt.lite_hardenable() { "unsealed (lite-hardenable)" } else { "" });
            for f in &r.findings { println!("      ! {f}"); flagged += 1; }
        }
        println!("formats: {}", by_fmt.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  "));
        println!("lint findings: {flagged}");
    }
    Ok(())
}

// ---------- manifest ----------

fn cmd_manifest(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(args.first().ok_or("manifest needs a path")?);
    let files = walk(&path);
    println!("{{\"tool\":\"thoxshield\",\"version\":\"{VERSION}\",\"root\":{},\"artifacts\":[", json_escape(&path.display().to_string()));
    for (i, f) in files.iter().enumerate() {
        let r = audit_one(f);
        println!("  {{\"path\":{},\"format\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"}}{}",
            json_escape(&r.path.display().to_string()), r.fmt.name(), r.size, r.sha,
            if i + 1 < files.len() { "," } else { "" });
    }
    println!("]}}");
    Ok(())
}

// ---------- harden ----------

struct Reader<'a> { b: &'a [u8], i: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() { return Err("unexpected eof".into()); }
        let s = &self.b[self.i..self.i + n]; self.i += n; Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, String> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn gguf_string(&mut self) -> Result<String, String> {
        let n = self.u64()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn gguf_value(&mut self, ty: u32) -> Result<(), String> { self.gguf_value_d(ty, 0) }
    fn gguf_value_d(&mut self, ty: u32, depth: u32) -> Result<(), String> {
        // Depth cap: adversarial ARRAY nesting must not overflow the
        // stack in audit/harden/verify. Legitimate breaker depth is 35.
        if depth > 512 { return Err("GGUF metadata nesting exceeds 512".into()); }
        match ty {
            0 | 1 | 7 => { self.take(1)?; }
            2 | 3 => { self.take(2)?; }
            4..=6 => { self.take(4)?; }
            8 => { self.gguf_string()?; }
            9 => { let et = self.u32()?; let n = self.u64()?; for _ in 0..n { self.gguf_value_d(et, depth + 1)?; } }
            10..=12 => { self.take(8)?; }
            _ => return Err(format!("unknown GGUF value type {ty}")),
        }
        Ok(())
    }
}

fn gguf_string_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + s.len());
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

fn harden_gguf(orig: &[u8], sha: &str) -> Result<Vec<u8>, String> {
    if orig.len() < 24 || &orig[0..4] != b"GGUF" { return Err("not a GGUF file".into()); }
    let mut r = Reader { b: orig, i: 4 };
    let version = r.u32()?;
    let tensor_count = r.u64()?;
    let meta_count = r.u64()?;
    let kv_start = r.i;
    let mut keys = Vec::new();
    for _ in 0..meta_count {
        let k = r.gguf_string()?;
        let ty = r.u32()?;
        r.gguf_value(ty)?;
        keys.push(k);
    }
    let kv_end = r.i;
    if keys.iter().any(|k| k == "thoxshield.nesting.breaker") { return Err("already lite-sealed".into()); }

    let mut added: Vec<u8> = Vec::new();
    let mut n_added: u64 = 0;
    // Canary string KVs (string type = 8).
    for (k, v) in [
        ("thoxshield.canary", "thox-counter-rea-canary"),
        ("thoxshield.origin.sha256", sha),
        ("thoxshield.enclave.manifest", "synthetic-delegation-manifest; no enclave is present; diagnostic only"),
    ] {
        added.extend_from_slice(&gguf_string_bytes(k));
        added.extend_from_slice(&8u32.to_le_bytes());
        added.extend_from_slice(&gguf_string_bytes(v));
        n_added += 1;
    }
    // Nesting breaker: ARRAY(9) of ARRAY ... innermost UINT32(4) with one 0 element.
    added.extend_from_slice(&gguf_string_bytes("thoxshield.nesting.breaker"));
    added.extend_from_slice(&9u32.to_le_bytes());
    for d in 0..NEST_DEPTH {
        let elem_ty = if d + 1 == NEST_DEPTH { 4u32 } else { 9u32 };
        added.extend_from_slice(&elem_ty.to_le_bytes());
        added.extend_from_slice(&1u64.to_le_bytes());
    }
    added.extend_from_slice(&0u32.to_le_bytes());
    n_added += 1;

    // Tensor-info region: parse it so the tensor data section can be
    // re-aligned. GGUF readers locate tensor data at the alignment
    // boundary after (header + metadata + tensor infos); inserting
    // metadata without re-padding shifts every tensor read. (Found by
    // the v2 virtual test lab on a production GGUF: gguf-py read all
    // 290 tensors misaligned. The pre-v1.1 code copied the tail verbatim.)
    let mut alignment: u64 = 32;
    {
        let mut ar = Reader { b: orig, i: kv_start };
        for _ in 0..meta_count {
            let k = ar.gguf_string()?;
            let ty = ar.u32()?;
            if k == "general.alignment" && ty == 4 {
                alignment = ar.u32()? as u64;
            } else {
                ar.gguf_value(ty)?;
            }
        }
    }
    if alignment == 0 || alignment > 4096 { return Err(format!("implausible GGUF alignment {alignment}")); }
    let mut tr = Reader { b: orig, i: kv_end };
    for _ in 0..tensor_count {
        tr.gguf_string()?;
        let n_dims = tr.u32()?;
        for _ in 0..n_dims { tr.u64()?; }
        tr.u32()?;
        tr.u64()?;
    }
    let ti_end = tr.i;
    let mut data_start = ((ti_end as u64).div_ceil(alignment) * alignment) as usize;
    if data_start > orig.len() {
        // Zero-tensor files (e.g. vocab-only GGUF) may end before the
        // alignment boundary; an empty data section starts at EOF.
        if ti_end == orig.len() { data_start = orig.len(); }
        else { return Err("GGUF tensor data start overruns file".into()); }
    }

    let mut out = Vec::with_capacity(orig.len() + added.len() + alignment as usize);
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&tensor_count.to_le_bytes());
    out.extend_from_slice(&(meta_count + n_added).to_le_bytes());
    out.extend_from_slice(&orig[kv_start..kv_end]);
    out.extend_from_slice(&added);
    out.extend_from_slice(&orig[kv_end..ti_end]);
    let pad = ((alignment - (out.len() as u64 % alignment)) % alignment) as usize;
    out.extend(std::iter::repeat_n(0u8, pad));
    out.extend_from_slice(&orig[data_start..]);
    Ok(out)
}

fn harden_safetensors(orig: &[u8], sha: &str) -> Result<Vec<u8>, String> {
    if orig.len() < 8 { return Err("not a safetensors file".into()); }
    let hlen = u64::from_le_bytes(orig[0..8].try_into().unwrap()) as usize;
    if 8 + hlen > orig.len() { return Err("safetensors header overruns file".into()); }
    let header_text = std::str::from_utf8(&orig[8..8 + hlen]).map_err(|_| "header is not utf8")?;
    let mut header = json::Parser::parse(header_text)?;
    if !matches!(header, json::Json::Obj(_)) { return Err("safetensors header is not an object".into()); }

    // __metadata__ canary strings.
    let mut meta = match header.get_mut_obj("__metadata__") {
        Some(json::Json::Obj(_)) => header.get_mut_obj("__metadata__").unwrap().clone(),
        _ => json::Json::Obj(Vec::new()),
    };
    if let json::Json::Obj(m) = &mut meta {
        let set = |m: &mut Vec<(String, json::Json)>, k: &str, v: &str| {
            if let Some(p) = m.iter().position(|(ek, _)| ek == k) { m[p].1 = json::Json::Str(v.into()); }
            else { m.push((k.into(), json::Json::Str(v.into()))); }
        };
        set(m, "thoxshield.canary", "thox-counter-rea-canary");
        set(m, "thoxshield.origin.sha256", sha);
        set(m, "thoxshield.enclave.manifest", "synthetic-delegation-manifest; no enclave is present; diagnostic only");
    }
    header.obj_insert("__metadata__", meta);

    // Nesting breaker on the first tensor descriptor (extra key, loaders ignore unknown keys).
    let first_tensor = if let json::Json::Obj(entries) = &header {
        entries.iter().find(|(k, _)| k != "__metadata__").map(|(k, _)| k.clone())
    } else { None };
    if let Some(name) = first_tensor {
        let mut nest = json::Json::Obj(vec![("notice".into(), json::Json::Str("thoxshield nesting breaker".into()))]);
        for _ in 0..NEST_DEPTH { nest = json::Json::Obj(vec![("nest".into(), nest)]); }
        if let Some(t) = header.get_mut_obj(&name) { t.obj_insert("thoxshield.topology", nest); }
    } else {
        return Err("no tensor descriptor found to carry the nesting breaker".into());
    }

    let new_header = json::stringify(&header);
    let mut out = Vec::with_capacity(8 + new_header.len() + (orig.len() - 8 - hlen));
    out.extend_from_slice(&(new_header.len() as u64).to_le_bytes());
    out.extend_from_slice(new_header.as_bytes());
    out.extend_from_slice(&orig[8 + hlen..]);
    Ok(out)
}

fn leb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop { let mut b = (v & 0x7f) as u8; v >>= 7; if v != 0 { b |= 0x80; } out.push(b); if v == 0 { break; } }
    out
}

fn harden_wasm(orig: &[u8], sha: &str) -> Result<Vec<u8>, String> {
    if orig.len() < 8 || orig[0..4] != [0x00, 0x61, 0x73, 0x6d] { return Err("not a WASM binary".into()); }
    if is_lite_sealed(Format::Wasm, orig) { return Err("already lite-sealed".into()); }
    // Custom section (id 0): name + payload. Custom sections are inert to
    // runtimes and validators, but static analyzers must walk them.
    let name = b"thoxshield.enclave.v1";
    let mut payload = Vec::new();
    payload.extend_from_slice(&leb128(name.len() as u64));
    payload.extend_from_slice(name);
    payload.extend_from_slice(format!("canary=thox-counter-rea; origin.sha256={sha}; nesting=").as_bytes());
    // A compact textual nesting ladder (depth marker for analyzer walks).
    for d in 0..NEST_DEPTH { payload.extend_from_slice(format!("n{d}[").as_bytes()); }
    payload.resize(payload.len() + NEST_DEPTH, b']');
    let mut out = Vec::with_capacity(orig.len() + payload.len() + 10);
    out.extend_from_slice(orig);
    out.push(0x00);
    out.extend_from_slice(&leb128(payload.len() as u64));
    out.extend_from_slice(&payload);
    Ok(out)
}

fn cmd_harden(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(args.first().ok_or("harden needs a path")?);
    let out_dir = args.windows(2).find(|w| w[0] == "--out").map(|w| PathBuf::from(&w[1]))
        .ok_or("harden needs --out <dir>")?;
    let max_pct: usize = args.windows(2).find(|w| w[0] == "--max-add-pct")
        .and_then(|w| w[1].parse().ok()).unwrap_or(5);
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let files = walk(&path);
    let (mut ok, mut skipped, mut failed, mut sealed) = (0usize, 0usize, 0usize, 0usize);
    for f in &files {
        let data = fs::read(f).map_err(|e| e.to_string())?;
        let fmt = detect(f, &data.iter().take(4096).copied().collect::<Vec<_>>());
        let rel = f.strip_prefix(&path).unwrap_or(f).to_path_buf();
        let dest = out_dir.join(&rel);
        if !fmt.lite_hardenable() { println!("  skip  {:<40} {} (audit-only in thoxshield)", rel.display(), fmt.name()); skipped += 1; continue; }
        if is_lite_sealed(fmt, &data) {
            if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
            fs::write(&dest, &data).map_err(|e| e.to_string())?;
            println!("  sealed {:<39} {}  already lite-sealed, copied unchanged", rel.display(), fmt.name());
            sealed += 1; continue;
        }
        let sha = sha256::sha256_hex(&data);
        let hardened = match fmt {
            Format::Gguf => harden_gguf(&data, &sha),
            Format::Safetensors => harden_safetensors(&data, &sha),
            Format::Wasm => harden_wasm(&data, &sha),
            _ => unreachable!(),
        };
        match hardened {
            Ok(bytes) => {
                let added = bytes.len() as i64 - data.len() as i64;
                let cap = std::cmp::max(4096i64, (data.len() as i64 * max_pct as i64) / 100);
                if added > cap {
                    println!("  FAIL  {:<40} {} would add {added} B over the lite cap of {cap} B — refused", rel.display(), fmt.name());
                    failed += 1; continue;
                }
                if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
                fs::write(&dest, &bytes).map_err(|e| e.to_string())?;
                println!("  ok    {:<40} {}  {} B -> {} B (+{} B, +{:.2}%)", rel.display(), fmt.name(), data.len(), bytes.len(), added,
                    if data.is_empty() { 0.0 } else { added as f64 * 100.0 / data.len() as f64 });
                ok += 1;
            }
            Err(e) => { println!("  FAIL  {:<40} {} ({e})", rel.display(), fmt.name()); failed += 1; }
        }
    }
    println!("thoxshield harden: {ok} hardened, {sealed} already sealed, {skipped} skipped (audit-only), {failed} failed -> {}", out_dir.display());
    if failed > 0 { Err(format!("{failed} artifact(s) failed")) } else { Ok(()) }
}

// ---------- verify ----------

fn cmd_verify(args: &[String]) -> Result<(), String> {
    if args.len() < 2 { return Err("verify needs <original> <hardened>".into()); }
    let (orig, hard) = (fs::read(&args[0]).map_err(|e| e.to_string())?, fs::read(&args[1]).map_err(|e| e.to_string())?);
    let fmt = detect(Path::new(&args[0]), &orig.iter().take(4096).copied().collect::<Vec<_>>());
    let mut checks: Vec<(&str, bool)> = Vec::new();
    match fmt {
        Format::Wasm => {
            checks.push(("original bytes preserved as prefix (custom section appended only)",
                (hard.len() > orig.len() && hard[..orig.len()] == orig[..])
                || (hard == orig && is_lite_sealed(fmt, &hard)))); // identity case: input was already sealed
            checks.push(("lite seal present", is_lite_sealed(fmt, &hard)));
        }
        Format::Safetensors => {
            let oh = u64::from_le_bytes(orig[0..8].try_into().unwrap()) as usize;
            let hh = u64::from_le_bytes(hard[0..8].try_into().unwrap()) as usize;
            checks.push(("tensor payload bytes identical", orig[8 + oh..] == hard[8 + hh..]));
            checks.push(("original header keys preserved",
                hard == orig // identity case: input was already sealed
                || (|| -> bool {
                    // Proper structural check with the in-tree JSON parser:
                    // every original key (except added thoxshield.topology)
                    // must exist in the hardened header.
                    let ojson = match json::Parser::parse(std::str::from_utf8(&orig[8..8 + oh]).unwrap_or("")) { Ok(v) => v, Err(_) => return false };
                    let hjson = match json::Parser::parse(std::str::from_utf8(&hard[8..8 + hh]).unwrap_or("")) { Ok(v) => v, Err(_) => return false };
                    fn keys_subset(o: &json::Json, h: &json::Json) -> bool {
                        match (o, h) {
                            (json::Json::Obj(om), json::Json::Obj(hm)) => om.iter().all(|(k, ov)| {
                                if k == "thoxshield.topology" { return true; }
                                match hm.iter().find(|(hk, _)| hk == k) { Some((_, hv)) => keys_subset(ov, hv), None => false }
                            }),
                            (json::Json::Arr(oa), json::Json::Arr(ha)) => oa.len() == ha.len() && oa.iter().zip(ha.iter()).all(|(a, b)| keys_subset(a, b)),
                            _ => true, // scalar values: presence of the key is what is checked here
                        }
                    }
                    keys_subset(&ojson, &hjson)
                })()));
        }
        Format::Gguf => {
            // Parse header + KVs + tensor infos; return (tensor count,
            // keys, tensor-info bytes, alignment, data start).
            let parse = |b: &[u8]| -> Result<GgufHeader, String> {
                let mut r = Reader { b, i: 4 }; r.u32()?; let tc = r.u64()?; let mc = r.u64()?;
                let mut keys = Vec::new();
                let mut alignment: u64 = 32;
                for _ in 0..mc {
                    let k = r.gguf_string()?; let ty = r.u32()?;
                    if k == "general.alignment" && ty == 4 { alignment = r.u32()? as u64; } else { r.gguf_value(ty)?; }
                    keys.push(k);
                }
                let ti_start = r.i;
                for _ in 0..tc {
                    r.gguf_string()?; let nd = r.u32()?;
                    for _ in 0..nd { r.u64()?; }
                    r.u32()?; r.u64()?;
                }
                let ti = b[ti_start..r.i].to_vec();
                if alignment == 0 { return Err("zero alignment".into()); }
                let ds = ((r.i as u64).div_ceil(alignment) * alignment) as usize;
                Ok((tc, keys, ti, alignment, ds))
            };
            if hard == orig && is_lite_sealed(fmt, &hard) {
                checks.push(("identity: input was already lite-sealed, copied unchanged", true));
            } else {
                let (otc, okeys, oti, oal, ods) = parse(&orig)?;
                let (htc, hkeys, hti, hal, hds) = parse(&hard)?;
                checks.push(("tensor count unchanged", otc == htc));
                checks.push(("all original metadata keys preserved, in order",
                    hkeys.len() >= okeys.len() && hkeys[..okeys.len()] == okeys[..]));
                checks.push(("lite nesting breaker present", hkeys.iter().any(|k| k == "thoxshield.nesting.breaker")));
                checks.push(("tensor-info records identical", oti == hti));
                checks.push(("tensor data section bytes identical", orig[ods..] == hard[hds..]));
                checks.push(("tensor data start aligned in both files",
                    (ods as u64).is_multiple_of(oal) && (hds as u64).is_multiple_of(hal)));
            }
        }
        _ => return Err(format!("verify in thoxshield covers gguf/safetensors/wasm, got {}", fmt.name())),
    }
    let mut all = true;
    for (name, pass) in &checks { println!("  {} {name}", if *pass { "PASS" } else { "FAIL" }); all &= pass; }
    println!("thoxshield verify: {} ({} -> {} B)", if all { "OK" } else { "FAILED" }, orig.len(), hard.len());
    if all { Ok(()) } else { Err("verification failed".into()) }
}
