// Format detection ported in spirit from upstream BLA src/core/detector.ts
// (MIT), trimmed to the formats THOX actually ships plus common release files.
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Gguf, Safetensors, Wasm, Sqlite, Asar, Elf, MachO, Pe, Dex, Pyc, Beam, Pcap,
    Zip, Plist, Javascript, Typescript, Python, SourceMap, Html, Unknown,
}
impl Format {
    pub fn name(&self) -> &'static str {
        match self {
            Format::Gguf => "model-gguf", Format::Safetensors => "model-safetensors",
            Format::Wasm => "wasm", Format::Sqlite => "sqlite", Format::Asar => "electron-asar",
            Format::Elf => "native-elf", Format::MachO => "native-macho", Format::Pe => "native-pe",
            Format::Dex => "android-dex", Format::Pyc => "python-pyc", Format::Beam => "erlang-beam",
            Format::Pcap => "pcap-capture", Format::Zip => "archive-zip", Format::Plist => "apple-plist",
            Format::Javascript => "javascript", Format::Typescript => "typescript",
            Format::Python => "python-source", Format::SourceMap => "sourcemap",
            Format::Html => "html-bundle", Format::Unknown => "unknown",
        }
    }
    /// Formats thoxshield can harden itself (light shields). Everything else is audit-only in lite.
    pub fn lite_hardenable(&self) -> bool { matches!(self, Format::Gguf | Format::Safetensors | Format::Wasm) }
}

pub fn detect(path: &Path, header: &[u8]) -> Format {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let h = header;
    if h.len() >= 6 && &h[0..6] == b"bplist" { return Format::Plist; }
    if h.len() >= 16 && &h[0..16] == b"SQLite format 3\0" { return Format::Sqlite; }
    if h.len() >= 4 && &h[0..4] == b"GGUF" { return Format::Gguf; }
    if h.len() >= 4 && &h[0..4] == b"dex\n" { return Format::Dex; }
    if h.len() >= 4 && h[0..4] == [0x00, 0x61, 0x73, 0x6d] { return Format::Wasm; }
    if h.len() >= 4 && h[0..4] == [0x7f, b'E', b'L', b'F'] { return Format::Elf; }
    if h.len() >= 4 {
        let be = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
        if matches!(be, 0xfeedface | 0xfeedfacf | 0xcafebabe | 0xcefaedfe | 0xcffaedfe) && ext != "class" { return Format::MachO; }
    }
    if h.len() >= 2 && &h[0..2] == b"MZ" { return Format::Pe; }
    if h.len() >= 4 && &h[0..4] == b"PK\x03\x04" { return if ext == "apk" { Format::Dex } else { Format::Zip }; }
    if h.len() >= 12 && &h[0..4] == b"FOR1" && &h[8..12] == b"BEAM" { return Format::Beam; }
    if h.len() >= 4 {
        let le = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        if matches!(le, 0xa1b2c3d4 | 0xa1b23c4d | 0xd4c3b2a1 | 0x0a0d0d0a) { return Format::Pcap; }
    }
    if ext == "safetensors" { return Format::Safetensors; }
    if h.len() >= 10 && h[8] == b'{' && h[9] == b'"' {
        let n = u64::from_le_bytes(h[0..8].try_into().unwrap());
        if n > 2 && n < 100_000_000 { return Format::Safetensors; }
    }
    if ext == "asar" { return Format::Asar; }
    if ext == "pyc" { return Format::Pyc; }
    match ext.as_str() {
        "js" | "mjs" | "cjs" | "jsx" => Format::Javascript,
        "ts" | "mts" | "cts" | "tsx" => Format::Typescript,
        "py" | "pyw" => Format::Python,
        "map" => Format::SourceMap,
        "html" | "htm" => Format::Html,
        "wasm" => Format::Wasm,
        "gguf" => Format::Gguf,
        "sqlite" | "sqlite3" => Format::Sqlite,
        "plist" | "entitlements" | "mobileprovision" => Format::Plist,
        "beam" => Format::Beam,
        "pcap" | "pcapng" | "cap" => Format::Pcap,
        _ => Format::Unknown,
    }
}
