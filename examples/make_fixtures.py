#!/usr/bin/env python3
"""Generate the three shieldable fixtures used in the paper's experiments:
a minimal GGUF v3 file, a minimal Safetensors file, and a minimal valid
WASM module. Run: python3 examples/make_fixtures.py ./fixtures"""
import json, struct, sys, os
d = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
os.makedirs(d, exist_ok=True)
def gstr(s):
    b = s.encode(); return struct.pack("<Q", len(b)) + b
kv = gstr("general.name") + struct.pack("<I", 8) + gstr("thox-test-model")
kv += gstr("general.architecture") + struct.pack("<I", 8) + gstr("llama")
kv += gstr("llama.context_length") + struct.pack("<I", 4) + struct.pack("<I", 2048)
ti = gstr("token_embd.weight") + struct.pack("<I", 1) + struct.pack("<Q", 4) + struct.pack("<I", 0) + struct.pack("<Q", 0)
body = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 1) + struct.pack("<Q", 3) + kv + ti
pad = (32 - (len(body) % 32)) % 32
open(f"{d}/model.gguf", "wb").write(body + b"\x00" * pad + struct.pack("<4f", 1, 2, 3, 4))
hdr = {"weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
       "bias": {"dtype": "F32", "shape": [2], "data_offsets": [16, 24]},
       "__metadata__": {"format": "pt"}}
hj = json.dumps(hdr).encode()
open(f"{d}/model.safetensors", "wb").write(struct.pack("<Q", len(hj)) + hj + struct.pack("<6f", 1, 2, 3, 4, 5, 6))
wasm = bytes([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 5, 3, 1, 0, 1,
              7, 10, 1, 6, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 2, 0])
open(f"{d}/core.wasm", "wb").write(wasm)
print("fixtures written to", d)
