#!/usr/bin/env python3
import os, sys, re, csv, base64, binascii, hashlib
import pefile
from argparse import ArgumentParser

def rc4(data, key):
    if isinstance(data, str): data = data.encode("utf-8")
    if isinstance(key, str):  key = key.encode("utf-8")
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for b in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def safe(v):
    if isinstance(v, bytes):
        return v.decode(errors="ignore").strip()
    if isinstance(v, str):
        return v.strip()
    return str(v).strip()

def count_before_four_consecutive_4_length(data, length=4, consec=4):
    c = 0
    for i, x in enumerate(data):
        if len(x) == length:
            c += 1
            if c == consec:
                return i - consec + 1
        else:
            c = 0
    return -1

def version_family(lines):
    k = count_before_four_consecutive_4_length(lines)
    return 201 if k == 4 else (200 if k == 3 else None)

def get_keys(lines, vfam):
    # First entry before the 4x4 block is a header we skip
    if lines:
        lines.pop(0)
    if vfam == 201:
        # v2.0.1 layout: build, rc4_traffic, rc4_static, then base64 list
        build, rc4_tr, rc4_st = map(safe, lines[:3])
        return build, rc4_tr, rc4_st, lines[3:], "2.0.1"
    if vfam == 200:
        # v2.0.0 / 2.1.1 / 2.1.2 layout: build, rc4_traffic, then base64 list
        build, rc4_tr = map(safe, lines[:2])
        return build, rc4_tr, "", lines[2:], "2.0.0 / 2.1.1 / 2.1.2"
    return "Unknown", "", "", lines, "Unknown"

def extract_config_from_file(path):
    # Quick MZ check to avoid pefile noise
    try:
        with open(path, "rb") as f:
            head = f.read(2)
            f.seek(0)
            data = f.read()
    except Exception:
        return None, "read_error"

    if head != b"MZ":
        return None, "not_pe"

    try:
        pe = pefile.PE(data=data)
    except Exception:
        return None, "pe_parse_error"

    rdata = next((s for s in pe.sections if s.Name.decode(errors="ignore").strip("\x00") == ".rdata"), None)
    if not rdata:
        return None, "no_rdata"

    blob = rdata.get_data()
    i = blob.find(b"string too long")
    if i == -1:
        return None, "marker_missing"
    blob = blob[i:]
    j = blob.find(b"aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYz")
    if j != -1:
        blob = blob[:j]

    lines = re.sub(b"\x00+", b"\n", blob).splitlines()

    vf = version_family(lines)
    build, rc4_tr, rc4_st, rest, version = get_keys(lines, vf)

    b64s = []
    for x in rest:
        try:
            b64s.append(base64.b64decode(x))
        except (binascii.Error, UnicodeDecodeError):
            continue

    dec = []
    for b in b64s:
        try:
            dec.append(rc4(b, safe(rc4_st)).decode(errors="ignore"))
        except Exception:
            pass

    # Expiry (first four strings commonly encode date parts)
    expiry = ""
    if len(dec) >= 4:
        expiry = f"{dec[0]}-{dec[1]}-{dec[2]}{dec[3]}"

    c2 = ""
    url_re = re.compile(r"^https?://[^\s\"']+$")
    php_re = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,24}/[^\s\"']+\.php$")
    for s in dec:
        s = s.strip()
        if url_re.match(s) or php_re.match(s):
            c2 = s
            break

    sha256 = hashlib.sha256(data).hexdigest()

    return {
        "file": os.path.basename(path),
        "sha256": sha256,
        "version": version,
        "build": build,
        "rc4_traffic": rc4_tr,
        "rc4_static": rc4_st,
        "expiry": expiry,
        "c2": c2
    }, "ok"

def print_neat_block(result, relpath):
    print(f"=== {relpath} ===")
    if result:
        print(f"[+] Version: {result['version']}")
        print(f"[+] Build ID: {result['build']}")
        print(f"[+] RC4 Traffic Key: {result['rc4_traffic']}")
        print(f"[+] RC4 Static String Key: {result['rc4_static']}")
        print(f"[+] Expiry: {result['expiry']}")
        print(f"[+] C2: {result['c2']}")
    else:
        print("[!] No config extracted")

def print_banner():
    print(r"""
  _________ __                .__  _________         ________   _________                _____.__        
 /   _____//  |_  ____ _____  |  | \_   ___ \  ___  _\_____  \  \_   ___ \  ____   _____/ ____\__| ____  
 \_____  \\   __\/ __ \\__  \ |  | /    \  \/  \  \/ //  ____/  /    \  \/ /  _ \ /    \   __\|  |/ ___\ 
 /        \|  | \  ___/ / __ \|  |_\     \____  \   //       \  \     \___(  <_> )   |  \  |  |  / /_/  >
/_______  /|__|  \___  >____  /____/\______  /   \_/ \_______ \  \______  /\____/|___|  /__|  |__\___  / 
        \/           \/     \/             \/                \/         \/            \/        /_____/  
          StealC v2 Configuration Extractor
                Author: Ben Hopkins
""")

def main():
    ap = ArgumentParser(description="StealC v2 config extractor — single file or directory mode")
    group = ap.add_mutually_exclusive_group(required=False)
    group.add_argument("--file", help="Path to a single StealC sample (PE file)")
    group.add_argument("--dir", help="Directory of candidate samples (unpacked PEs)")
    ap.add_argument("--output", help="Optional output CSV path (if omitted results print to terminal)")
    ap.add_argument("--quiet", action="store_true", help="Only write CSV (no per-file blocks)")

    # If no args provided, show banner + help
    if len(sys.argv) == 1:
        print_banner()
        ap.print_help(sys.stderr)
        sys.exit(1)

    args = ap.parse_args()

    # Require at least one mode
    if not (args.file or args.dir):
        ap.print_help(sys.stderr)
        sys.exit(1)

    # Build file list
    paths = []
    base_dir = "."
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        paths = [args.file]
        base_dir = os.path.dirname(args.file) or "."
    else:
        # dir mode
        if not os.path.isdir(args.dir):
            print(f"[!] Directory not found: {args.dir}")
            sys.exit(1)
        base_dir = args.dir
        for root, _, files in os.walk(args.dir):
            for fn in sorted(files):
                paths.append(os.path.join(root, fn))

    rows = []
    total = ok = 0

    for path in paths:
        total += 1
        res, status = extract_config_from_file(path)
        rel = os.path.relpath(path, base_dir)
        if status == "ok":
            rows.append(res)
            ok += 1
            if not args.quiet and not args.output:
                print_neat_block(res, rel)
        else:
            if not args.quiet and not args.output:
                print(f"=== {rel} ===")
                print(f"[!] No config extracted (reason: {status})")

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=["file","sha256","version","build","rc4_traffic","rc4_static","expiry","c2"]
            )
            w.writeheader()
            w.writerows(rows)

        print(f"[✓] Wrote {args.output} ({len(rows)} rows, {ok}/{total} extracted)")
    else:
        print(f"\n[✓] {ok}/{total} configs extracted (no CSV output)")

if __name__ == "__main__":
    main()
