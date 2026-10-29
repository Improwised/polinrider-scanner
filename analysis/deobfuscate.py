#!/usr/bin/env python3
"""Statically unpack a "global.o='N-NNNN-du'" worm sample. Nothing is executed.

The obfuscator is polymorphic (names, seeds and constants change per build),
so every constant is parsed out of the code's structure rather than hard-coded.

usage: python3 -I deobfuscate.py SAMPLE_FILE [OUT_DIR]
SAMPLE_FILE may be a whole infected source file; the payload is located in it.
Writes stage1.js, stage2.js and stage2_clear.js (string table inlined) to
OUT_DIR, and prints the extracted indicators as JSON.
"""
import base64, json, os, re, sys

QSTR = r"'((?:[^'\\]|\\.)*)'"
DSTR = r'"((?:[^"\\]|\\.)*)"'


def js_unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c); i += 1; continue
        n = s[i + 1]
        if n == "x":
            out.append(chr(int(s[i + 2:i + 4], 16))); i += 4
        elif n == "u":
            out.append(chr(int(s[i + 2:i + 6], 16))); i += 6
        else:
            out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(n, n)); i += 2
    return "".join(out)


def swap_shuffle(s, seed, a, b, c, d, mod):
    """The obfuscator's in-place pseudo-random swap permutation."""
    z, q, w = list(s), len(s), seed
    for i in range(q):
        x = w * (i + a) + (w % b)
        y = w * (i + c) + (w % d)
        z[x % q], z[y % q] = z[y % q], z[x % q]
        w = (x + y) % mod
    return "".join(z)


def find_payload(text):
    m = re.search(r'eval\("global\.o=\'([^\']*)\';"\+atob\(\'([A-Za-z0-9+/=]+)\'\)\)', text)
    if m:
        return m.group(1), base64.b64decode(m.group(2)).decode()
    m = re.search(r"global\.o='([^']*)';(var _\$_[0-9a-f]+=.*)", text)
    if m:
        return m.group(1), m.group(2)
    raise SystemExit("no payload found")


def string_table(code):
    """var _$_xxxx=(function(q,w){...shuffle...})("...",SEED); -> (name, list, end)"""
    m = re.search(
        r"var (_\$_[0-9a-f]+)=\(function\((\w+),(\w+)\)\{.*?"
        r"var \w+=\3\* \(\w+\+ (\d+)\)\+ \(\3% (\d+)\);var \w+=\3\* \(\w+\+ (\d+)\)\+ \(\3% (\d+)\);.*?"
        r"\3= \(\w+\+ \w+\)% (\d+)\};(.*?)return \w+\.join\(\w+\)(.*?)\}\)\(" + DSTR + r",(\d+)\);", code, re.S)
    if not m:
        raise SystemExit("string table not found")
    name = m.group(1)
    a, b, c, d, mod = map(int, m.group(4, 5, 6, 7, 8))
    raw = swap_shuffle(js_unescape(m.group(11)), int(m.group(12)), a, b, c, d, mod)
    # .split(X).join(Y) chain, with X/Y resolved from the local var declarations
    vars_ = {k: js_unescape(v) for k, v in re.findall(r"var (\w+)=" + QSTR, m.group(9))}
    vars_.update({k: chr(int(v)) for k, v in re.findall(r"var (\w+)=String\.fromCharCode\((\d+)\)", m.group(9))})
    chain = re.findall(r"\.split\((\w+)\)\.join\((\w+)\)", m.group(10))
    for x, y in chain:
        raw = raw.replace(vars_[x], vars_[y])
    last = re.search(r"\.split\((\w+)\)$", m.group(10)).group(1)
    return name, raw.split(vars_[last]), m.end()


def inline(code, name, table):
    return re.sub(re.escape(name) + r"\[0x([0-9a-f]+)\]", lambda mm: repr(table[int(mm.group(1), 16)]), code)


def stage2_source(stage1):
    m = re.search(
        r"function (\w+)\((\w+)\)\{var (\w+)=(\d+);.*?"
        r"var \w+=\3\*\(\w+\+(\d+)\)\+\(\3%(\d+)\);var \w+=\3\*\(\w+\+(\d+)\)\+\(\3%(\d+)\);.*?"
        r"\3=\(\w+\+\w+\)%(\d+);\};return", stage1, re.S)
    if not m:
        raise SystemExit("loader shuffle not found")
    fn = m.group(1)
    seed, a, b, c, d, mod = map(int, m.group(4, 5, 6, 7, 8, 9))
    shuf = lambda s: swap_shuffle(js_unescape(s), seed, a, b, c, d, mod)
    dec_var = re.search(r"\w+\(\w+," + fn + r"\((\w+)\)\)", stage1).group(1)
    decoder_src = shuf(re.search(r"var " + dec_var + "=" + QSTR, stage1).group(1))
    blob = shuf(re.search(r"\w+\(" + fn + r"\(" + QSTR + r"\)\)", stage1).group(1))
    return decompress(decoder_src, blob), decoder_src


def decompress(src, arg):
    """Port of the generated dictionary decompressor; constants parsed from src."""
    ints = dict(re.findall(r"(\w+)=(\d+)", re.search(r"var ([^;]*);", src).group(1)))
    # constants get adjusted once ("j+=21;t+=60;...") right before the main loop
    prologue = src[:src.index("for(var", src.index(".length;"))]
    for k, v in re.findall(r"(\w+)\+=(\d+);", prologue):
        if k in ints:
            ints[k] = int(ints[k]) + int(v)
    ints = {k: int(v) for k, v in ints.items()}
    n = list(map(int, re.search(r"var \w+=\[([\d,]+)\];var \w+=\[\];for", src).group(1).split(",")))
    m = re.search(r"\((\w+)-1\)\*(\w+)\+\w+\.charCodeAt\(\w+\+1\)-(\w+);", src)
    mult, sub = ints[m.group(2)], ints[m.group(3)]
    esc = ints[re.search(r"else if\(\w+==(\w+)\)", src).group(1)]
    alpha = re.search(r'var \w+="([a-z]+)";', src).group(1)
    k = list(map(int, re.search(r"var \w+=\[([\d,]+)\]\.concat", src).group(1).split(","))) + n
    dot = chr(int(re.search(r"String\.fromCharCode\((\d+)\);for", src).group(1)))
    final = re.search(r'split\(\w+\+"(.)"\)\.join\(\w+\);$', src).group(1)
    b = {v: i + 1 for i, v in enumerate(n)}
    z = arg.split(" ")
    for e in range(len(z) - 1, -1, -1):
        r, parts, h, w, g = z[e], None, 0, 0, len(z[e])
        while w < g:
            ch = ord(r[w]); y = b.get(ch)
            if y:
                s = (y - 1) * mult + ord(r[w + 1]) - sub; p = w; w += 1
            elif ch == esc:
                s = mult * (len(n) - sub + ord(r[w + 1])) + ord(r[w + 2]) - sub; p = w; w += 2
            else:
                w += 1; continue
            parts = parts or []
            if p > h:
                parts.append(r[h:p])
            parts.append(z[s + 1]); h = w + 1; w += 1
        if parts is not None:
            if h < g:
                parts.append(r[h:])
            z[e] = "".join(parts)
    o = z[0]
    for i in range(len(k)):
        o = o.replace(dot + alpha[i], chr(k[i]))
    return o.replace(dot + final, dot)


def indicators(clear, table):
    hosts = sorted({s for s in table if re.fullmatch(r"[a-z0-9.-]+\.(com|org|io|net)", s)})
    key = re.search(r"await \w+\(" + QSTR + r",parseInt\(", clear)
    return {
        "rpc_hosts": hosts,
        "wallet_substring": next((s for s in table if re.fullmatch(r"[0-9a-f]{32}", s)), None),
        "xor_key": js_unescape(key.group(1)) if key else None,
        "payload_separator": next((s for s in table if s in ("?.?",) or re.fullmatch(r"\W\.\W", s or "")), None),
        "globals_set": sorted({s for s in table if re.fullmatch(r"_p_t|ix|_\w+", s)}),
    }


def main():
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    out = sys.argv[2] if len(sys.argv) > 2 else "."
    os.makedirs(out, exist_ok=True)
    marker, stage1 = find_payload(text)
    t1name, t1, _ = string_table(stage1)
    stage2, _ = stage2_source(stage1)
    t2name, t2, end = string_table(stage2)
    clear = inline(stage2[end:], t2name, t2)
    for fn, body in (("stage1.js", stage1), ("stage2.js", stage2), ("stage2_clear.js", clear)):
        open(os.path.join(out, fn + ".INERT"), "w").write(body)
    print(json.dumps({"marker": marker, "stage1_table": t1name, "stage1_strings": t1,
                      "stage2_table": t2name, **indicators(clear, t2)}, indent=1))


if __name__ == "__main__":
    main()
