#!/usr/bin/env python3
"""Slip Three - check the uplink.

Fetches the signed run, verifies every signature and every link in the chain,
and tells you whether the next check is overdue. Standard library only: no
installs, no accounts, nothing of yours leaves your machine.

    python3 check_slip_three.py

If it says VERIFIED, the run is intact and nobody has edited history. If it
says OVERDUE, nothing has been signed since the date shown.
"""
import hashlib, json, sys, urllib.request
from base64 import b64decode
from pathlib import Path
from datetime import datetime, timezone

URL = "https://st88openocean.github.io/slip-three/canary/canary.json"

# ---------------------------------------------------------------- ed25519
# RFC 8032, written out rather than imported so that every line of this file
# can be read before it is run. Slow and clear beats fast and opaque here.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)

def _recover_x(y, sign):
    if y >= P: return None
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if (x * x - xx) % P != 0: return None
    if x % 2 != sign: x = P - x
    return x

def _add(a, b):
    x1, y1, z1, t1 = a; x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    Cc = t1 * 2 * D * t2 % P
    Dd = z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - Cc, Dd + Cc, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)

def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: q = _add(q, pt)
        pt = _add(pt, pt); s >>= 1
    return q

_gy = 4 * pow(5, P - 2, P) % P
G_PT = (_recover_x(_gy, 0), _gy, 1, _recover_x(_gy, 0) * _gy % P)

def _decode_point(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    x = _recover_x(y, b[31] >> 7)
    if x is None: return None
    return (x, y, 1, x * y % P)

def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32: return False
    A = _decode_point(pub)
    R = _decode_point(sig[:32])
    if A is None or R is None: return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    x1, y1, z1, _ = _mul(s, G_PT)
    x2, y2, z2, _ = _add(R, _mul(h, A))
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0

# ---------------------------------------------------------------- the check
def digest(e):
    payload = {k: e[k] for k in ("seq", "utc", "due_utc", "prev", "note")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    raw = (Path(src).read_bytes() if not src.startswith("http")
           else urllib.request.urlopen(src, timeout=30).read())
    doc = json.loads(raw)
    pub = b64decode(doc["public_key"])
    chain = doc["chain"]

    print("SLIP THREE  //  UPLINK CHECK")
    print(f"key     {doc['public_key']}")
    print(f"entries {len(chain)}")
    print()

    prev, ok = "0" * 64, True
    for e in chain:
        h = digest(e)
        links = e["prev"] == prev
        hashes = h == e["hash"]
        signed = ed25519_verify(pub, b64decode(e["sig"]), bytes.fromhex(e["hash"]))
        good = links and hashes and signed
        ok &= good
        flag = "ok  " if good else "FAIL"
        print(f"  {flag}  #{e['seq']:03d}  {e['utc']}  {h[:16]}…")
        if not good:
            print(f"        link={links} hash={hashes} sig={signed}")
        prev = e["hash"]

    last = chain[-1]
    due = datetime.fromisoformat(last["due_utc"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    left = due - now
    print()
    print(f"chain      {'VERIFIED - unbroken, nothing rewritten' if ok else 'BROKEN'}")
    print(f"latest     #{last['seq']:03d}  {last['utc']}")
    print(f"note       {last['note']}")
    print(f"next due   {last['due_utc']}")
    if left.total_seconds() < 0:
        d = -left
        print(f"status     OVERDUE by {d.days}d {d.seconds // 3600}h")
    else:
        print(f"status     HOLDING - {left.days}d {left.seconds // 3600}h remaining")
    print(f"checked    {now.strftime('%Y-%m-%dT%H:%M:%SZ')}  (your clock)")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
