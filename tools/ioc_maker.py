#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, json, uuid, random, hashlib, datetime as dt, pathlib

DOMAINS = [
    "soft-updatecdn.com", "patch-checker.net", "cdn-telemetry.io",
    "event-broker.app", "micro-updates.org", "ms-secpatch.net",
    "threat-cache.net", "repo-assets.org", "cdn-metrics.info"
]

def rand_ipv4():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def rand_sha256(seed=None):
    h = hashlib.sha256()
    h.update(os.urandom(32 if seed is None else seed))
    return h.hexdigest()

def gen_iocs(n=3):
    iocs = []
    for _ in range(n):
        kind = random.choice(["domain", "ipv4", "sha256"])
        if kind == "domain":
            v = random.choice(DOMAINS)
            # parfois un subdomain
            if random.random() < 0.6:
                v = f"{uuid.uuid4().hex[:6]}.{v}"
        elif kind == "ipv4":
            v = rand_ipv4()
        else:
            v = rand_sha256()
        iocs.append({"type": kind, "value": v})
    return iocs

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    return p

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)

def maybe_write_yara(rules_dir: str):
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rule_name = f"R_{uuid.uuid4().hex[:8]}_{ts}"
    pattern = os.urandom(8).hex().upper()
    src = f"""
rule {rule_name} {{
  meta:
    author = "sec-lab"
    created = "{ts}"
    ref = "lab"
  strings:
    $a = {{ { ' '.join([pattern[i:i+2] for i in range(0,len(pattern),2)]) } }}
  condition:
    all of them
}}
""".lstrip()
    out = os.path.join(rules_dir, f"{rule_name}.yar")
    with open(out, "w", encoding="utf-8") as f:
        f.write(src)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--num-iocs", type=int, default=None, help="Nombre d'IoC à générer (défaut: 1-4 aléatoire)")
    ap.add_argument("--out-dir", type=str, default=None, help="Dossier de sortie (défaut: artifacts/iocs/YYYY/MM/DD)")
    ap.add_argument("--yara-prob", type=float, default=0.15, help="Proba d'ajouter une règle YARA")
    args = ap.parse_args()

    n = args.num_iocs or random.randint(1, 4)
    now = dt.datetime.now()
    rel = now.strftime("artifacts/iocs/%Y/%m/%d")
    out_dir = args.out_dir or rel
    ensure_dir(out_dir)

    payload = {
        "id": str(uuid.uuid4()),
        "generated_at": now.isoformat(),
        "iocs": gen_iocs(n),
        "notes": "R&D lab feed (synthetic)"
    }
    fn = os.path.join(out_dir, f"ioc_{now.strftime('%H%M%S')}_{payload['id'][:8]}.json")
    write_json(fn, payload)

    created = [fn]
    # YARA ?
    if random.random() < float(args.yara_prob):
        rules_dir = ensure_dir("rules/yara")
        created.append(maybe_write_yara(rules_dir))

    print("\\n".join(created))

if __name__ == "__main__":
    main()
