"""Score a target against the suite.

    python -m guardeval run --endpoint http://localhost:8000/chat
    python -m guardeval run --mock          # no target: scores the layers only

A target is any HTTP endpoint that accepts {"messages":[...]} and returns
{"text": "..."}. The evaluator never asserts a pass on the basis of one prompt:
it reports a rate, because a guardrail that holds 19 of 20 times is a guardrail
that fails once a day in production.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from typing import Callable, Dict, List

from . import defences, suite


def _http_target(endpoint: str, timeout=30) -> Callable[[str], str]:
    def call(prompt: str) -> str:
        body = json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(endpoint, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data.get("text") or data.get("output") or json.dumps(data)

    return call


def evaluate(target: Callable[[str], str] | None, layers: List[str], canary=defences.CANARY):
    rows = []
    for case in suite.SUITE:
        blocked_by, text = None, ""
        # input-side layers run first; the first one that trips is the reason
        for name in layers:
            fn = defences.LAYERS[name]
            if name.startswith("output") or name.startswith("tool"):
                continue
            v = fn(case.text)
            if v.blocked:
                blocked_by = f"{name}: {v.reason}"
                break
        if blocked_by is None and target is not None:
            text = target(case.text)
            for name in layers:
                fn = defences.LAYERS[name]
                if not (name.startswith("output") or name.startswith("tool")):
                    continue
                v = fn(text)
                if v.blocked:
                    blocked_by = f"{name}: {v.reason}"
                    break
            if blocked_by is None and canary in text.upper():
                blocked_by = None
        rows.append({
            "id": case.id, "category": case.category, "tactic": case.tactic,
            "blocked_by": blocked_by,
            "bypassed": blocked_by is None,
        })
    total = len(rows)
    bypass = sum(1 for r in rows if r["bypassed"])
    per_cat: Dict[str, dict] = {}
    for r in rows:
        d = per_cat.setdefault(r["category"], {"total": 0, "bypassed": 0})
        d["total"] += 1
        d["bypassed"] += int(r["bypassed"])
    return {
        "layers": layers,
        "cases": total,
        "bypassed": bypass,
        "bypass_rate": round(bypass / total, 3),
        "per_category": {
            k: {**v, "rate": round(v["bypassed"] / v["total"], 3)}
            for k, v in sorted(per_cat.items())
        },
        "rows": rows,
    }


def matrix():
    """Single-layer bypass matrix — which layer earns its place."""
    out = {}
    for name in defences.LAYERS:
        r = evaluate(None, [name]) if name.startswith("input") or name.startswith("tool") \
            else {"bypass_rate": None, "bypassed": None, "cases": len(suite.SUITE)}
        out[name] = r
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardeval")
    ap.add_argument("--endpoint")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--layers", nargs="+", default=list(defences.LAYERS))
    ap.add_argument("--out", default="out/results.json")
    a = ap.parse_args(argv)

    target = _http_target(a.endpoint) if a.endpoint else None
    r = evaluate(target, a.layers)
    print(f"cases {r['cases']}  bypassed {r['bypassed']}  rate {r['bypass_rate']}")
    for cat, v in r["per_category"].items():
        print(f"  {cat:14} {v['bypassed']}/{v['total']}  {v['rate']}")
    import os
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(r, f, indent=2)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
