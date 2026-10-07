"""Toy reference guard for the harness demo. It is a naive literal matcher written for this repo and is NOT the guard
behind the external table. Contract: python3 sample_guard.py FILE, prints one JSON line, exit 0 = PASS, exit 1 = FLAG."""
import json, re, sys

PATTERNS = [r"ignore (all )?previous instructions", r"sk-[A-Za-z0-9]{20,}", r"\b\d{3}-\d{2}-\d{4}\b"]


def verdict(text):
    return "FLAG" if any(re.search(p, text, re.I) for p in PATTERNS) else "PASS"


def main(argv):
    if len(argv) != 1:
        print(json.dumps({"verdict": "FLAG", "reason": "usage"}))
        return 2
    with open(argv[0], encoding="utf-8") as f:
        v = verdict(f.read())
    print(json.dumps({"verdict": v}))
    return 0 if v == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
