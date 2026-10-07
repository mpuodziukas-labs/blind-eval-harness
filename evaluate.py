"""Blind-evaluation harness: score any command-line guard as a black box, with confidence intervals and every miss listed.

    python3 evaluate.py                      sample set through the bundled toy guard, plus the recorded external table
    python3 evaluate.py --guard "CMD"        same sample set through your guard (CMD gets one file path as its last argument)
    python3 evaluate.py --guard "CMD" --external   also run your guard on the 500 external rows

Guard contract: the case text is written to a file, the guard is run as CMD FILE. The guard flags an attack by exiting
non-zero. PASS means exit 0 AND a JSON line {"verdict": "PASS"} on stdout. A crash, a timeout, a signal or unreadable
output counts as flagged (fail closed) and is never skipped. A positive is an attack.
"""
import hashlib, json, pathlib, shlex, subprocess, sys, tempfile
from math import sqrt

ROOT = pathlib.Path(__file__).parent
SAMPLE_DIR = ROOT / "cases-sample"
EXT_SAMPLE = ROOT / "external" / "deepset-prompt-injections" / "sample.jsonl"
EXT_TITLE = "deepset/prompt-injections (external)"
DEFAULT_GUARD = [sys.executable, str(ROOT / "sample_guard.py")]
CLASSES = ("injection", "egress")
TIMEOUT = 20


# ---- statistics ---------------------------------------------------------------
def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def confusion(pairs):
    c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for is_attack, flagged in pairs:
        c[("tp" if flagged else "fn") if is_attack else ("fp" if flagged else "tn")] += 1
    return c


def rates(c):
    pp, ap = c["tp"] + c["fp"], c["tp"] + c["fn"]
    return (c["tp"] / pp if pp else None, c["tp"] / ap if ap else None)


def fmt_rate(p, k, n):
    if p is None:
        return "n/a (0 cases)"
    lo, hi = wilson(k, n)
    return f"{p:.2f} [{lo:.2f}, {hi:.2f}]"


# ---- the sample case set ----------------------------------------------------------
def cases_hash(d=SAMPLE_DIR):
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(d).glob("*.jsonl")):
        h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def load_cases(name):
    return [json.loads(l) for l in (SAMPLE_DIR / f"{name}.jsonl").read_text().splitlines() if l]


# ---- key-shaped strings are built at run time, so no literal shape sits in any file --------
_KEY = lambda: "sk" + "-" + "Zx9Qw8Er7T" * 4
_TOKENS = {"key": _KEY, "ssn": lambda: "912" + "-" + "34" + "-" + "5678"}


def resolve(text):
    for name, fn in _TOKENS.items():
        v = fn()
        text = text.replace("{{%s:1}}" % name, v[: len(v) // 2]).replace("{{%s:2}}" % name, v[len(v) // 2:]).replace("{{%s}}" % name, v)
    return text


# ---- running and interpreting a guard -------------------------------------------------------
def real_runner(argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", True
    return p.returncode, p.stdout, False


def _json_line(out):
    for line in out.strip().splitlines():
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def interpret(rc, out):
    """(flagged, reason). Anything unreadable is flagged: the contract fails closed."""
    j = _json_line(out)
    if not isinstance(j, dict) or "verdict" not in j:
        return True, f"fail-closed: unreadable output (rc={rc})"
    return not (rc == 0 and j["verdict"] == "PASS"), f"verdict={j['verdict']} reason={j.get('reason')}"


def run_guard(cases, guard=None, runner=real_runner, cls="injection"):
    guard = guard or DEFAULT_GUARD
    results = []
    for case in cases:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                f = pathlib.Path(tmp) / "case.txt"
                f.write_text(case["text"] if case.get("literal") else resolve(case["text"]), encoding="utf-8")
                rc, out, timed_out = runner(list(guard) + [str(f)], TIMEOUT)
                if timed_out:
                    flagged, reason = True, "fail-closed: timeout"
                else:
                    flagged, reason = interpret(rc, out)
            except Exception as e:
                flagged, reason = True, f"fail-closed: crash ({type(e).__name__})"
        results.append({"class": cls, "id": case["id"], "label": case["label"], "pred": flagged, "reason": reason})
    return results


def run_sample(guard=None, runner=real_runner):
    return [r for name in CLASSES for r in run_guard(load_cases(name), guard, runner, name)]


def load_external():
    """The seeded external sample, scanned literally (no placeholder resolution)."""
    return [dict(json.loads(l), literal=True) for l in EXT_SAMPLE.read_text(encoding="utf-8").splitlines() if l]


def run_external(guard=None, runner=real_runner):
    return run_guard(load_external(), guard, runner, "external")


# ---- report -----------------------------------------------------------------------------------
HEAD = ["| {} | attacks | benign | TP | FP | TN | FN | precision [95% CI] | recall [95% CI] |", "|---|---|---|---|---|---|---|---|---|"]


def _row(label, preds):
    c = confusion([(p["label"] == "attack", p["pred"]) for p in preds])
    prec, rec = rates(c)
    return (f"| {label} | {c['tp'] + c['fn']} | {c['fp'] + c['tn']} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} | "
            f"{fmt_rate(prec, c['tp'], c['tp'] + c['fp'])} | {fmt_rate(rec, c['tp'], c['tp'] + c['fn'])} |")


def _misses(preds):
    return [{"id": p["id"], "kind": "FN" if p["label"] == "attack" else "FP", "reason": p["reason"]}
            for p in preds if (p["label"] == "attack") != p["pred"]]


def summarize(preds):
    rows = [HEAD[0].format("sample class (not the scored set)"), HEAD[1]]
    rows += [_row(name, [p for p in preds if p["class"] == name]) for name in CLASSES]
    return "\n".join(rows), _misses(preds)


def summarize_external(preds):
    return "\n".join([HEAD[0].format("set"), HEAD[1], _row(EXT_TITLE, preds)]), _misses(preds)


def misses_tsv(preds):
    text = {c["id"]: c["text"] for c in load_external()}
    lines = ["id\tkind\treason\ttext"]
    for m in _misses(preds):
        lines.append(f"{m['id']}\t{m['kind']}\t{' '.join(m['reason'].split())}\t{' '.join(text[m['id']].split())[:140]}")
    return "\n".join(lines) + "\n"


def main(argv):
    guard = shlex.split(argv[argv.index("--guard") + 1]) if "--guard" in argv else None
    preds = run_sample(guard)
    table, misses = summarize(preds)
    print(f"Sample set (written for this repo, not the scored set), guard: {'your command' if guard else 'bundled toy guard'}")
    print(table)
    print(f"\nSample misses ({len(misses)}):")
    for m in misses:
        print(f"- `{m['id']}` ({m['kind']}): {' '.join(m['reason'].split())[:110]}")
    if guard and "--external" in argv:
        ext, how = run_external(guard), "live run of your guard"
    else:
        ext, how = json.loads((ROOT / "external-predictions.json").read_text()), "recorded answers of a private pattern scanner, not the toy guard"
    ext_table, ext_misses = summarize_external(ext)
    print(f"\nExternal dataset: {EXT_TITLE}, {how}")
    print(ext_table)
    print(f"External misses ({len(ext_misses)}): see external-misses.tsv")
    if "--record" in argv and guard and "--external" in argv:
        (ROOT / "external-predictions.json").write_text(json.dumps(ext, indent=0, sort_keys=True) + "\n")
        (ROOT / "external-misses.tsv").write_text(misses_tsv(ext), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
