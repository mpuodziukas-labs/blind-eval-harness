"""Break evaluate.py on purpose, one way at a time, and require the test suite to go RED.

    python3 mutants.py

A control copy (no change) must pass first, otherwise a RED mutant proves nothing.
"""
import pathlib, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).parent
MUTANTS = {
    "wilson-half-width": ("h = z * sqrt(", "h = 0.5 * z * sqrt("),
    "hash-ignores-content": ('h.update(p.name.encode() + b"\\0" + p.read_bytes() + b"\\0")', 'h.update(p.name.encode() + b"\\0")'),
    "crash-skipped": ('flagged, reason = True, f"fail-closed: crash ({type(e).__name__})"', "continue"),
    "timeout-passes": ('flagged, reason = True, "fail-closed: timeout"', 'flagged, reason = False, "timeout"'),
    "garbage-passes": ('return True, f"fail-closed: unreadable output (rc={rc})"', 'return False, "unreadable"'),
    "nonzero-exit-ignored": ('return not (rc == 0 and j["verdict"] == "PASS")', 'return j["verdict"] != "PASS"'),
}


def pytest(d):
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                       cwd=d, capture_output=True, text=True, env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    failed = sorted(set(re.findall(r"^FAILED \S+::(\w+)", p.stdout, re.M)))
    m = re.search(r"(\d+) passed", p.stdout)
    return p.returncode, int(m.group(1)) if m else 0, failed


def copy(dst):
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))


def main():
    bad = 0
    with tempfile.TemporaryDirectory() as t:
        c = pathlib.Path(t) / "control"
        copy(c)
        rc, n, _ = pytest(c)
        print(f"control PASS {n}/{n}" if rc == 0 and n else f"control FAIL rc={rc}")
        if rc != 0 or n == 0:
            return 1
        for name, (old, new) in MUTANTS.items():
            d = pathlib.Path(t) / name
            copy(d)
            src = (d / "evaluate.py").read_text()
            if src.count(old) != 1:
                print(f"mutant {name} NOT APPLIED (pattern found {src.count(old)} times)")
                bad += 1
                continue
            (d / "evaluate.py").write_text(src.replace(old, new))
            rc, _, failed = pytest(d)
            if rc == 0 or not failed:
                print(f"mutant {name} SURVIVED (suite stayed green)")
                bad += 1
            else:
                print(f"mutant {name} FAIL exactly ({', '.join(failed)})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
