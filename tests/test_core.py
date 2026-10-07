import json, pathlib, re, shutil, sys

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import evaluate as ev

README = (ROOT / "README.md").read_text()


# ---- Wilson interval math: known published values ----------------------------
def test_wilson_half_of_ten():
    lo, hi = ev.wilson(5, 10)
    assert round(lo, 4) == 0.2366 and round(hi, 4) == 0.7634


def test_wilson_zero_of_ten():
    lo, hi = ev.wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775


def test_wilson_ten_of_ten():
    lo, hi = ev.wilson(10, 10)
    assert round(lo, 4) == 0.7225 and round(hi, 4) == 1.0


def test_wilson_empty_is_full_range():
    assert ev.wilson(0, 0) == (0.0, 1.0)


def test_wilson_bounds_and_width_shrinks_with_n():
    lo1, hi1 = ev.wilson(40, 50)
    lo2, hi2 = ev.wilson(400, 500)
    assert 0 <= lo1 < 0.8 < hi1 <= 1 and (hi2 - lo2) < (hi1 - lo1)


# ---- confusion matrix ---------------------------------------------------------
def test_confusion_counts():
    pairs = [(True, True)] * 3 + [(True, False)] * 2 + [(False, True)] * 1 + [(False, False)] * 4
    c = ev.confusion(pairs)
    assert (c["tp"], c["fp"], c["tn"], c["fn"]) == (3, 1, 4, 2)
    p, r = ev.rates(c)
    assert p == 3 / 4 and r == 3 / 5


def test_rates_undefined_when_no_positive_predictions():
    p, r = ev.rates(ev.confusion([(True, False), (False, False)]))
    assert p is None and r == 0.0


def test_fmt_undefined_is_na():
    assert ev.fmt_rate(None, 0, 0).startswith("n/a")


# ---- hash freeze of the sample set ---------------------------------------------
def test_readme_pins_the_sample_hash():
    m = re.search(r"sample-sha256: ([0-9a-f]{64})", README)
    assert m, "README has no sample-sha256 line"
    assert ev.cases_hash() == m.group(1), "sample cases changed without updating the hash"


def test_readme_keeps_the_private_set_hash_line_only():
    assert re.search(r"cases-sha256: [0-9a-f]{64}", README)


def test_hash_changes_when_a_case_changes(tmp_path):
    d = tmp_path / "cases"
    shutil.copytree(ROOT / "cases-sample", d)
    before = ev.cases_hash(d)
    f = d / "egress.jsonl"
    f.write_text(f.read_text().replace('"label": "benign"', '"label": "attack"', 1))
    assert ev.cases_hash(d) != before


def test_hash_changes_when_a_case_file_is_removed(tmp_path):
    d = tmp_path / "cases"
    shutil.copytree(ROOT / "cases-sample", d)
    before = ev.cases_hash(d)
    (d / "egress.jsonl").unlink()
    assert ev.cases_hash(d) != before


# ---- sample case shape ------------------------------------------------------------
@pytest.mark.parametrize("name", ev.CLASSES)
def test_sample_has_at_most_ten_cases_and_unique_ids(name):
    cases = ev.load_cases(name)
    ids = [c["id"] for c in cases]
    assert 0 < len(ids) <= 10 and len(ids) == len(set(ids))
    assert {c["label"] for c in cases} == {"attack", "benign"}


def test_no_literal_key_shapes_in_any_case_file():
    pat = re.compile(r"sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|\b\d{3}-\d{2}-\d{4}\b")
    for p in (ROOT / "cases-sample").glob("*.jsonl"):
        assert not pat.search(p.read_text()), p.name


def test_placeholders_all_resolve_and_halves_join():
    for name in ev.CLASSES:
        for c in ev.load_cases(name):
            assert "{{" not in ev.resolve(c["text"]), c["id"]
    assert ev.resolve("{{key:1}}") + ev.resolve("{{key:2}}") == ev.resolve("{{key}}")
    assert re.fullmatch(r"sk-[A-Za-z0-9]{40}", ev.resolve("{{key}}"))


# ---- fake guards, all through the same black-box contract ------------------------------
ALL = [c for n in ev.CLASSES for c in ev.load_cases(n)]


def test_says_attack_to_everything_recall_one_precision_base_rate():
    res = ev.run_guard(ALL, runner=lambda *a: (1, '{"verdict": "FLAG"}', False))
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    p, r = ev.rates(c)
    assert r == 1.0 and c["fn"] == 0
    assert abs(p - sum(x["label"] == "attack" for x in ALL) / len(ALL)) < 1e-12


def test_says_benign_to_everything_misses_every_attack():
    res = ev.run_guard(ALL, runner=lambda *a: (0, '{"verdict": "PASS"}', False))
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    assert c["tp"] == 0 and c["fp"] == 0 and c["fn"] == sum(x["label"] == "attack" for x in ALL)


def test_pass_verdict_with_nonzero_exit_is_flagged():
    res = ev.run_guard(ALL[:1], runner=lambda *a: (1, '{"verdict": "PASS"}', False))
    assert res[0]["pred"] is True


def _boom(*a):
    raise RuntimeError("guard blew up")


def _segv(*a):
    return -11, "", False


def _timeout(*a):
    return None, "", True


def _garbage_exit0(*a):
    return 0, "<<not json>>", False


@pytest.mark.parametrize("bad", [_boom, _segv, _timeout, _garbage_exit0])
def test_crash_is_fail_closed_not_skipped(bad):
    res = ev.run_guard(ALL, runner=bad)
    assert len(res) == len(ALL), "a crash must not drop a case"
    assert all(r["pred"] is True and "fail-closed" in r["reason"] for r in res)
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    assert c["fn"] == 0 and c["fp"] == sum(x["label"] == "benign" for x in ALL)


def test_bundled_guard_runs_for_real_through_the_cli():
    res = ev.run_sample()
    assert len(res) == len(ALL)
    got = {r["id"]: r["pred"] for r in res}
    assert got["s-inj-a-literal"] is True and got["s-inj-b-recipe"] is False and got["s-egr-a-split-key"] is False


# ---- README == the printed output --------------------------------------------------------
def test_readme_sample_table_and_misses_match_live_run():
    table, misses = ev.summarize(ev.run_sample())
    assert table in README, "README sample table drifted from evaluate.py"
    for m in misses:
        assert f"`{m['id']}` ({m['kind']})" in README, f"miss {m['id']} not published in README"


def test_readme_lists_every_mutant():
    import mutants
    for name in mutants.MUTANTS:
        assert f"mutant {name} FAIL exactly" in README, name
    assert "control PASS" in README
