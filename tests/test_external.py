import hashlib, json, pathlib, random, re, sys

import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import evaluate as ev

README = (ROOT / "README.md").read_text()
EXT = ROOT / "external"
DS = EXT / "deepset-prompt-injections"


def _manifest():
    rows, meta = [], {}
    for line in (EXT / "MANIFEST.tsv").read_text().splitlines():
        if line.startswith("# "):
            k, _, v = line[2:].partition(" ")
            meta[k] = v
        elif line and not line.startswith("file\t"):
            f, sha, n, _note = line.split("\t")
            rows.append((f, sha, int(n)))
    return rows, meta


def test_manifest_hashes_match_every_file():
    rows, _ = _manifest()
    assert rows, "empty manifest"
    for f, sha, _ in rows:
        assert hashlib.sha256((EXT / f).read_bytes()).hexdigest() == sha, f


def test_no_unlisted_file_in_external():
    rows, _ = _manifest()
    listed = {f for f, _, _ in rows} | {"MANIFEST.tsv"}
    assert {str(p.relative_to(EXT)) for p in EXT.rglob("*") if p.is_file()} == listed


def test_manifest_records_source_license_revision_seed():
    _, meta = _manifest()
    assert meta["url"].startswith("https://huggingface.co/datasets/deepset/prompt-injections")
    assert re.fullmatch(r"[0-9a-f]{40}", meta["revision"])
    assert "apache-2.0" in meta["license"] and "cc-by-4.0" in meta["license"]
    assert int(meta["seed"]) > 0 and int(meta["sample-size"]) <= 500


def test_sample_is_the_documented_seeded_draw_and_keeps_dataset_labels():
    _, meta = _manifest()
    full = [json.loads(l) for l in (DS / "rows.jsonl").read_text().splitlines() if l]
    samp = [json.loads(l) for l in (DS / "sample.jsonl").read_text().splitlines() if l]
    idx = sorted(random.Random(int(meta["seed"])).sample(range(len(full)), int(meta["sample-size"])))
    assert [r["id"] for r in samp] == [full[i]["id"] for i in idx]
    by_id = {r["id"]: r for r in full}
    for s in samp:
        assert s["text"] == by_id[s["id"]]["text"] and s["label"] == by_id[s["id"]]["label"]
    assert {s["label"] for s in samp} == {"attack", "benign"}


def test_raw_label_to_attack_mapping_is_unchanged():
    full = [json.loads(l) for l in (DS / "rows.jsonl").read_text().splitlines() if l]
    assert all(r["label"] == ("attack" if r["raw_label"] == 1 else "benign") for r in full)


def test_external_cases_are_scanned_literally():
    seen = []
    c = {"id": "x", "label": "attack", "text": "{{key}} literal braces", "literal": True}

    def runner(argv, timeout):
        seen.append(pathlib.Path(argv[-1]).read_text(encoding="utf-8"))
        return 0, '{"verdict": "PASS"}', False

    ev.run_guard([c], runner=runner)
    assert seen == ["{{key}} literal braces"]


def test_external_crash_is_fail_closed_not_skipped():
    cases = ev.load_external()
    res = ev.run_external(runner=lambda *a: (None, "", True))
    assert len(cases) == 500 and len(res) == len(cases) and all(r["pred"] for r in res)


def test_fake_blind_guard_misses_every_external_attack():
    res = ev.run_external(runner=lambda *a: (0, '{"verdict": "PASS"}', False))
    c = ev.confusion([(r["label"] == "attack", r["pred"]) for r in res])
    assert c["tp"] == 0 and c["fn"] > 0 and c["fp"] == 0


def test_recorded_external_predictions_cover_the_sample_and_labels_agree():
    preds = json.loads((ROOT / "external-predictions.json").read_text())
    by_id = {c["id"]: c["label"] for c in ev.load_external()}
    assert {p["id"] for p in preds} == set(by_id) and len(preds) == len(by_id)
    assert all(p["label"] == by_id[p["id"]] for p in preds)


def test_readme_external_table_matches_recorded_predictions_and_misses_file():
    preds = json.loads((ROOT / "external-predictions.json").read_text())
    table, misses = ev.summarize_external(preds)
    assert table in README, "README external table drifted from external-predictions.json"
    listed = [l.split("\t")[0] for l in (ROOT / "external-misses.tsv").read_text().splitlines()[1:]]
    assert listed == [m["id"] for m in misses] and len(listed) > 0
    assert (ROOT / "external-misses.tsv").read_text() == ev.misses_tsv(preds)


def test_readme_carries_license_attribution():
    assert "deepset" in README and "CC-BY-4.0" in README and "4f61ecb038e9c3fb77e21034b22511b523772cdd" in README
