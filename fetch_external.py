"""One-time fetch of the external test set, run BEFORE any scored run.

    python3 fetch_external.py     needs network and pyarrow; evaluate.py does not need either

Downloads the two parquet files of deepset/prompt-injections at a pinned revision,
keeps the dataset's own labels (1 = attack, 0 = benign), writes every row to rows.jsonl,
draws a seeded sample of at most 500 rows to sample.jsonl, and records sha256 of each
file in external/MANIFEST.tsv. No row is relabeled or filtered.
"""
import hashlib, io, json, pathlib, random, urllib.request

import pyarrow.parquet as pq

ROOT = pathlib.Path(__file__).parent
DS = ROOT / "external" / "deepset-prompt-injections"
REV = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
BASE = f"https://huggingface.co/datasets/deepset/prompt-injections/resolve/{REV}/data/"
FILES = {"train": "train-00000-of-00001-9564e8b05b4757ab.parquet", "test": "test-00000-of-00001-701d16158af87368.parquet"}
SEED, SIZE = 20261004, 500


def main():
    DS.mkdir(parents=True, exist_ok=True)
    rows = []
    for split, name in FILES.items():
        raw = urllib.request.urlopen(BASE + name, timeout=60).read()
        (DS / f"{split}.parquet").write_bytes(raw)
        t = pq.read_table(io.BytesIO(raw)).to_pylist()
        for i, r in enumerate(t):
            rows.append({"id": f"ext-{split}-{i:04d}", "split": split, "raw_label": int(r["label"]),
                         "label": "attack" if int(r["label"]) == 1 else "benign", "text": r["text"]})
    dump = lambda rs: "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rs)
    (DS / "rows.jsonl").write_text(dump(rows), encoding="utf-8")
    idx = sorted(random.Random(SEED).sample(range(len(rows)), min(SIZE, len(rows))))
    sample = [rows[i] for i in idx]
    (DS / "sample.jsonl").write_text(dump(sample), encoding="utf-8")
    counts = {f"{s}.parquet": sum(r["split"] == s for r in rows) for s in FILES}
    lines = [
        "# url https://huggingface.co/datasets/deepset/prompt-injections",
        f"# revision {REV}",
        "# license apache-2.0 (card front matter) and cc-by-4.0 (card dataset_info); both permissive, attribution given in README",
        f"# seed {SEED}",
        f"# sample-size {len(sample)}",
        "# sampling sorted(random.Random(seed).sample(range(len(rows.jsonl)), sample-size)), rows.jsonl order = train then test",
        "# language the dataset gives no per-language field, so no per-language split is reported",
        "file\tsha256\trows\tnote",
    ]
    notes = {"train.parquet": "raw download", "test.parquet": "raw download", "rows.jsonl": "all rows, dataset labels", "sample.jsonl": "seeded sample scored"}
    n = {"rows.jsonl": len(rows), "sample.jsonl": len(sample), **counts}
    for f in ("train.parquet", "test.parquet", "rows.jsonl", "sample.jsonl"):
        sha = hashlib.sha256((DS / f).read_bytes()).hexdigest()
        lines.append(f"deepset-prompt-injections/{f}\t{sha}\t{n[f]}\t{notes[f]}")
    (ROOT / "external" / "MANIFEST.tsv").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
