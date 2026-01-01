import os
import json
import csv
from glob import glob
import ast

def load_record(path: str) -> dict:
    """
    Loads a single-record file.
    Supports:
      - valid JSON dict (double quotes)
      - Python dict literal (single quotes) via ast.literal_eval
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()

    # Try strict JSON first
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fallback: Python literal (safe parser, not eval)
        data = ast.literal_eval(text)

    if not isinstance(data, dict):
        raise ValueError(f"{path} did not contain a dict record. Got: {type(data).__name__}")

    return data


def combine_records_to_csv(json_dir: str, output_csv: str, pattern: str = "*.json") -> int:
    paths = sorted(glob(os.path.join(json_dir, pattern)))
    if not paths:
        raise FileNotFoundError(f"No files found in {json_dir!r} matching {pattern!r}")

    records = []
    all_keys = set()

    for p in paths:
        rec = load_record(p)
        records.append(rec)
        all_keys.update(rec.keys())

    # Stable column order: put logfile first if present, then the rest alphabetically
    fieldnames = []
    if "logfile" in all_keys:
        fieldnames.append("logfile")
    fieldnames += sorted(k for k in all_keys if k != "logfile")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)

    return len(records)


if __name__ == "__main__":
    json_dir = r"jsons"
    output_csv = r"combined.csv"

    count = combine_records_to_csv(json_dir, output_csv, pattern="*.json")
    print(f"Wrote {count} rows to {output_csv}")
