import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


import os, json
from datetime import datetime, time

import pandas as pd
from tqdm import tqdm
from pprint import pprint


SUCCESS_LIKE = {"success", "partial success"}

KEYSPACE = {
    "weak": 20_000,
    "medium": 1_757_600,
    "strong": 4.845392e28,
}


def normalize_result(s: str) -> str:
    s = "" if s is None else str(s)
    s = s.strip().lower()
    s = re.sub(r"[_\-]+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def infer_strength_group(username: str) -> Optional[str]:
    if "weak" in username:
        return "weak"
    elif "medium" in username:
        return "medium"
    elif "strong" in username:
        return "strong"
    else:
        return "unknown"


def normalize_ts(ts: str) -> str:
    ts = ts.strip()
    return ts[:-1] if ts.endswith("+00:00Z") else ts


def fmt_seconds(s: float) -> str:
    if s is None or not math.isfinite(s):
        return "N/A"
    if s < 1:
        return f"{s:.3f} s"
    minutes = s / 60
    if minutes < 60:
        return f"{minutes:.2f} min"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.2f} hr"
    days = hours / 24
    if days < 365:
        return f"{days:.2f} days"
    years = days / 365.25
    if years < 1_000:
        return f"{years:.2f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.2f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.2f} million years"
    return f"{years / 1_000_000_000:.2f} billion years"


@dataclass
class UserStats:
    start_ts: str
    success_ts: Optional[str]


def main(logfile: str, chunksize: int = 750_000) -> None:
    path = Path(logfile)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    total_attempts = 0
    global_min_ts = None
    global_max_ts = None
    global_first_success_ts = None

    users: Dict[str, UserStats] = {}
    user_category: Dict[str, str] = {}

    reader = pd.read_csv(
        path,
        header=None,
        names=["timestamp", "group_seed", "username", "hash_mode",
            "protection_flags", "result", "latency_ms"],
        usecols=["timestamp", "username", "result"],
        dtype="string",
        chunksize=chunksize,
        engine="c",
    )

    total_size = path.stat().st_size  # bytes, for display only

    with tqdm(
        reader,
        desc="Processing log",
        unit="chunk",
    ) as pbar:
        for chunk in pbar:
            total_attempts += len(chunk)

            ts = chunk["timestamp"].map(normalize_ts)

            cmin, cmax = ts.min(), ts.max()
            global_min_ts = cmin if global_min_ts is None or cmin < global_min_ts else global_min_ts
            global_max_ts = cmax if global_max_ts is None or cmax > global_max_ts else global_max_ts

            res_norm = chunk["result"].map(normalize_result)
            is_success = res_norm.isin(SUCCESS_LIKE)

            if is_success.any():
                smin = ts[is_success].min()
                global_first_success_ts = (
                    smin if global_first_success_ts is None or smin < global_first_success_ts
                    else global_first_success_ts
                )

            usernames = chunk["username"].tolist()
            ts_list = ts.tolist()
            succ_list = is_success.tolist()

            for u, t, ok in zip(usernames, ts_list, succ_list):
                if u not in user_category:
                    cat = infer_strength_group(u)
                    if cat:
                        user_category[u] = cat

                st = users.get(u)
                if st is None:
                    users[u] = UserStats(start_ts=t, success_ts=(t if ok else None))
                else:
                    if t < st.start_ts:
                        st.start_ts = t
                    if ok and (st.success_ts is None or t < st.success_ts):
                        st.success_ts = t
            pbar.set_postfix(rows_processed=total_attempts)

    t0 = pd.to_datetime(global_min_ts, utc=True)
    t1 = pd.to_datetime(global_max_ts, utc=True)

    attempts_per_second = (
        total_attempts / (t1 - t0).total_seconds()
        if t1 > t0 else None
    )

    time_to_first_success_ms = (
        (pd.to_datetime(global_first_success_ts, utc=True) - t0).total_seconds() * 1000
        if global_first_success_ts else None
    )

    totals = {k: 0 for k in KEYSPACE}
    successes = {k: 0 for k in KEYSPACE}

    for u, st in users.items():
        cat = user_category.get(u)
        if cat:
            totals[cat] += 1
            if st.success_ts:
                successes[cat] += 1


    return {
    # ---- basic summary ----
    "logfile": path.name,
    "total_attempts": int(total_attempts),
    "attempts_per_second": float(attempts_per_second) if attempts_per_second is not None else None,
    "time_to_first_success_ms": (
        float(time_to_first_success_ms) if time_to_first_success_ms is not None else None
    ),

    # ---- success rate by category (user-based) ----
    "weak_total_users": int(totals.get("weak", 0)),
    "weak_successful_users": int(successes.get("weak", 0)),
    "weak_success_rate": (
        successes.get("weak", 0) / totals["weak"] if totals.get("weak", 0) > 0 else 0.0
    ),

    "medium_total_users": int(totals.get("medium", 0)),
    "medium_successful_users": int(successes.get("medium", 0)),
    "medium_success_rate": (
        successes.get("medium", 0) / totals["medium"] if totals.get("medium", 0) > 0 else 0.0
    ),

    "strong_total_users": int(totals.get("strong", 0)),
    "strong_successful_users": int(successes.get("strong", 0)),
    "strong_success_rate": (
        successes.get("strong", 0) / totals["strong"] if totals.get("strong", 0) > 0 else 0.0
    ),

    "weak_expected_seconds": KEYSPACE["weak"] / (2 * attempts_per_second),
    "weak_worst_seconds": KEYSPACE["weak"] / attempts_per_second,

    "medium_expected_seconds": KEYSPACE["medium"] / (2 * attempts_per_second),
    "medium_worst_seconds": KEYSPACE["medium"] / attempts_per_second,

    "strong_expected_seconds": KEYSPACE["strong"] / (2 * attempts_per_second),
    "strong_worst_seconds": KEYSPACE["strong"] / attempts_per_second
}


def extract_mode_name(filename):
    name = os.path.basename(filename)

    if not name.startswith("attempts__") or not name.endswith(".log"):
        return None  # or raise ValueError

    return name[len("attempts__"):-len(".log")]


if __name__ == "__main__":
    for entry in os.scandir("../logs/"):
        if entry.is_file() and "brute__none__sha" not in entry.name.lower() and "brute__totp__sha" not in entry.name.lower():
            print(entry.name)
            config = extract_mode_name(entry.name)
            results = main(f"../logs/attempts__{config}.log")
            pprint(results, sort_dicts=False)

            with open(f"jsons/{config}.json", "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)


