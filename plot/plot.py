from __future__ import annotations

import re
import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


COLS = [
    "timestamp",
    "group_seed",
    "username",
    "hash_mode",
    "protection_flags",
    "result",
    "latency_ms",
]

SUCCESS_SET = {"success", "partial_success"}


def infer_strength_group(username: str) -> str | None:
    parts = re.split(r"[^a-z]+", username)  # split on non-letters; handles underscores
    for g in ("weak", "medium", "strong"):
        if g in parts:
            return g
    return None


def process_one_file(path: Path):
    df = pd.read_csv(path, header=None, names=COLS, skipinitialspace=True)

    df["timestamp"] = (df["timestamp"].astype(str).str.replace(r"\+00:00Z$", "+00:00", regex=True))
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp", "username"])
    df["is_success"] = df["result"].isin(SUCCESS_SET)
    df["strength_group"] = df["username"].apply(infer_strength_group)
    df = df.dropna(subset=["strength_group"])

    # per-user start/end (first success)
    starts = df.groupby("username")["timestamp"].min().rename("start_time")
    ends = df[df["is_success"]].groupby("username")["timestamp"].min().rename("end_time")

    user_times = pd.concat([starts, ends], axis=1).dropna(subset=["end_time"]).copy()
    user_times["duration_ms"] = (user_times["end_time"] - user_times["start_time"]).dt.total_seconds() * 1000.0

    user_group = df.groupby("username")["strength_group"].first()
    user_times = user_times.join(user_group, how="left").dropna(subset=["strength_group"])

    # mean duration per group + user counts
    mean_ms = user_times.groupby("strength_group")["duration_ms"].mean() / 1000.0
    cnt = user_times.groupby("strength_group")["duration_ms"].count()

    out = pd.DataFrame({
        "strength_group": ["weak", "medium", "strong"],
        "mean_time_to_success_ms": [mean_ms.get("weak"), mean_ms.get("medium"), mean_ms.get("strong")],
        "successful_users": [cnt.get("weak", 0), cnt.get("medium", 0), cnt.get("strong", 0)],
    })

    return out, df


def plot_bar(means_df: pd.DataFrame, title: str) -> None:
    # Debug: show what we're plotting
    print("\n== Computed per-group metrics ==")
    print(means_df.to_string(index=False))

    plot_df = means_df.copy()
    # Fill missing means with 0 so bars always render
    plot_df["mean_time_to_success_ms"] = plot_df["mean_time_to_success_ms"].fillna(0)

    plt.figure()
    plt.bar(plot_df["strength_group"], plot_df["mean_time_to_success_ms"])
    plt.ylim(0, max(plot_df["mean_time_to_success_ms"].max(), 1))  # prevent flat/empty look

    plt.xlabel("User group strength")
    plt.ylabel("Mean time to success (s)\n(per-user start → first success/partial_success)")
    plt.title(title)

    # annotate counts on top of bars
    for i, row in plot_df.iterrows():
        plt.text(i, row["mean_time_to_success_ms"], f"n={int(row['successful_users'])}",
                 ha="center", va="bottom")

    plt.tight_layout()
    plt.show()



def main(paths: list[str]) -> None:
    if not paths:
        raise SystemExit("Provide at least one log file path.")

    for p in paths:
        path = Path(p)
        if not path.exists():
            raise SystemExit(f"File not found: {path}")

        means_df, raw_df = process_one_file(path)

        # Title: use the file's hash_mode/protection_flags (unique values)
        hash_modes = ", ".join(sorted({str(x) for x in raw_df["hash_mode"].dropna().unique()}))
        prot_flags = ", ".join(sorted({str(x) for x in raw_df["protection_flags"].dropna().unique()}))

        title = f"{path.name}\nhash_mode={hash_modes} | protection_flags={prot_flags}"
        plot_bar(means_df, title)
        

if __name__ == "__main__":
    main(["../logs/attempts__captcha__sha_salt.log"])
