#!/usr/bin/env python3
"""Produce final aggregate and private audit tables for the labelled corpus."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged-dir", type=Path, required=True)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(
    path: Path, rows: Iterable[dict[str, object]], fields: list[str]
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def threshold_counts(counts: Counter[str]) -> dict[str, int]:
    return {
        f"at_least_{threshold}": sum(value >= threshold for value in counts.values())
        for threshold in (2, 5, 10, 20, 50, 100)
    }


def main() -> int:
    args = parse_args()
    base = args.merged_dir
    private = base / ".private"
    masked = read_csv(base / "labeled_masked.csv")
    raw = read_csv(private / "merged_raw.csv")
    if len(masked) != len(raw):
        raise ValueError("masked/raw row counts differ")

    masked_by_id = {row["merged_id"]: row for row in masked}
    if len(masked_by_id) != len(masked):
        raise ValueError("merged_id is not unique")

    label_fields = [
        "model_assisted_label",
        "live",
        "page_original",
        "intent",
        "target",
        "contact",
        "target_category",
        "false_positive_type",
        "confidence",
        "decision_basis",
    ]
    labeled_raw = [
        {**row, **{field: masked_by_id[row["merged_id"]][field] for field in label_fields}}
        for row in raw
    ]
    write_csv(
        private / "labeled_raw.csv",
        labeled_raw,
        list(raw[0]) + label_fields,
    )
    os.chmod(private / "labeled_raw.csv", 0o600)

    positives_raw = [
        row for row in labeled_raw if row["model_assisted_label"] == "positive"
    ]
    positives_masked = [
        masked_by_id[row["merged_id"]] for row in positives_raw
    ]
    write_csv(base / "positive_masked.csv", positives_masked, list(masked[0]))

    domain_rows: list[dict[str, object]] = []
    by_domain: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in positives_raw:
        by_domain[row["registrable_domain"]].append(row)
    for domain, rows in sorted(
        by_domain.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        phase_counts = Counter(row["source_phase"] for row in rows)
        domain_rows.append(
            {
                "registrable_domain": domain,
                "post_count": len(rows),
                "exact_body_units": len(
                    {masked_by_id[row["merged_id"]]["review_unit_id"] for row in rows}
                ),
                "source_unit_count": len({row["source_unit_descriptor"] for row in rows}),
                "prior_count": phase_counts.get("prior", 0),
                "new_count": phase_counts.get("new", 0),
            }
        )
    write_csv(
        private / "positive_domain_counts.csv",
        domain_rows,
        [
            "registrable_domain",
            "post_count",
            "exact_body_units",
            "source_unit_count",
            "prior_count",
            "new_count",
        ],
    )
    os.chmod(private / "positive_domain_counts.csv", 0o600)

    by_source_unit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in positives_raw:
        by_source_unit[row["source_unit_descriptor"]].append(row)
    source_rows: list[dict[str, object]] = []
    for descriptor, rows in sorted(
        by_source_unit.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        parsed = json.loads(descriptor)
        source_rows.append(
            {
                "source_unit_kind": parsed[0],
                "source_unit_value": parsed[1],
                "registrable_domain": rows[0]["registrable_domain"],
                "post_count": len(rows),
                "exact_body_units": len(
                    {masked_by_id[row["merged_id"]]["review_unit_id"] for row in rows}
                ),
            }
        )
    write_csv(
        private / "positive_source_unit_counts.csv",
        source_rows,
        [
            "source_unit_kind",
            "source_unit_value",
            "registrable_domain",
            "post_count",
            "exact_body_units",
        ],
    )
    os.chmod(private / "positive_source_unit_counts.csv", 0o600)

    exact_counts = Counter(row["review_unit_id"] for row in positives_masked)
    near_counts = Counter(
        row["near_duplicate_fingerprint"]
        for row in positives_masked
        if row["near_duplicate_fingerprint"]
    )
    by_near: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in positives_masked:
        if row["near_duplicate_fingerprint"]:
            by_near[row["near_duplicate_fingerprint"]].append(row)
    near_rows = [
        {
            "near_duplicate_fingerprint": fingerprint,
            "post_count": len(rows),
            "exact_body_units": len({row["review_unit_id"] for row in rows}),
            "domain_count": len({row["registrable_domain"] for row in rows}),
            "prior_count": sum(row["source_phase"] == "prior" for row in rows),
            "new_count": sum(row["source_phase"] == "new" for row in rows),
        }
        for fingerprint, rows in sorted(
            by_near.items(), key=lambda item: (-len(item[1]), item[0])
        )
        if len(rows) > 1
    ]
    write_csv(
        private / "positive_near_duplicate_groups.csv",
        near_rows,
        [
            "near_duplicate_fingerprint",
            "post_count",
            "exact_body_units",
            "domain_count",
            "prior_count",
            "new_count",
        ],
    )
    os.chmod(private / "positive_near_duplicate_groups.csv", 0o600)

    domain_counts = Counter(row["registrable_domain"] for row in positives_raw)
    source_counts = Counter(row["source_unit_descriptor"] for row in positives_raw)
    source_unit_kind_counts = Counter(
        json.loads(descriptor)[0] for descriptor in source_counts
    )
    posts_by_source_unit_kind = Counter()
    for descriptor, count in source_counts.items():
        posts_by_source_unit_kind[json.loads(descriptor)[0]] += count
    phase_counts = Counter(row["source_phase"] for row in positives_raw)
    dataset_counts = Counter(row["source_dataset"] for row in positives_raw)
    category_counts = Counter(row["target_category"] for row in positives_masked)

    summary = {
        "label_scope": "model_assisted_positive_only",
        "positive_posts": len(positives_raw),
        "positive_exact_body_units": len(exact_counts),
        "positive_exact_duplicate_groups": sum(value > 1 for value in exact_counts.values()),
        "positive_exact_duplicate_group_rows": sum(
            value for value in exact_counts.values() if value > 1
        ),
        "positive_exact_duplicate_extra_copies": sum(
            value - 1 for value in exact_counts.values() if value > 1
        ),
        "positive_near_duplicate_groups": sum(value > 1 for value in near_counts.values()),
        "positive_near_duplicate_group_rows": sum(
            value for value in near_counts.values() if value > 1
        ),
        "positive_near_duplicate_extra_copies": sum(
            value - 1 for value in near_counts.values() if value > 1
        ),
        "positive_domains": len(domain_counts),
        "positive_source_units": len(source_counts),
        "positive_source_units_by_kind": dict(source_unit_kind_counts),
        "positive_posts_by_source_unit_kind": dict(posts_by_source_unit_kind),
        "max_posts_in_one_domain": max(domain_counts.values(), default=0),
        "max_posts_in_one_source_unit": max(source_counts.values(), default=0),
        "domain_thresholds": threshold_counts(domain_counts),
        "source_unit_thresholds": threshold_counts(source_counts),
        "positive_posts_by_phase": dict(phase_counts),
        "positive_posts_by_dataset": dict(dataset_counts),
        "positive_posts_by_target_category": dict(category_counts),
        "top_one_domain_share": (
            max(domain_counts.values(), default=0) / len(positives_raw)
            if positives_raw
            else 0.0
        ),
        "raw_urls_exposed_in_public_outputs": False,
        "manual_human_label_claimed": False,
    }
    (base / "research_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
