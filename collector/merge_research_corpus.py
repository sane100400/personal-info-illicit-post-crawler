#!/usr/bin/env python3
"""Merge prior and newly collected public-post corpora for final review.

Deduplication is intentionally limited to canonical final URLs and stable public
post identities.  Repeated body text on different post URLs is retained as a
distribution characteristic rather than removed as duplicate content.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import secrets
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

if __package__ in {None, ""}:
    repository_root = Path(__file__).resolve().parents[1]
    if str(repository_root) not in sys.path:
        sys.path.insert(0, str(repository_root))

from collector.collect_candidates import (
    canonicalize_url,
    mask_text,
    near_duplicate_id,
    normalize_extracted_text,
    post_identity_descriptor,
    source_unit_descriptor,
)


RAW_FIELDS = [
    "merged_id",
    "source_phase",
    "source_dataset",
    "source_sample_id",
    "collected_at",
    "source_url",
    "canonical_url",
    "registrable_domain",
    "title",
    "text",
    "post_identity_descriptor",
    "source_unit_descriptor",
]

MASKED_FIELDS = [
    "merged_id",
    "source_phase",
    "source_dataset",
    "source_sample_id",
    "collected_at",
    "url_hmac",
    "registrable_domain",
    "masked_title",
    "masked_text",
    "post_identity_kind",
    "source_unit_kind",
    "near_duplicate_fingerprint",
    "review_unit_id",
]

AUDIT_FIELDS = [
    "dropped_source_phase",
    "dropped_source_dataset",
    "dropped_sample_id",
    "kept_merged_id",
    "reason",
    "canonical_url",
    "post_identity_descriptor",
]


def parse_dataset(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("dataset must use NAME=PATH")
    name, raw_path = value.split("=", 1)
    name = name.strip()
    path = Path(raw_path.strip())
    if not name or not path.is_file():
        raise argparse.ArgumentTypeError(f"invalid dataset: {value}")
    return name, path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prior", action="append", type=parse_dataset, default=[])
    parser.add_argument("--new", action="append", type=parse_dataset, default=[])
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def rows_from(path: Path) -> Iterable[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        yield from csv.DictReader(handle)


def write_csv(path: Path, rows: Iterable[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def get_or_create_key(path: Path) -> bytes:
    if path.exists():
        return bytes.fromhex(path.read_text(encoding="ascii").strip())
    key = secrets.token_bytes(32)
    path.write_text(key.hex() + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    return key


def url_hmac(key: bytes, canonical_url: str) -> str:
    return hmac.new(
        key,
        canonical_url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def main() -> int:
    args = parse_args()
    if not args.prior or not args.new:
        raise ValueError("at least one --prior and one --new dataset are required")

    args.out.mkdir(parents=True, exist_ok=True)
    private_dir = args.out / ".private"
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    key = get_or_create_key(private_dir / "url_hmac_key")

    kept: list[dict[str, object]] = []
    audit: list[dict[str, object]] = []
    seen_urls: dict[str, str] = {}
    seen_strong_identities: dict[tuple[str, ...], str] = {}
    input_counts: Counter[str] = Counter()
    phase_input_counts: Counter[str] = Counter()
    dropped_reasons: Counter[str] = Counter()

    ordered = [
        *(('prior', name, path) for name, path in args.prior),
        *(('new', name, path) for name, path in args.new),
    ]
    for phase, dataset, path in ordered:
        for row in rows_from(path):
            input_counts[dataset] += 1
            phase_input_counts[phase] += 1
            raw_url = str(row.get("source_url") or "").strip()
            canonical = canonicalize_url(raw_url) or raw_url
            identity = post_identity_descriptor(canonical)
            kept_id = seen_urls.get(canonical, "")
            reason = "duplicate_url" if kept_id else ""
            if not reason and identity[0] != "url":
                kept_id = seen_strong_identities.get(identity, "")
                reason = "duplicate_post_identity" if kept_id else ""
            if reason:
                dropped_reasons[reason] += 1
                audit.append(
                    {
                        "dropped_source_phase": phase,
                        "dropped_source_dataset": dataset,
                        "dropped_sample_id": row.get("sample_id", ""),
                        "kept_merged_id": kept_id,
                        "reason": reason,
                        "canonical_url": canonical,
                        "post_identity_descriptor": json.dumps(
                            identity, ensure_ascii=False, separators=(",", ":")
                        ),
                    }
                )
                continue

            merged_id = f"M-{len(kept) + 1:06d}"
            title = str(row.get("title") or row.get("masked_title") or "")
            text = str(row.get("text") or row.get("masked_text") or "")
            unit = source_unit_descriptor(canonical, title, text)
            record: dict[str, object] = {
                "merged_id": merged_id,
                "source_phase": phase,
                "source_dataset": dataset,
                "source_sample_id": row.get("sample_id", ""),
                "collected_at": row.get("collected_at", ""),
                "source_url": raw_url,
                "canonical_url": canonical,
                "registrable_domain": row.get("registrable_domain", ""),
                "title": title,
                "text": text,
                "post_identity_descriptor": json.dumps(
                    identity, ensure_ascii=False, separators=(",", ":")
                ),
                "source_unit_descriptor": json.dumps(
                    unit, ensure_ascii=False, separators=(",", ":")
                ),
                "post_identity": identity,
                "source_unit": unit,
            }
            kept.append(record)
            seen_urls[canonical] = merged_id
            if identity[0] != "url":
                seen_strong_identities[identity] = merged_id

    exact_groups: dict[str, list[int]] = defaultdict(list)
    masked_rows: list[dict[str, object]] = []
    for index, row in enumerate(kept):
        masked_title = mask_text(str(row["title"]))
        masked_text = mask_text(str(row["text"]))
        exact_payload = normalize_extracted_text(masked_title) + "\n" + (
            normalize_extracted_text(masked_text)
        )
        exact_key = hashlib.sha256(exact_payload.encode("utf-8")).hexdigest()
        exact_groups[exact_key].append(index)
        fingerprint = near_duplicate_id(masked_title, masked_text)
        masked_rows.append(
            {
                "merged_id": row["merged_id"],
                "source_phase": row["source_phase"],
                "source_dataset": row["source_dataset"],
                "source_sample_id": row["source_sample_id"],
                "collected_at": row["collected_at"],
                "url_hmac": url_hmac(key, str(row["canonical_url"])),
                "registrable_domain": row["registrable_domain"],
                "masked_title": masked_title,
                "masked_text": masked_text,
                "post_identity_kind": row["post_identity"][0],
                "source_unit_kind": row["source_unit"][0],
                "near_duplicate_fingerprint": fingerprint,
                "review_unit_id": "",
            }
        )

    review_units: list[dict[str, object]] = []
    for unit_number, indexes in enumerate(exact_groups.values(), start=1):
        unit_id = f"U-{unit_number:06d}"
        for index in indexes:
            masked_rows[index]["review_unit_id"] = unit_id
        representative = masked_rows[indexes[0]]
        review_units.append(
            {
                "review_unit_id": unit_id,
                "member_count": len(indexes),
                "merged_ids": [str(masked_rows[i]["merged_id"]) for i in indexes],
                "source_phase_counts": dict(
                    Counter(str(masked_rows[i]["source_phase"]) for i in indexes)
                ),
                "domain_count": len(
                    {str(masked_rows[i]["registrable_domain"]) for i in indexes}
                ),
                "masked_title": representative["masked_title"],
                "masked_text": representative["masked_text"],
                "near_duplicate_fingerprint": representative[
                    "near_duplicate_fingerprint"
                ],
            }
        )

    raw_path = private_dir / "merged_raw.csv"
    audit_path = private_dir / "dedup_audit.csv"
    units_path = private_dir / "review_units.jsonl"
    masked_path = args.out / "merged_masked.csv"
    write_csv(raw_path, kept, RAW_FIELDS)
    write_csv(audit_path, audit, AUDIT_FIELDS)
    write_csv(masked_path, masked_rows, MASKED_FIELDS)
    with units_path.open("w", encoding="utf-8") as handle:
        for unit in review_units:
            handle.write(json.dumps(unit, ensure_ascii=False) + "\n")
    os.chmod(raw_path, 0o600)
    os.chmod(audit_path, 0o600)
    os.chmod(units_path, 0o600)

    phase_kept = Counter(str(row["source_phase"]) for row in kept)
    dataset_kept = Counter(str(row["source_dataset"]) for row in kept)
    exact_duplicate_groups = [indexes for indexes in exact_groups.values() if len(indexes) > 1]
    near_groups: Counter[str] = Counter(
        str(row["near_duplicate_fingerprint"])
        for row in masked_rows
        if row["near_duplicate_fingerprint"]
    )
    summary = {
        "deduplication_policy": [
            "canonical_final_url",
            "stable_public_post_identity",
        ],
        "body_fingerprint_used_for_removal": False,
        "input_rows": sum(input_counts.values()),
        "input_rows_by_phase": dict(phase_input_counts),
        "input_rows_by_dataset": dict(input_counts),
        "kept_rows": len(kept),
        "kept_rows_by_phase": dict(phase_kept),
        "kept_rows_by_dataset": dict(dataset_kept),
        "dropped_rows": len(audit),
        "dropped_reasons": dict(dropped_reasons),
        "unique_domains": len(
            {str(row["registrable_domain"]) for row in kept if row["registrable_domain"]}
        ),
        "unique_source_units": len({tuple(row["source_unit"]) for row in kept}),
        "review_units": len(review_units),
        "exact_body_duplicate_groups": len(exact_duplicate_groups),
        "exact_body_duplicate_rows": sum(len(group) for group in exact_duplicate_groups),
        "near_duplicate_groups": sum(count > 1 for count in near_groups.values()),
        "near_duplicate_rows": sum(count for count in near_groups.values() if count > 1),
        "raw_urls_exposed_in_masked_output": False,
    }
    (args.out / "merge_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
