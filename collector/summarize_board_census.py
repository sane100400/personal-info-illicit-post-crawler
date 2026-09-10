#!/usr/bin/env python3
"""Aggregate an exhaustive board crawl by stable public-post identity."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

if __package__ in {None, ""}:
    repository_root = Path(__file__).resolve().parents[1]
    if str(repository_root) not in sys.path:
        sys.path.insert(0, str(repository_root))

from collector.collect_candidates import post_identity_descriptor


THRESHOLDS = (10, 50, 100, 500, 1_000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Collector output directory containing data.csv and candidates_masked.csv",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def normalized_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).lower()
    return re.sub(r"\s+", " ", normalized).strip()


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def percentage(count: int, total: int) -> str:
    return f"{count / total * 100:.1f}%" if total else "0.0%"


def main() -> int:
    args = parse_args()
    out = args.out.resolve()
    raw_rows = read_csv(out / "data.csv")
    masked_rows = read_csv(out / "candidates_masked.csv")
    masked_by_id = {row["sample_id"]: row for row in masked_rows}
    if len(masked_by_id) != len(masked_rows):
        raise RuntimeError("Duplicate sample_id in candidates_masked.csv")
    if {row["sample_id"] for row in raw_rows} != set(masked_by_id):
        raise RuntimeError("Raw and masked sample_id populations differ")

    groups: dict[tuple[str, ...], list[tuple[dict[str, str], dict[str, str]]]] = (
        defaultdict(list)
    )
    for raw in raw_rows:
        masked = masked_by_id[raw["sample_id"]]
        groups[post_identity_descriptor(raw["source_url"])].append((raw, masked))

    representatives = [items[0][1] for items in groups.values()]
    domains = Counter(row["registrable_domain"] for row in representatives)
    boards = Counter(
        row["source_unit_hmac"]
        for row in representatives
        if row["source_unit_kind"] == "board"
    )
    source_units = Counter(row["source_unit_hmac"] for row in representatives)
    board_domains: dict[str, str] = {}
    for row in representatives:
        if row["source_unit_kind"] != "board":
            continue
        unit = row["source_unit_hmac"]
        domain = row["registrable_domain"]
        if unit in board_domains and board_domains[unit] != domain:
            raise RuntimeError("One board HMAC maps to multiple domains")
        board_domains[unit] = domain

    fingerprints = Counter(
        row["near_duplicate_fingerprint"]
        for row in representatives
        if row["near_duplicate_fingerprint"]
    )
    exact_bodies = Counter(
        normalized_text(row["masked_text"])
        for row in representatives
        if normalized_text(row["masked_text"])
    )
    exact_title_bodies = Counter(
        normalized_text(row["masked_title"] + "\n" + row["masked_text"])
        for row in representatives
        if normalized_text(row["masked_title"] + "\n" + row["masked_text"])
    )

    duplicate_groups = [items for items in groups.values() if len(items) > 1]
    duplicate_consistency = {
        "groups": len(duplicate_groups),
        "rows": sum(len(items) for items in duplicate_groups),
        "same_domain_groups": sum(
            len({masked["registrable_domain"] for _, masked in items}) == 1
            for items in duplicate_groups
        ),
        "same_source_unit_groups": sum(
            len({masked["source_unit_hmac"] for _, masked in items}) == 1
            for items in duplicate_groups
        ),
        "same_title_groups": sum(
            len({masked["masked_title"] for _, masked in items}) == 1
            for items in duplicate_groups
        ),
        "same_text_groups": sum(
            len({masked["masked_text"] for _, masked in items}) == 1
            for items in duplicate_groups
        ),
        "same_fingerprint_groups": sum(
            len({masked["near_duplicate_fingerprint"] for _, masked in items}) == 1
            for items in duplicate_groups
        ),
    }

    collection_summary = json.loads((out / "collection_summary.json").read_text())
    manifest = json.loads((out / "data_manifest.json").read_text())
    total = len(representatives)
    metrics = {
        "dataset_version": manifest.get("dataset_version"),
        "generated_at": collection_summary.get("generated_at"),
        "processed_candidate_urls": collection_summary.get("attempted_candidates"),
        "remaining_queue_positions": collection_summary.get(
            "remaining_queue_positions"
        ),
        "raw_retained_rows": len(raw_rows),
        "unique_posts_by_public_id": total,
        "post_identity_duplicate_surplus": len(raw_rows) - total,
        "post_identity_duplicate_groups": len(duplicate_groups),
        "post_identity_duplicate_consistency": duplicate_consistency,
        "unique_domains": len(domains),
        "unique_source_units": len(source_units),
        "unique_boards": len(boards),
        "largest_domain_posts": max(domains.values(), default=0),
        "largest_domain_share": (
            round(max(domains.values(), default=0) / total, 4) if total else 0
        ),
        "largest_board_posts": max(boards.values(), default=0),
        "largest_board_share": (
            round(max(boards.values(), default=0) / total, 4) if total else 0
        ),
        "domain_thresholds": {
            str(threshold): sum(count >= threshold for count in domains.values())
            for threshold in THRESHOLDS
        },
        "board_thresholds": {
            str(threshold): sum(count >= threshold for count in boards.values())
            for threshold in THRESHOLDS
        },
        "distinct_masked_bodies": len(exact_bodies),
        "repeated_masked_body_surplus": total - len(exact_bodies),
        "distinct_masked_title_body_pairs": len(exact_title_bodies),
        "repeated_masked_title_body_surplus": total - len(exact_title_bodies),
        "distinct_simhash_fingerprints": len(fingerprints),
        "simhash_duplicate_surplus": total - len(fingerprints),
        "simhash_duplicate_groups": sum(count > 1 for count in fingerprints.values()),
        "simhash_rows_in_duplicate_groups": sum(
            count for count in fingerprints.values() if count > 1
        ),
        "largest_simhash_group": max(fingerprints.values(), default=0),
        "excluded_domains": manifest.get("settings", {}).get(
            "excluded_domains", []
        ),
        "additional_search_provider_calls": 0,
        "manual_labeling_completed": False,
    }
    (out / "board_census_aggregation.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    domain_rows = [
        {
            "rank": rank,
            "registrable_domain": domain,
            "unique_candidate_posts": count,
            "share": percentage(count, total),
        }
        for rank, (domain, count) in enumerate(domains.most_common(), 1)
    ]
    write_csv(
        out / "domain_post_counts.csv",
        ["rank", "registrable_domain", "unique_candidate_posts", "share"],
        domain_rows,
    )

    board_rows = [
        {
            "rank": rank,
            "registrable_domain": board_domains[unit],
            "board_hmac": unit,
            "unique_candidate_posts": count,
            "share": percentage(count, total),
        }
        for rank, (unit, count) in enumerate(boards.most_common(), 1)
    ]
    write_csv(
        out / "board_post_counts.csv",
        [
            "rank",
            "registrable_domain",
            "board_hmac",
            "unique_candidate_posts",
            "share",
        ],
        board_rows,
    )

    top_domain, top_domain_count = domains.most_common(1)[0]
    top_board_unit, top_board_count = boards.most_common(1)[0]
    report = f"""# 게시판 전수 순회 집계

> 데이터셋: `{metrics['dataset_version']}`
>
> 수집 종료: {metrics['generated_at']}
> 집계 단위: 등록 도메인 + 게시판 식별자 + 공개 게시글 ID(없으면 정규화 URL)

## 핵심 결과

- 처리한 후보 URL: {metrics['processed_candidate_urls']:,}개(남은 큐 {metrics['remaining_queue_positions']}개)
- 자동 의도 게이트 통과 저장 행: {len(raw_rows):,}건
- 게시글 ID 기준 거래 유도 후보: **{total:,}건**
- URL 검색·목록 문맥 차이로 제거한 중복 행: {len(raw_rows) - total:,}건
- 등록 도메인: **{len(domains)}개**
- 게시판: **{len(boards)}개**
- 단일 도메인 최대: **{top_domain_count:,}건**(`{top_domain}`, {percentage(top_domain_count, total)})
- 단일 게시판 최대: **{top_board_count:,}건**(`{board_domains[top_board_unit]}`, {percentage(top_board_count, total)})
- 10건 이상 도메인: {metrics['domain_thresholds']['10']}개
- 50건 이상 도메인: {metrics['domain_thresholds']['50']}개
- 100건 이상 도메인: {metrics['domain_thresholds']['100']}개
- 500건 이상 도메인: {metrics['domain_thresholds']['500']}개
- 1,000건 이상 도메인: {metrics['domain_thresholds']['1000']}개

## 반복 게시

- 서로 다른 비식별 제목·본문 조합: {len(exact_title_bodies):,}개
- 같은 비식별 제목·본문 조합의 추가 복제 게시글: {total - len(exact_title_bodies):,}건
- 서로 다른 비식별 본문: {len(exact_bodies):,}개
- 같은 비식별 본문의 추가 복제 게시글: {total - len(exact_bodies):,}건
- 서로 다른 SimHash 지문: {len(fingerprints):,}개
- 동일 SimHash 지문의 추가 게시글: {total - len(fingerprints):,}건

비식별화가 서로 다른 연락처를 같은 마스킹 토큰으로 바꿀 수 있으므로, 위 반복 게시 수치는 원문 완전 동일성을 입증하는 값이 아니라 비식별 텍스트 기준의 관찰값이다. SimHash는 근접 중복 지문이며 수동 군집 판정이 아니다.

## 해석 범위

이 결과는 새 검색 API 호출 없이 기존에 발견한 게시판의 공개 내부 링크를 큐가 소진될 때까지 순회한 결과다. `dcinside.com`은 초대형 커뮤니티이므로 내부 링크 확장에서 제외했고 최종 결과에도 포함되지 않았다. 자동 필터를 통과한 후보를 집계한 값으로, 수동 이중 라벨링 전에는 확정 불법 게시물이 아니라 **거래 유도 후보 게시글**로 표현한다. 또한 검색엔진 전체 웹의 전수가 아니라 발견된 게시판 링크망의 전수 순회이므로 실제 공개 게시량의 하한이다.
"""
    (out / "board_census_summary.md").write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
