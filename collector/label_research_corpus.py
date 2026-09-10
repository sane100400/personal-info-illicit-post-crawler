#!/usr/bin/env python3
"""Apply an auditable, masked-text screening rubric to the merged corpus.

The script never reads raw URLs or unmasked contacts.  Exact masked-body units
are classified once and the result is propagated to every distinct post that
shares that body.  A positive label requires all five study criteria:

    live AND page_original AND intent AND target AND contact

The implementation is deliberately conservative.  Informational pages,
legitimate B2B databases, marketing services, extraction software, and
single-account marketplace listings are kept in the corpus but labelled as
negative rather than silently discarded.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


LABEL_FIELDS = [
    "review_unit_id",
    "member_count",
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

ROW_LABEL_FIELDS = [
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

INFORMATIONAL_DOMAINS = {
    "accio.com",
    "goldprint.kr",
    "itemmania.com",
    "lfind.kr",
    "telegram.pe.kr",
}

GAME_ACCOUNT_DOMAINS = {
    "reaccount.net",
}

LEGITIMATE_DB_DOMAINS = {
    "localdb.kr",
    "samo-db.com",
}

UNAVAILABLE_RE = re.compile(
    r"(?:404\s*(?:not found|error)|페이지를\s*찾을\s*수\s*없|존재하지\s*않는\s*게시물|"
    r"삭제된\s*게시물|접근이\s*제한|권한이\s*없)",
    re.I,
)

INFORMATIONAL_TITLE_RE = re.compile(
    r"(?:사건\s*(?:요약)?|판결|무죄|유죄|손해배상|혐의|검거|적발|뉴스|보도자료|"
    r"가이드|완벽\s*가이드|이용\s*방법|확인\s*방법|성공\s*전략|시장\s*동향|"
    r"개인정보(?:처리|취급)방침|개인정보보호법|유출\s*(?:사고|논란)|"
    r"새\s*위협|예방|주의사항|정책|약관|업무안내|발급\s*안내|"
    r"처벌\s*수위|어떻게\s*차단|범죄\s*(?:증가|우려)|웹서비스\s*등장|"
    r"판치는\s*불법|보도되|실태|단속|검색\s*결과|태그의\s*글\s*목록|"
    r"showing\s+results|pokazywanie\s+wyników)",
    re.I,
)

TRANSACTION_RE = re.compile(
    r"(?:판매|팝니다|팔아요|삽니다|사요|매입|구매|구입|대여|임대|거래|제작|"
    r"공급|구합니다|구해요|전문\s*상담|거래\s*연결|판매처|구매처)",
    re.I,
)

CONTACT_STRONG_RE = re.compile(
    r"(?:\[MESSENGER_ID\]|\[PHONE\]|\[EMAIL\]|\[ACCOUNT\]|"
    r"텔레그램|telegram|텔레|텔그|텔램|텔래|탤레|탤래|테그램|테ㄱ렘|"
    r"(?:신청|채팅|문의)텔|"
    r"ㅌㄹ|카카오톡|카톡|카.톡|톡상담|오픈채팅|위챗|라인\s*[:：]|"
    r"쪽지|DM\b|gmail|메일\s*[:：]?|ⓐ)",
    re.I,
)

CONTACT_CONTEXT_RE = re.compile(
    r"(?:문의|연락|상담|신청)\s*(?:주세요|바랍니다|가능|[:：])|"
    r"(?:문의|연락|상담)\s*(?:처|방법)|1\s*[:：]\s*1\s*문의",
    re.I,
)

FINANCIAL_TARGET_RE = re.compile(
    r"(?:대포\s*(?:통장|계좌)|통장\s*(?:판매|팝니다|삽니다|매입|구매|구입|대여|"
    r"임대|거래|제작|구합니다|파는법|빌려)|(?:판매|팝니다|삽니다|매입|구매|"
    r"구입|대여|임대|거래|제작)\s*(?:통장|계좌)|계좌\s*(?:판매|팝니다|"
    r"삽니다|매입|구매|구입|대여|임대|거래|구합니다)|ㅌㅈ\s*(?:판매|"
    r"팝니다|삽니다|매입|구매|임대)|개인장|법인장|코인장|"
    r"사업자장|장집|통장알바|이체알바|계좌알바|충전계좌\s*매입)",
    re.I,
)

IDENTITY_DOCUMENT_RE = re.compile(
    r"(?:신분증|주민등록증|민증|운전면허증?|여권|외국인등록증|학생증|사원증)"
    r".{0,28}(?:판매|팝니다|삽니다|매입|구매|구입|제작|위조|복제)|"
    r"(?:판매|팝니다|삽니다|매입|구매|구입|제작|위조|복제).{0,28}"
    r"(?:신분증|주민등록증|민증|운전면허증?|여권|외국인등록증)",
    re.I | re.S,
)

DATA_CATEGORY = (
    r"대출|주식|코인|카지노|토토|보험|유흥|통신|고객|회원|개인|대학생|성인|"
    r"실시간|최신|각종|마케팅|TM|부동산|병원|환자|투자|리딩|휴대폰|"
    r"유튜브(?:\s*프리미엄)?"
)
PERSONAL_DATA_RE = re.compile(
    rf"(?:(?:{DATA_CATEGORY})\s*(?:DB|디비)|(?:DB|디비)\s*(?:{DATA_CATEGORY}))"
    r".{0,45}(?:판매|팝니다|삽니다|매입|구매|구입|거래|공급|제공)|"
    r"(?:판매|팝니다|삽니다|매입|구매|구입|거래|공급|제공).{0,45}"
    rf"(?:(?:{DATA_CATEGORY})\s*(?:DB|디비)|(?:DB|디비)\s*(?:{DATA_CATEGORY}))|"
    r"(?:DB|디비)\s*(?:판매|팝니다|삽니다|매입|구매|구입|거래)|"
    r"(?:개인정보|고객정보|회원정보|전화번호\s*목록|연락처\s*목록)"
    r".{0,35}(?:판매|팝니다|삽니다|매입|구매|구입|거래|공급|제공)",
    re.I | re.S,
)

BULK_ACCOUNT_RE = re.compile(
    r"(?:(?:N사|네이버).{0,24}(?:비실명|비실계)|"
    r"(?:비실명|비실계).{0,24}(?:계정|아이디|(?<![A-Za-z])ID(?![A-Za-z]))|"
    r"(?:계정|아이디|(?<![A-Za-z])ID(?![A-Za-z])).{0,24}(?:비실명|비실계)|"
    r"해킹\s*(?:아이디|계정)|대포\s*(?:폰|계정)|"
    r"010\s*인증|인증\s*(?:번호|대행|계정)|선불\s*유심|대포\s*유심|"
    r"외국인\s*(?:유심|심)|대포심|선불폰|법인폰|010\s*(?<![A-Za-z])ID(?![A-Za-z])|"
    r"네이버\s*(?:아이디|(?<![A-Za-z])ID(?![A-Za-z]))\s*(?:업체|판매|구매)|"
    r"N사\s*(?:아이디|(?<![A-Za-z])ID(?![A-Za-z])|계정)|실명\s*계정|실계패스|신패스|성인실명인증|"
    r"(?:카페)?최적화\s*(?:아이디|(?<![A-Za-z])ID(?![A-Za-z])))"
    r"|(?:(?:계정|아이디|(?<![A-Za-z])ID(?![A-Za-z])).{0,35}(?:대량|묶음|일괄|개당|1개당|\d[\d,]*\s*개|천개|만개|"
    r"생성\s*대행|업체|최저가|년도별|다량))",
    re.I | re.S,
)

SINGLE_ACCOUNT_RE = re.compile(
    r"(?:유튜브|틱톡|인스타|게임|채널|윈조이|SNS).{0,30}(?:계정|채널).{0,25}"
    r"(?:판매|팝니다|삽니다|구매|거래)|(?:계정|채널).{0,25}(?:판매|팝니다|"
    r"삽니다|구매|거래)",
    re.I | re.S,
)

MASS_INDICATOR_RE = re.compile(
    r"(?:비실명|비실계|대량|다량|묶음|일괄|개당|1개당|천개|만개|업체|년도별|"
    r"생성\s*대행|최저가|N사|네이버\s*(?:아이디|ID))",
    re.I,
)

MARKETING_SERVICE_RE = re.compile(
    r"(?:구글|웹문서|백링크|검색노출).{0,24}(?:홍보|광고|대행)|"
    r"(?:홍보|광고|대행).{0,24}(?:구글|웹문서|백링크|검색노출)",
    re.I | re.S,
)

EXTRACTION_SOFTWARE_RE = re.compile(
    r"(?:DB|디비|아이디|회원).{0,28}(?:추출기|수집기|프로그램)|"
    r"(?:추출기|수집기|프로그램).{0,28}(?:DB|디비|아이디|회원)",
    re.I | re.S,
)

LEGITIMATE_DB_RE = re.compile(
    r"(?:퍼미션\s*DB|동의\s*(?:기반|받은)|인허가\s*DB|사업자\s*DB|"
    r"공공데이터|정상\s*B2B|노리워드\s*CPA)",
    re.I,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged-dir", type=Path, required=True)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(
    path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def classify(
    unit: dict[str, object], domains: set[str]
) -> dict[str, object]:
    title = compact(str(unit.get("masked_title") or ""))
    body = compact(str(unit.get("masked_text") or ""))
    # Most compromised-board advertisements put the actual post first.  When a
    # meaningful post title is available it is authoritative; otherwise only
    # the first 700 body characters are considered.  This prevents old posts,
    # sidebars, and footer navigation from minting a target signal.
    title_has_post_signal = bool(
        TRANSACTION_RE.search(title)
        or CONTACT_STRONG_RE.search(title)
        or CONTACT_CONTEXT_RE.search(title)
    )
    use_body_lead = not title_has_post_signal or domains == {"t.me"}
    lead = compact(title + (" " + body[:700] if use_body_lead else ""))
    intent_scope = compact(title + " " + body[:700])
    contact_scope = compact(title + " " + body[:2_000])
    # Mask tokens describe redaction, not content.  In particular, the "ID"
    # substring in ``[MESSENGER_ID]`` must not be interpreted as a sold account.
    semantic_lead = re.sub(
        r"\[(?:MESSENGER_ID|PHONE|EMAIL|ACCOUNT|CONTACT_URL|NUMERIC_IDENTIFIER|"
        r"NATIONAL_ID|BANK_ACCOUNT|IP_ADDRESS)\]",
        " ",
        lead,
        flags=re.I,
    )

    live = bool(lead) and not bool(UNAVAILABLE_RE.search(title + " " + body[:500]))
    informational = bool(domains & INFORMATIONAL_DOMAINS) or bool(
        INFORMATIONAL_TITLE_RE.search(title)
    )
    page_original = live and not informational

    false_type = ""
    if not live:
        false_type = "unavailable"
    elif informational:
        false_type = "news_guide_or_search_reflection"

    semantic_intent_scope = re.sub(
        r"\[(?:MESSENGER_ID|PHONE|EMAIL|ACCOUNT|CONTACT_URL|NUMERIC_IDENTIFIER|"
        r"NATIONAL_ID|BANK_ACCOUNT|IP_ADDRESS)\]",
        " ",
        intent_scope,
        flags=re.I,
    )
    intent = page_original and bool(TRANSACTION_RE.search(semantic_intent_scope))
    contact = page_original and bool(
        CONTACT_STRONG_RE.search(contact_scope)
        or CONTACT_CONTEXT_RE.search(contact_scope)
    )

    target_category = ""
    if FINANCIAL_TARGET_RE.search(semantic_lead):
        target_category = "financial_account"
    elif IDENTITY_DOCUMENT_RE.search(semantic_lead):
        target_category = "identity_document"
    elif PERSONAL_DATA_RE.search(semantic_lead):
        target_category = "personal_data_db"
    elif BULK_ACCOUNT_RE.search(semantic_lead):
        target_category = "bulk_account_or_authentication"

    target = page_original and bool(target_category)

    if page_original and domains & LEGITIMATE_DB_DOMAINS and (
        LEGITIMATE_DB_RE.search(semantic_lead) or "localdb.kr" in domains
    ):
        target = False
        target_category = ""
        false_type = "legitimate_b2b_database"
    elif page_original and LEGITIMATE_DB_RE.search(semantic_lead):
        target = False
        target_category = ""
        false_type = "legitimate_b2b_database"
    elif page_original and MARKETING_SERVICE_RE.search(title):
        target = False
        target_category = ""
        false_type = "marketing_service"
    elif (
        page_original
        and EXTRACTION_SOFTWARE_RE.search(semantic_lead)
    ):
        target = False
        target_category = ""
        false_type = "extraction_software"
    elif page_original and domains & GAME_ACCOUNT_DOMAINS:
        target = False
        target_category = ""
        false_type = "single_account_listing"
    elif (
        page_original
        and SINGLE_ACCOUNT_RE.search(title)
        and not MASS_INDICATOR_RE.search(
            re.sub(r"\[(?:MESSENGER_ID|ACCOUNT)\]", " ", title, flags=re.I)
        )
    ):
        target = False
        target_category = ""
        false_type = "single_account_listing"

    factors = [live, page_original, intent, target, contact]
    positive = all(factors)
    label = "positive" if positive else "negative"

    if not positive and not false_type:
        if not intent:
            false_type = "no_transaction_intent"
        elif not target:
            false_type = "out_of_scope_target"
        elif not contact:
            false_type = "no_transaction_channel"
        else:
            false_type = "criteria_not_met"

    if positive:
        evidence = target_category + "; offer and contact signals in title/lead body"
        confidence = "high" if CONTACT_STRONG_RE.search(lead) else "medium"
    else:
        missing = [
            name
            for name, value in zip(
                ("live", "page_original", "intent", "target", "contact"), factors
            )
            if not value
        ]
        evidence = false_type + "; failed=" + ",".join(missing)
        confidence = "high" if false_type not in {
            "no_transaction_intent",
            "out_of_scope_target",
            "no_transaction_channel",
        } else "medium"

    return {
        "review_unit_id": unit["review_unit_id"],
        "member_count": unit["member_count"],
        "model_assisted_label": label,
        "live": int(live),
        "page_original": int(page_original),
        "intent": int(intent),
        "target": int(target),
        "contact": int(contact),
        "target_category": target_category,
        "false_positive_type": false_type,
        "confidence": confidence,
        "decision_basis": evidence,
    }


def main() -> int:
    args = parse_args()
    merged_dir = args.merged_dir
    masked_path = merged_dir / "merged_masked.csv"
    units_path = merged_dir / ".private" / "review_units.jsonl"
    if not masked_path.is_file() or not units_path.is_file():
        raise FileNotFoundError("merged corpus inputs are missing")

    rows = read_csv(masked_path)
    rows_by_unit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        rows_by_unit[row["review_unit_id"]].append(row)

    units = [json.loads(line) for line in units_path.read_text(encoding="utf-8").splitlines()]
    labels: list[dict[str, object]] = []
    labels_by_unit: dict[str, dict[str, object]] = {}
    for unit in units:
        domains = {
            row["registrable_domain"]
            for row in rows_by_unit[str(unit["review_unit_id"])]
            if row["registrable_domain"]
        }
        label = classify(unit, domains)
        labels.append(label)
        labels_by_unit[str(unit["review_unit_id"])] = label

    private_dir = merged_dir / ".private"
    write_csv(private_dir / "review_unit_labels.csv", labels, LABEL_FIELDS)
    (private_dir / "review_unit_labels.csv").chmod(0o600)

    labeled_rows: list[dict[str, object]] = []
    for row in rows:
        label = labels_by_unit[row["review_unit_id"]]
        labeled_rows.append({**row, **{name: label[name] for name in ROW_LABEL_FIELDS}})
    write_csv(
        merged_dir / "labeled_masked.csv",
        labeled_rows,
        list(rows[0]) + ROW_LABEL_FIELDS,
    )

    unit_label_counts = Counter(str(label["model_assisted_label"]) for label in labels)
    row_label_counts = Counter(
        str(row["model_assisted_label"]) for row in labeled_rows
    )
    positive_rows = [row for row in labeled_rows if row["model_assisted_label"] == "positive"]
    domain_counts = Counter(row["registrable_domain"] for row in positive_rows)
    category_counts = Counter(row["target_category"] for row in positive_rows)
    false_counts = Counter(
        str(label["false_positive_type"])
        for label in labels
        if label["model_assisted_label"] == "negative"
    )
    summary = {
        "rubric": "ActionablePositive=L_and_O_and_I_and_T_and_C",
        "label_name": "model_assisted_label",
        "classification_input": "masked_title_or_first_700_chars_of_masked_body",
        "review_units": len(labels),
        "rows": len(labeled_rows),
        "unit_label_counts": dict(unit_label_counts),
        "row_label_counts": dict(row_label_counts),
        "positive_domains": len([domain for domain in domain_counts if domain]),
        "positive_target_category_rows": dict(category_counts),
        "negative_unit_types": dict(false_counts),
        "manual_human_label_claimed": False,
    }
    (merged_dir / "label_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
