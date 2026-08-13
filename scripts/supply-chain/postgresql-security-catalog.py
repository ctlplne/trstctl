#!/usr/bin/env python3
"""Normalize PostgreSQL's official security table into fail-closed JSON evidence.

The extracted embedded server has no package database, so a filesystem scanner
usually sees only its Maven wrapper. PostgreSQL is its own CVE Numbering Authority;
this adapter preserves the fetched project page and turns only the relevant rows
into version-comparable data for the receipt policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b(?:1\d|[1-9])(?:\.\d+){1,2}\b")
MAJOR_TOKEN_RE = re.compile(r"\b(?:1\d|[1-9])\b")
RANGE_RE = re.compile(
    r"((?:1\d|[1-9])(?:\.\d+)?)\s*(?:-|–|—|through|to)\s*"
    r"((?:1\d|[1-9])(?:\.\d+)?)",
    re.IGNORECASE,
)
SCORE_VECTOR_RE = re.compile(
    r"\b(10(?:\.0)?|[0-9](?:\.[0-9]))\s+((?:CVSS:|AV:)[^\s]+)",
    re.IGNORECASE,
)


def die(message: str) -> "NoReturn":
    print(f"postgresql-security-catalog: {message}", file=sys.stderr)
    raise SystemExit(1)


def clean_text(parts: list[str]) -> str:
    # A <br> or nested <a> separates adjacent text nodes without contributing a
    # character. Join nodes first so "8.8</a><span>AV:N" cannot become "8.8AV:N".
    return " ".join(" ".join(parts).split())


class SecurityTableParser(HTMLParser):
    """Collect table cells without trusting styling or column CSS classes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, object]]] = []
        self._row: list[dict[str, object]] | None = None
        self._text: list[str] | None = None
        self._links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._text = []
            self._links = []
        elif tag == "a" and self._text is not None:
            href = dict(attrs).get("href")
            if href:
                self._links.append(href)

    def handle_data(self, data: str) -> None:
        if self._text is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "td" and self._row is not None and self._text is not None:
            self._row.append({"text": clean_text(self._text), "links": self._links[:]})
            self._text = None
            self._links = []
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None
            self._text = None
            self._links = []


def major_number(version: str) -> int:
    return int(version.split(".", 1)[0])


def version_parts(version: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+){1,2}", version):
        die(f"invalid PostgreSQL version {version!r}")
    parts = tuple(int(piece) for piece in version.split("."))
    return parts + (0,) * (3 - len(parts))


def affects_major(text: str, major: int) -> bool:
    for match in RANGE_RE.finditer(text):
        if major_number(match.group(1)) <= major <= major_number(match.group(2)):
            return True
    return any(int(token) == major for token in MAJOR_TOKEN_RE.findall(text))


def fixed_version_for_major(text: str, major: int) -> str | None:
    matches = VERSION_RE.findall(text)
    return next((version for version in matches if major_number(version) == major), None)


def severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def normalize_rows(
    parser: SecurityTableParser, source_url: str, postgres_version: str
) -> list[dict[str, object]]:
    major = major_number(postgres_version)
    advisories: list[dict[str, object]] = []
    seen: set[str] = set()

    for row in parser.rows:
        if len(row) < 5:
            continue
        first = str(row[0]["text"])
        cve_match = CVE_RE.search(first)
        if not cve_match:
            continue
        cve = cve_match.group(0).upper()
        affected_text = str(row[1]["text"])
        if not affects_major(affected_text, major):
            continue
        fixed_text = str(row[2]["text"])
        fixed_version = fixed_version_for_major(fixed_text, major)
        if fixed_version is None:
            die(f"{cve} affects PostgreSQL {major} but has no matching fixed version")

        component_text = str(row[3]["text"])
        scores = list(SCORE_VECTOR_RE.finditer(component_text))
        if not scores:
            die(f"{cve} has no parseable CVSS score and vector")
        worst = max(scores, key=lambda match: float(match.group(1)))
        score = float(worst.group(1))
        component = component_text[: scores[0].start()].strip(" :-")
        if not component:
            die(f"{cve} has no component name")

        links = row[0]["links"]
        advisory_url = urljoin(source_url, str(links[0])) if links else ""
        if not advisory_url.startswith("https://www.postgresql.org/"):
            die(f"{cve} advisory link is not on www.postgresql.org")
        if cve in seen:
            die(f"duplicate advisory row for {cve}")
        seen.add(cve)

        advisories.append(
            {
                "cve": cve,
                "advisory_url": advisory_url,
                "affected_versions": affected_text,
                "fixed_versions": fixed_text,
                "fixed_version": fixed_version,
                "component": component,
                "cvss_score": score,
                "cvss_vector": worst.group(2),
                "severity": severity(score),
                "summary": str(row[4]["text"]),
                "affects_assessed_version": version_parts(postgres_version)
                < version_parts(fixed_version),
            }
        )

    if not advisories:
        die(f"official table yielded no advisories for PostgreSQL {major}")
    return advisories


def main() -> None:
    args = argparse.ArgumentParser()
    args.add_argument("--html", required=True, type=Path)
    args.add_argument("--output", required=True, type=Path)
    args.add_argument("--postgres-version", required=True)
    args.add_argument("--source-url", required=True)
    parsed = args.parse_args()

    assessed = parsed.postgres_version
    version_parts(assessed)
    major = major_number(assessed)
    expected_url = f"https://www.postgresql.org/support/security/{major}/"
    source = urlparse(parsed.source_url)
    if (
        parsed.source_url != expected_url
        or source.scheme != "https"
        or source.hostname != "www.postgresql.org"
    ):
        die(f"source URL must be {expected_url}")

    try:
        raw = parsed.html.read_bytes()
        html = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        die(f"cannot read UTF-8 source HTML: {exc}")
    if not raw:
        die("source HTML is empty")

    parser = SecurityTableParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # HTMLParser errors vary by Python patch release.
        die(f"cannot parse source HTML: {exc}")

    advisories = normalize_rows(parser, parsed.source_url, assessed)
    fetched_at_unix = int(time.time())
    document = {
        "schema": "trstctl.postgresql-security-catalog.v1",
        "source": {
            "authority": "PostgreSQL Global Development Group CVE Numbering Authority",
            "url": parsed.source_url,
            "fetched_at_utc": datetime.fromtimestamp(
                fetched_at_unix, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "fetched_at_unix": fetched_at_unix,
            "content_sha256": hashlib.sha256(raw).hexdigest(),
        },
        "assessed_postgres_version": assessed,
        "assessed_major": str(major),
        "advisories": advisories,
    }

    parsed.output.parent.mkdir(parents=True, exist_ok=True)
    parsed.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
