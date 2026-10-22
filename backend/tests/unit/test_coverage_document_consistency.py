"""
`BLUEPRINT_COVERAGE.md` must not contradict itself (ADR-116).

Two sections of that document were stale on 22 Oct 2026. §11 listed
`Sources` as partial and `Investigation` as absent, three revisions
after both shipped; §16 read "None of that has been measured", two
revisions after six of its eight items were measured. In both cases the
summary table at the top of the same file was correct and the prose
below it was wrong.

That is worse than being uniformly out of date. Each half reads as
authoritative on its own, so a reader who checks the table and a reader
who checks the section come away with different answers about the same
release.

The cause is mechanical: a table row is one line and gets updated with
the change; a prose section is a paragraph elsewhere and does not. This
closes that specific gap, and nothing wider. It compares the two halves
of one document against each other. It cannot tell whether either half
is true of the code — that still needs a person, which is how this drift
was found.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[3] / "docs" / "BLUEPRINT_COVERAGE.md"

#: `| 11 | Dashboard and API contracts | 31 | `MET` (ADR-108, …) |`
SUMMARY_ROW = re.compile(
    r"^\|\s*(\d{1,2})\s*\|[^|]*\|[^|]*\|\s*`([A-Z]+)`",
    re.M,
)

#: `| 11 | Dashboard and API contracts | 31 | …` — the requirement count.
SUMMARY_COUNT = re.compile(
    r"^\|\s*(\d{1,2})\s*\|[^|]*\|\s*(\d+)\s*\|",
    re.M,
)

#: `**251 of 255 discrete requirements — about 98 %.**`
HEADLINE = re.compile(
    r"\*\*(\d+)\s+of\s+(\d+)\s+discrete requirements[^*]*\*\*"
)

#: `**Four requirements remain` / `**Two requirements remain`
REMAINING = re.compile(r"\*\*(\w+)\s+requirements? remain", re.I)

WORDS = {
    "zero": 0, "no": 0, "one": 1, "two": 2, "three": 3, "four": 4,
    "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

#: ``### §16 — operational acceptance … · `MET` ``
SECTION_HEADING = re.compile(
    r"^###\s*§(\d{1,2})\s*—[^\n]*?·\s*`([A-Z]+)`",
    re.M,
)


@pytest.fixture(scope="module")
def document() -> str:
    assert DOC.is_file(), f"{DOC} is missing"
    return DOC.read_text(encoding="utf-8")


def test_the_document_was_actually_read(document: str) -> None:
    """
    Without this, a renamed or emptied file makes every assertion below
    vacuously true — the way a check fails open rather than closed.
    """
    assert len(document) > 5_000
    # Nineteen sections, eighteen of which carry a single verdict. §18's
    # cell reads "13 `MET`, 2 `PARTIAL`" — a composite, deliberately not
    # reduced to one word, and so not parsed as one.
    assert len(SUMMARY_ROW.findall(document)) >= 18, "the summary table is missing rows"
    assert len(SECTION_HEADING.findall(document)) >= 4, "no section verdicts were found"


def test_each_section_verdict_matches_the_summary_table(document: str) -> None:
    """
    A section that carries a verdict must carry the SAME verdict the
    summary table gives it.

    Only sections that state one are checked. A heading like
    `### §9 — three technology deviations` makes no claim and is not
    forced to.
    """
    summary = {int(n): verdict for n, verdict in SUMMARY_ROW.findall(document)}
    assert summary, "the summary table did not parse"

    disagreements = []
    for raw, section_verdict in SECTION_HEADING.findall(document):
        number = int(raw)
        table_verdict = summary.get(number)
        if table_verdict is None:
            disagreements.append(f"§{number} has a section but no summary row")
        elif table_verdict != section_verdict:
            disagreements.append(
                f"§{number}: summary says `{table_verdict}`, "
                f"its section says `{section_verdict}`"
            )

    assert not disagreements, (
        "BLUEPRINT_COVERAGE.md contradicts itself (ADR-116):\n  "
        + "\n  ".join(disagreements)
    )


def test_no_section_claims_a_gap_the_summary_calls_met(document: str) -> None:
    """
    The §16 failure in a form the heading check cannot see.

    §16's heading said `PARTIAL` and its body said "None of that has been
    measured", while the table said `MET`. The heading check catches the
    first. This catches a body that still denies a measurement the
    summary claims, by looking for the phrasings this document actually
    used to mean "nothing here exists yet".
    """
    met = {int(n) for n, verdict in SUMMARY_ROW.findall(document) if verdict == "MET"}

    denials = (
        "none of that has been measured",
        "nothing had measured any of it",
        "is `absent`",
        "— `absent`",
    )

    positions = [(m.start(), int(m.group(1))) for m in SECTION_HEADING.finditer(document)]
    offences = []
    for index, (start, number) in enumerate(positions):
        end = positions[index + 1][0] if index + 1 < len(positions) else len(document)
        # A quoted denial is being REPORTED, not asserted: §16 now records
        # what it used to say, and must be able to say so without tripping
        # this check. Quoted spans are dropped before scanning.
        body = re.sub(r'["\u201c][^"\u201d]*["\u201d]', " ", document[start:end]).lower()
        if number not in met:
            continue
        for phrase in denials:
            if phrase in body:
                offences.append(f"§{number}: summary says `MET` but its body says {phrase!r}")

    assert not offences, (
        "a section denies something the summary table claims (ADR-116):\n  "
        + "\n  ".join(offences)
    )


def test_the_headline_total_is_the_sum_of_the_table(document: str) -> None:
    """
    The headline count must be the table's own arithmetic.

    It read "≈ 247 of ≈ 249" while the Requirements column summed to
    255 — understating by six the table it claimed to summarise. The
    `≈` hedged a number that is not approximate: it is a column of
    integers (ADR-117).
    """
    headline = HEADLINE.search(document)
    assert headline, "the headline requirement count is missing or reworded"
    met, claimed_total = int(headline.group(1)), int(headline.group(2))

    actual_total = sum(int(n) for _, n in SUMMARY_COUNT.findall(document))
    assert actual_total > 200, "the Requirements column did not parse"

    assert claimed_total == actual_total, (
        f"the headline says {claimed_total} requirements; the summary "
        f"table sums to {actual_total} (ADR-117)"
    )
    assert met <= claimed_total


def test_the_remaining_count_matches_the_open_gaps(document: str) -> None:
    """
    "N requirements remain" must equal the open rows of the
    closing-gaps table.

    It said "two", naming only §5 and §10, while that table listed four
    — §18's Windows and network-integration criteria as well. Three
    parts of one file, two answers to the question the document exists
    to answer (ADR-117).

    A closed gap is struck through (`| ~~§11 …`); an open one is not.
    """
    remaining = REMAINING.search(document)
    assert remaining, "the 'N requirements remain' sentence is missing or reworded"
    word = remaining.group(1).lower()
    claimed = WORDS.get(word, None)
    assert claimed is not None, f"unrecognised count word {word!r}"

    start = document.index("## What would close the rest")
    table = document[start : document.index("\n\n", document.index("|---", start))]
    rows = [
        line for line in table.splitlines()
        if line.startswith("|") and not line.startswith("|---") and "| Gap |" not in line
    ]
    assert rows, "the closing-gaps table did not parse"
    open_rows = [line for line in rows if "~~" not in line]

    assert claimed == len(open_rows), (
        f"the summary says {claimed} requirement(s) remain; the "
        f"closing-gaps table lists {len(open_rows)} open:\n  "
        + "\n  ".join(open_rows)
    )
