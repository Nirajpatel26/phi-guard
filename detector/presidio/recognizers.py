"""Custom PHI recognizer definitions.

The patterns, context words and validators live here as plain data so that the
same definitions drive both engines:

* the Presidio engine turns them into PatternRecognizer subclasses, and
* the "lite" engine (pure `re`, used in unit tests and CI where spaCy/Presidio
  aren't installed) evaluates them directly.

Scores follow Presidio's convention: the base pattern score is deliberately low
for ambiguous shapes; a context word nearby raises it (CONTEXT_BOOST), and a
validator can reject a match outright.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

CONTEXT_BOOST = 0.35
CONTEXT_WINDOW = 40  # characters before the match searched for context words


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def npi_valid(value: str) -> bool:
    """CMS NPI check: 10 digits, starts with 1 or 2, Luhn over '80840' + NPI."""
    digits = re.sub(r"\D", "", value)
    return len(digits) == 10 and digits[0] in "12" and luhn_valid("80840" + digits)


def synthetic_ssn_valid(value: str) -> bool:
    """Accept 9xx-xx-xxxx (never issued by SSA, used for synthetic data).

    Presidio's built-in UsSsnRecognizer intentionally rejects 9xx area numbers,
    so without this recognizer every synthetic SSN would be missed and the recall
    numbers would be meaningless. Group 00 and serial 0000 are still rejected.
    """
    digits = re.sub(r"\D", "", value)
    return len(digits) == 9 and digits[0] == "9" and digits[3:5] != "00" and digits[5:] != "0000"


def real_ssn_shape_valid(value: str) -> bool:
    """Mirror of the SSA rules Presidio applies to issued-range SSNs."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or len(set(digits)) == 1:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in {"000", "666"} and area[0] != "9" and group != "00" and serial != "0000"


@dataclass(frozen=True)
class PatternSpec:
    name: str
    regex: str
    score: float


@dataclass(frozen=True)
class RecognizerSpec:
    entity: str
    name: str
    patterns: tuple[PatternSpec, ...]
    context: tuple[str, ...] = ()
    validator: Callable[[str], bool] | None = None
    flags: int = 0
    # Patterns in Presidio-only mode: set False if a built-in recognizer already covers it.
    lite_only: bool = False
    extra: dict = field(default_factory=dict)


CUSTOM_SPECS: tuple[RecognizerSpec, ...] = (
    RecognizerSpec(
        entity="MEDICAL_RECORD_NUMBER",
        name="PhiGuardMrnRecognizer",
        patterns=(
            PatternSpec("mrn_prefixed", r"\bMRN[-:#\s]?\d{6,8}\b", 0.85),
            PatternSpec("mrn_bare", r"\b\d{7}\b", 0.15),
        ),
        context=("mrn", "medical record", "chart", "record number"),
        flags=re.IGNORECASE,
    ),
    RecognizerSpec(
        entity="HEALTH_PLAN_ID",
        name="PhiGuardMemberIdRecognizer",
        patterns=(PatternSpec("member_id", r"\b[A-Z]{3}\d{9}\b", 0.45),),
        context=("member", "subscriber", "plan", "insurance", "policy", "eligibility", "coverage"),
    ),
    RecognizerSpec(
        entity="US_NPI",
        name="PhiGuardNpiRecognizer",
        patterns=(PatternSpec("npi", r"\b[12]\d{9}\b", 0.4),),
        context=("npi", "provider", "prescriber", "physician", "rendering", "pcp"),
        validator=npi_valid,
    ),
    RecognizerSpec(
        entity="US_SSN",
        name="PhiGuardSyntheticSsnRecognizer",
        patterns=(
            PatternSpec("ssn_9xx_dashed", r"\b9\d{2}-\d{2}-\d{4}\b", 0.6),
            PatternSpec("ssn_9xx_compact", r"\b9\d{8}\b", 0.2),
        ),
        context=("ssn", "social security", "social", "ss#", "taxpayer"),
        validator=synthetic_ssn_valid,
    ),
)

# Lite-engine approximations of Presidio built-ins. Not used when Presidio is available.
LITE_BUILTIN_SPECS: tuple[RecognizerSpec, ...] = (
    RecognizerSpec(
        entity="US_SSN", name="LiteSsn",
        patterns=(PatternSpec("ssn_dashed", r"\b\d{3}-\d{2}-\d{4}\b", 0.5),),
        context=("ssn", "social security"), validator=real_ssn_shape_valid, lite_only=True,
    ),
    RecognizerSpec(
        entity="EMAIL_ADDRESS", name="LiteEmail",
        patterns=(PatternSpec("email", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", 1.0),), lite_only=True,
    ),
    RecognizerSpec(
        entity="PHONE_NUMBER", name="LitePhone",
        patterns=(PatternSpec("us_phone", r"(?<!\d)\(?\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}\b", 0.6),),
        context=("phone", "tel", "call", "mobile", "contact"), lite_only=True,
    ),
    RecognizerSpec(
        entity="DATE_TIME", name="LiteDate",
        patterns=(
            PatternSpec("iso", r"\b(19|20)\d{2}-\d{2}-\d{2}\b", 0.6),
            PatternSpec("us", r"\b\d{1,2}/\d{1,2}/(19|20)\d{2}\b", 0.6),
            PatternSpec("long", r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? (19|20)\d{2}\b", 0.6),
        ),
        lite_only=True,
    ),
    RecognizerSpec(
        # Key-based heuristic (no NER): a capitalised First Last after a name-like key.
        entity="PERSON", name="LiteKeyedPerson",
        patterns=(PatternSpec(
            "keyed_name",
            r"(?:(?<=name=)|(?<=name': ')|(?<=\"name\": \")|(?<=[Pp]atient )|(?<=search\?name=))"
            # O'Brien / Smith-Jones are fine; a trailing quote must not be swallowed
            r"[A-Z][a-z]+(?:[ +][A-Z][a-z]*(?:['-][A-Z]?[a-z]+)*)+",
            0.7),),
        lite_only=True,
    ),
)


def presidio_recognizers() -> list:
    """Build Presidio PatternRecognizers from CUSTOM_SPECS. Imports Presidio lazily."""
    from presidio_analyzer import Pattern, PatternRecognizer

    recognizers = []
    for spec in CUSTOM_SPECS:
        validator = spec.validator

        class _Recognizer(PatternRecognizer):  # noqa: N801 - generated per spec
            _validator = staticmethod(validator) if validator else None

            def validate_result(self, pattern_text: str):  # type: ignore[override]
                # None keeps the pattern score (so context still matters); False drops the match.
                if self._validator is None:
                    return None
                return None if self._validator(pattern_text) else False

        recognizers.append(_Recognizer(
            supported_entity=spec.entity,
            name=spec.name,
            patterns=[Pattern(p.name, p.regex if not spec.flags else f"(?i){p.regex}", p.score)
                      for p in spec.patterns],
            context=list(spec.context),
        ))
    return recognizers
