"""Detection engines and the PHI alerting policy.

build_engine("auto") returns the Presidio engine when presidio-analyzer and a spaCy
model are installed, otherwise the lite engine. The engine name is recorded in
every alert and in measure.py output so results are never silently mixed.

Policy decisions (documented because they move precision/recall):
* DATE_TIME alone is not PHI in a log line (every line has timestamps). A date is
  kept only with birth-date context nearby or alongside another PHI identifier.
* Matches below SCORE_THRESHOLD are dropped; context words lift ambiguous
  patterns (bare 7-digit MRNs, member IDs, NPIs) over the threshold.
* Raw log lines are never written to alert output; alerts carry a masked copy
  and a SHA-256 of the original line.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Protocol

from .recognizers import (CONTEXT_BOOST, CONTEXT_WINDOW, CUSTOM_SPECS, LITE_BUILTIN_SPECS,
                          RecognizerSpec, presidio_recognizers)

ENTITIES = ["PERSON", "DATE_TIME", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS",
            "MEDICAL_RECORD_NUMBER", "HEALTH_PLAN_ID", "US_NPI"]
SCORE_THRESHOLD = 0.5
DOB_CONTEXT = re.compile(r"(dob|d\.o\.b|birth|born|birthdate)", re.IGNORECASE)
HIGH_ENTITIES = {"US_SSN", "MEDICAL_RECORD_NUMBER", "HEALTH_PLAN_ID"}


@dataclass
class Finding:
    entity: str
    start: int
    end: int
    score: float
    recognizer: str = ""


@dataclass
class ScanResult:
    findings: list[Finding]
    masked: str
    severity: str | None   # None when nothing survived the policy
    line_sha256: str
    engine: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["entities"] = sorted({f.entity for f in self.findings})
        return d


class Engine(Protocol):
    name: str

    def analyze(self, text: str) -> list[Finding]: ...

    def mask(self, text: str, findings: list[Finding]) -> str: ...


# ----------------------------------------------------------------------------- shared
def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep the highest-scoring (then longest) finding among overlapping spans."""
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda f: (-f.score, -(f.end - f.start), f.start)):
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def manual_mask(text: str, findings: list[Finding]) -> str:
    out, cursor = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[cursor:f.start])
        out.append(f"<{f.entity}>")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)


def apply_policy(text: str, findings: list[Finding]) -> list[Finding]:
    findings = [f for f in findings if f.score >= SCORE_THRESHOLD]
    has_identifier = any(f.entity != "DATE_TIME" for f in findings)
    kept = []
    for f in findings:
        if f.entity == "DATE_TIME":
            window = text[max(0, f.start - 30):f.start]
            if not (DOB_CONTEXT.search(window) or has_identifier):
                continue
        kept.append(f)
    return kept


def severity_for(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    entities = {f.entity for f in findings}
    if entities & HIGH_ENTITIES or ("PERSON" in entities and len(entities) > 1):
        return "HIGH"
    return "MEDIUM"


# ----------------------------------------------------------------------------- lite engine
class LiteEngine:
    """Pure-regex approximation. No NER: PERSON is only found after name-like keys."""

    name = "lite"

    def __init__(self, specs: tuple[RecognizerSpec, ...] = CUSTOM_SPECS + LITE_BUILTIN_SPECS) -> None:
        self._compiled = [(spec, [(p, re.compile(p.regex, spec.flags)) for p in spec.patterns]) for spec in specs]

    def analyze(self, text: str) -> list[Finding]:
        lower = text.lower()
        found = []
        for spec, patterns in self._compiled:
            for p, rx in patterns:
                for m in rx.finditer(text):
                    value = m.group(0)
                    if spec.validator and not spec.validator(value):
                        continue
                    score = p.score
                    window = lower[max(0, m.start() - CONTEXT_WINDOW):m.end() + 20]
                    if spec.context and any(w in window for w in spec.context):
                        score = min(1.0, score + CONTEXT_BOOST)
                    found.append(Finding(spec.entity, m.start(), m.end(), round(score, 2), spec.name))
        return resolve_overlaps(found)

    def mask(self, text: str, findings: list[Finding]) -> str:
        return manual_mask(text, findings)


# ----------------------------------------------------------------------------- presidio engine
class PresidioEngine:
    name = "presidio"

    def __init__(self, spacy_model: str = "en_core_web_lg") -> None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": spacy_model}],
        })
        self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        for r in presidio_recognizers():
            self.analyzer.registry.add_recognizer(r)
        self.anonymizer = AnonymizerEngine()
        self.name = f"presidio({spacy_model})"

    def analyze(self, text: str) -> list[Finding]:
        results = self.analyzer.analyze(text=text, language="en", entities=ENTITIES, score_threshold=0.3)
        found = [Finding(r.entity_type, r.start, r.end, round(r.score, 2),
                         (r.recognition_metadata or {}).get("recognizer_name", "")) for r in results]
        return resolve_overlaps(found)

    def mask(self, text: str, findings: list[Finding]) -> str:
        from presidio_analyzer import RecognizerResult
        from presidio_anonymizer.entities import OperatorConfig

        if not findings:
            return text
        res = self.anonymizer.anonymize(
            text=text,
            analyzer_results=[RecognizerResult(f.entity, f.start, f.end, f.score) for f in findings],
            operators={"DEFAULT": OperatorConfig("replace")},
        )
        return res.text


def build_engine(prefer: str = "auto", spacy_model: str = "en_core_web_lg") -> Engine:
    if prefer == "lite":
        return LiteEngine()
    try:
        return PresidioEngine(spacy_model)
    except (ImportError, OSError) as exc:
        if prefer == "presidio":
            raise RuntimeError(f"Presidio engine requested but unavailable: {exc}") from exc
        return LiteEngine()


def scan_line(engine: Engine, text: str) -> ScanResult:
    findings = apply_policy(text, engine.analyze(text))
    return ScanResult(
        findings=findings,
        masked=engine.mask(text, findings),
        severity=severity_for(findings),
        line_sha256=hashlib.sha256(text.encode()).hexdigest(),
        engine=engine.name,
    )
