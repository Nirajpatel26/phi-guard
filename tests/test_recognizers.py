"""Custom recognizers, validators and the alerting policy (lite engine; no Presidio needed)."""
import pytest

from detector.presidio.engine import LiteEngine, apply_policy, scan_line
from detector.presidio.recognizers import luhn_valid, npi_valid, real_ssn_shape_valid, synthetic_ssn_valid
from scripts.generate_patients import make_npi, npi_check_digit


@pytest.fixture(scope="module")
def engine():
    return LiteEngine()


def entities(engine, text):
    return {f.entity for f in scan_line(engine, text).findings}


# ---------------------------------------------------------------- validators
def test_cms_example_npi_is_valid():
    # CMS's published example: 123456789 -> check digit 3
    assert npi_check_digit("123456789") == 3
    assert npi_valid("1234567893")


@pytest.mark.parametrize("bad", ["1234567890", "3234567893", "123456789", "12345678931"])
def test_invalid_npis_rejected(bad):
    assert not npi_valid(bad)


def test_generated_npis_pass_luhn():
    import random
    rng = random.Random(1)
    assert all(npi_valid(make_npi(rng)) for _ in range(200))


def test_luhn_basic():
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")


def test_synthetic_ssn_rules():
    assert synthetic_ssn_valid("912-34-5678")
    assert not synthetic_ssn_valid("912-00-5678")     # group 00
    assert not synthetic_ssn_valid("912-34-0000")     # serial 0000
    assert not synthetic_ssn_valid("123-45-6789")     # not 9xx


def test_real_ssn_shape_rules():
    assert real_ssn_shape_valid("219-09-9999")
    for bad in ("000-12-3456", "666-12-3456", "901-12-3456", "111-11-1111"):
        assert not real_ssn_shape_valid(bad)


# ---------------------------------------------------------------- detection
@pytest.mark.parametrize("text,expected", [
    ("mrn=MRN-1234567 opened", "MEDICAL_RECORD_NUMBER"),
    ("chart lookup medical record 7654321", "MEDICAL_RECORD_NUMBER"),
    ("eligibility member_id=HPX123456789", "HEALTH_PLAN_ID"),
    ("rendering provider NPI 1234567893", "US_NPI"),
    ('{"ssn": "912-34-5678"}', "US_SSN"),
    ("identity verified ssn=912345678", "US_SSN"),
    ("callback phone=(617) 555-0142", "PHONE_NUMBER"),
    ("mail to jane.doe7@example.com", "EMAIL_ADDRESS"),
])
def test_custom_and_builtin_entities_detected(engine, text, expected):
    assert expected in entities(engine, text)


def test_npi_without_context_is_not_flagged(engine):
    # Luhn-valid 10-digit number with no provider context: below threshold by design.
    assert "US_NPI" not in entities(engine, "epoch 1234567893 checkpoint")


def test_npi_failing_luhn_is_dropped_even_with_context(engine):
    assert "US_NPI" not in entities(engine, "provider NPI 1234567890")


def test_bare_seven_digits_without_context_not_mrn(engine):
    assert entities(engine, "processed 1234567 records") == set()


def test_order_id_shape_without_context_not_member_id(engine):
    assert "HEALTH_PLAN_ID" not in entities(engine, "order ORD123456789 shipped")


def test_lone_timestamp_is_not_phi(engine):
    assert entities(engine, "build 2026-11-01 deployed") == set()


def test_date_with_dob_context_is_phi(engine):
    assert "DATE_TIME" in entities(engine, "DOB: 04/12/1961 confirmed")


def test_policy_keeps_date_next_to_identifier(engine):
    found = engine.analyze("subscriber HPX123456789 seen 2025-06-01")
    kept = {f.entity for f in apply_policy("subscriber HPX123456789 seen 2025-06-01", found)}
    assert {"HEALTH_PLAN_ID", "DATE_TIME"} <= kept


def test_masking_removes_values_and_keeps_marker(engine):
    text = "Patient Maria Lopez (MRN 1234567) ssn=912-34-5678 rid=seed-L999"
    r = scan_line(engine, text)
    assert "1234567" not in r.masked and "912-34-5678" not in r.masked and "Maria" not in r.masked
    assert r.masked.endswith("rid=seed-L999")
    assert r.severity == "HIGH"


def test_masking_keeps_surrounding_quotes(engine):
    r = scan_line(engine, "record {'mrn': 'MRN-1234567', 'name': 'Linda Moore', 'ssn': '912-34-5678'}")
    assert "'name': '<PERSON>', 'ssn': '<US_SSN>'" in r.masked
    assert "Mary O'Brien" not in scan_line(engine, "patient name=Mary O'Brien admitted").masked


def test_scan_result_never_contains_raw_line_hash_only(engine):
    r = scan_line(engine, "ssn=912-34-5678").to_dict()
    assert "912-34-5678" not in str(r["masked"]) and len(r["line_sha256"]) == 64
