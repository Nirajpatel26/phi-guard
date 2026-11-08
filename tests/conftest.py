import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "app" / "sample-ehr"))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def patients() -> list[dict]:
    from scripts.generate_patients import generate
    return generate(200, 42)


@pytest.fixture(scope="session")
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture()
def load_fixture():
    def _load(name: str):
        return json.loads((FIXTURES / name).read_text())
    return _load
