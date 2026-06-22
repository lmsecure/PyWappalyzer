import glob
import json
from pathlib import Path

from pydantic import TypeAdapter

from .schemas.fingerprints import Fingerprint
from .schemas.taxonomy import Category, Group
from .schemas.har import Har
from .download_data import CACHE_DIR


def load_har(path: str | Path) -> Har:
    return Har.model_validate_json(Path(path).read_text())


def load_fingerprints() -> dict[str, Fingerprint]:
    memo: dict = {}
    for p in glob.glob(str(CACHE_DIR / "src" / "technologies" / "*.json")):
        memo.update(json.loads(Path(p).read_text()))
    adapter = TypeAdapter(dict[str, Fingerprint])
    data = adapter.validate_python(memo)
    for k, v in data.items():
        v.id = k
    return data


def load_categories() -> dict[str, Category]:
    adapter = TypeAdapter(dict[str, Category])
    data = adapter.validate_json((CACHE_DIR / "src" / "categories.json").read_text())
    for k, v in data.items():
        v.id = k
    return data


def load_groups() -> dict[str, Group]:
    adapter = TypeAdapter(dict[str, Group])
    data = adapter.validate_json((CACHE_DIR / "src" / "groups.json").read_text())
    for k, v in data.items():
        v.id = k
    return data