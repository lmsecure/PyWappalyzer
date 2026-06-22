from .taxonomy import Category, Group
from .fingerprints import Fingerprint, Pattern
from .base import APISchema


class Detection(APISchema):
    url: str
    source_url: str = "" 
    fingerprint: Fingerprint
    app_type: str
    pattern: Pattern
    value: str
    key: str = ""
    resolved_version: str = ""
    via: str | None = None
    categories: list[Category] | None = None
    groups: list[Group] | None = None