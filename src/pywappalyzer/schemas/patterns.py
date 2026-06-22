from collections.abc import Mapping

import regex

from .base import APISchema


class Pattern(APISchema):
    string: str
    rx: regex.Pattern = regex.compile("", 0)
    version: str | None = None
    confidence: int = 100


class DomSelector(APISchema):
    selector: str
    exists: bool | None = None
    text: list[Pattern] | None = None
    attributes: Mapping[str, list[Pattern]] | None = None