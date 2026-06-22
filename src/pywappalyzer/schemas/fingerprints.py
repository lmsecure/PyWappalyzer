from collections.abc import Mapping

# from loguru import logger
from pydantic import Field, field_validator
import regex

from .base import APISchema
from .patterns import Pattern, DomSelector


def prepare_pattern(v: str | list[str], *, set_regex: bool = True) -> list[Pattern]:
    if isinstance(v, list):
        result = []
        for p in v:
            result.extend(prepare_pattern(p, set_regex=set_regex))
        return result

    attrs = {}
    parts = v.split("\\;")
    for index, expression in enumerate(parts):
        if index == 0:
            attrs["string"] = expression
            if set_regex:
                try:
                    attrs["rx"] = regex.compile(expression, regex.I)
                except regex.error as e:
                    # logger.debug(f"Caught '{e}' compiling regex: {parts}")
                    attrs["rx"] = regex.compile(r"(?!x)x")
        else:
            attr = expression.split(":")
            if len(attr) > 1:
                key = attr.pop(0)
                attrs[str(key)] = ":".join(attr)

    return [Pattern(**attrs)]

   
class Fingerprint(APISchema):
    id: str = "N/A"
    website: str
    cats: list[int] = Field(default_factory=list)
    description: str | None = None
    icon: str | None = None
    cpe: str | None = None
    saas: bool | None = None
    oss: bool | None = None

    pricing: list[str] = Field(default_factory=list)
    implies: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    requires_category: list[int] = Field(default_factory=list)
    excludes: list[str] = Field(default_factory=list)

    dom: list[DomSelector] = Field(default_factory=list)
    headers: Mapping[str, list[Pattern]] = Field(default_factory=dict)
    cookies: Mapping[str, list[Pattern]] = Field(default_factory=dict)
    meta: Mapping[str, list[Pattern]] = Field(default_factory=dict)
    html: list[Pattern] = Field(default_factory=list)
    url: list[Pattern] = Field(default_factory=list)
    script_src: list[Pattern] = Field(default_factory=list)
    scripts: list[Pattern] = Field(default_factory=list)
    css: list[Pattern] = Field(default_factory=list)
    js: Mapping[str, list[Pattern]] = Field(default_factory=dict)
    xhr: list[Pattern] = Field(default_factory=list)

    @field_validator("pricing", "implies", "requires", "excludes", mode="before")
    @classmethod
    def parse_strings(cls, v):
        return v if isinstance(v, list) else [v]

    @field_validator("requires_category", mode="before")
    @classmethod
    def parse_numbers(cls, v):
        return v if isinstance(v, list) else [v]

    @field_validator("html", "url", "script_src", "scripts", "css", "xhr", mode="before")
    @classmethod
    def parse_patterns(cls, v):
        return prepare_pattern(v)

    @field_validator("headers", "cookies", mode="before")
    @classmethod
    def parse_headers(cls, v):
        return {k.lower(): prepare_pattern(val) for k, val in v.items()}

    @field_validator("js", mode="before")
    @classmethod
    def parse_js(cls, v):
        return {k: prepare_pattern(val) for k, val in v.items()}

    @field_validator("meta", mode="before")
    @classmethod
    def parse_meta(cls, v):
        thing = {"generator": v} if not isinstance(v, dict) else v
        return {k.lower(): prepare_pattern(val) for k, val in thing.items()}

    @field_validator("dom", mode="before")
    @classmethod
    def parse_dom(cls, v):
        if isinstance(v, str):
            return [DomSelector(selector=v.split("\\;")[0].strip(), exists=True)]

        if isinstance(v, list):
            return [DomSelector(selector=o.split("\\;")[0].strip(), exists=True) for o in v]

        return [
            DomSelector(
                selector=cssselect.split("\\;")[0].strip(),
                exists=True if clause.get("exists") is not None else None,
                text=prepare_pattern(clause["text"]) if clause.get("text") else None,
                attributes=(
                    {k: prepare_pattern(p) for k, p in clause["attributes"].items()}
                    if clause.get("attributes") else None
                ),
            )
            for cssselect, clause in v.items()
        ]
