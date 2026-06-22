from datetime import datetime

from pydantic import Field

from .base import APISchema


class Header(APISchema):
    name: str
    value: str


class Cookie(APISchema):
    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    http_only: bool | None = None
    secure: bool | None = None


class Content(APISchema):
    size: int = 0
    mime_type: str = ""
    text: str | None = None
    encoding: str | None = None


class Request(APISchema):
    method: str
    url: str
    http_version: str = ""
    headers: list[Header] = Field(default_factory=list)
    cookies: list[Cookie] = Field(default_factory=list)


class Response(APISchema):
    status: int
    status_text: str = ""
    http_version: str = ""
    headers: list[Header] = Field(default_factory=list)
    cookies: list[Cookie] = Field(default_factory=list)
    content: Content
    redirect_url: str = Field("", alias="redirectURL")


class Entry(APISchema):
    pageref: str | None = None
    started_date_time: datetime | None = None
    time: float = 0.0
    request: Request
    response: Response
    server_ip_address: str | None = Field(None, alias="serverIPAddress")
    connection: str | None = None


class Log(APISchema):
    entries: list[Entry]


class Har(APISchema):
    log: Log