import base64
from functools import cached_property
from selectolax.parser import HTMLParser
from urllib.parse import urlparse

from .schemas.har import Har, Entry, Content


class HarWrapper():
    def __init__(self, har: Har):
        self.har = har
        self.js_mime_types = (
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "text/x-javascript",
            "application/ecmascript",
            "text/ecmascript",
        )
        
    @cached_property
    def scripts_with_url(self) -> list[tuple[str, str]]:
        return [
            (str(entry.request.url), text)
            for entry in self.javascript_entries
            if (text := self._decode_content(entry.response.content))
        ]

    @cached_property
    def inline_scripts_with_url(self) -> list[tuple[str, str]]:
        result = []
        for tag in self.dom.css("script:not([src])"):
            text = tag.text()
            if text and text.strip():
                result.append((self.url, text))
        return result

    @cached_property
    def all_scripts_with_url(self) -> list[tuple[str, str]]:
        return self.inline_scripts_with_url + self.scripts_with_url

    @cached_property
    def stylesheets_with_url(self) -> list[tuple[str, str]]:
        return [
            (str(entry.request.url), text)
            for entry in self.stylesheet_entries
            if (text := self._decode_content(entry.response.content))
        ]
    
    @cached_property
    def stylesheet_entries(self):
        return [entry for entry in self.har.log.entries if self.is_stylesheet(entry)]

    @cached_property
    def javascript_entries(self):
        return [entry for entry in self.har.log.entries if self.is_javascript(entry)]

    @cached_property
    def script_src(self):
        return [entry.request.url for entry in self.javascript_entries]

    @cached_property
    def html_entry(self):
        for entry in self.har.log.entries:
            if self.is_html(entry) and 200 <= entry.response.status < 300:
                return entry
        return None

    @cached_property
    def url(self):
        if self.html_entry is None:
            return ""
        return str(self.html_entry.request.url)

    @cached_property
    def html(self) -> str:
        if self.html_entry is None:
            return ""
        return self._decode_content(self.html_entry.response.content) or ""

    @cached_property
    def headers(self):
        main_domain = self._get_main_domain(self.url)
        memo: dict[str, str] = {}
        for entry in self.har.log.entries:
            host = urlparse(str(entry.request.url)).hostname or ""
            if not host.endswith(main_domain):
                continue
            for header in entry.response.headers:
                memo.setdefault(header.name.lower(), header.value)
        return memo

    @cached_property
    def cookies(self):
        main_domain = self._get_main_domain(self.url)
        memo: dict[str, str] = {}
        for entry in self.har.log.entries:
            host = urlparse(str(entry.request.url)).hostname or ""
            if not host.endswith(main_domain):
                continue
            for cookie in entry.response.cookies:
                memo.setdefault(cookie.name.lower(), cookie.value)
        return memo

    @cached_property
    def dom(self):
        return HTMLParser(self.html)

    @cached_property
    def meta(self):
        memo: dict[str, str] = {}

        for meta in self.dom.css("meta"):
            name = meta.attributes.get("name")
            content = meta.attributes.get("content")
            if name and content:
                memo[name.lower()] = content

        return memo
    
    def _get_main_domain(self, url: str) -> str:
        host = urlparse(url).hostname or ""
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _decode_content(self, content: Content) -> str | None:
        text = content.text
        if not text:
            return None
        if content.encoding == "base64":
            return base64.b64decode(text).decode("utf-8", errors="replace")
        return text

    def is_javascript(self, entry: Entry) -> bool:
        mime = entry.response.content.mime_type.split(";")[0].strip().lower()
        url = str(entry.request.url).split("?")[0]
        by_mime = mime.startswith(self.js_mime_types)
        by_ext = url.endswith((".js", ".mjs", ".cjs"))
        return entry.request.method == "GET" and (by_mime or by_ext)


    def is_stylesheet(self, entry: Entry) -> bool:
        return (
            entry.request.method == "GET"
            and entry.response.content.mime_type.startswith("text/css")
        )


    def is_html(self, entry: Entry) -> bool:
        return (
            entry.request.method == "GET"
            and entry.response.content.mime_type.startswith("text/html")
        )