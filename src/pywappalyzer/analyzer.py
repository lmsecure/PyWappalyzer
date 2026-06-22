import fnmatch
from selectolax.parser import HTMLParser

import regex
# from loguru import logger

from .schemas.detection import Detection
from .schemas.patterns import Pattern
from .schemas.fingerprints import Fingerprint
from .har_wrapper import HarWrapper


class Analyzer:
    def __init__(self, har_wrapper: HarWrapper, live_dom_html: str | None = None):
        self.har_wrapper = har_wrapper
        self._dom = HTMLParser(live_dom_html) if live_dom_html else har_wrapper.dom

    def _replace_ternary(self, version: str, groups: list[str]) -> str:
        return regex.sub(
            r'\\(\d+)\?([^:]*):(.*?)(?=\\|$)',
            lambda m: m.group(2) if groups[int(m.group(1)) - 1] else m.group(3),
            version
        )

    def resolve_version(self, pattern: Pattern, match: regex.Match) -> str:
        if not pattern.version:
            return ""

        version = pattern.version
        groups = [g or "" for g in match.groups()]

        version = self._replace_ternary(version, groups)

        for i, group in enumerate(groups, 1):
            version = version.replace(f"\\{i}", group)

        return version.strip()
    
    def analyze_script_src(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []
        for pattern in fingerprint.script_src:
            for url in self.har_wrapper.script_src:
                url_str = str(url)
                match = pattern.rx.search(url_str)
                if not match:
                    continue

                # Проверяем что совпадение не упало внутрь hex-hash сегмента.
                # Символ перед началом совпадения должен быть разделителем пути.
                start = match.start()
                match_text = url_str[match.start():match.end()]
                if not match_text.startswith('/') and start > 0 and url_str[start - 1] not in "/._-":
                    continue

                detections.append(
                    Detection.model_construct(
                        url=self.har_wrapper.url,
                        fingerprint=fingerprint,
                        app_type="script_src",
                        pattern=pattern,
                        value=url_str,
                        resolved_version=self.resolve_version(pattern, match),
                    )
                )
        return detections

    def analyze_url(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []

        for pattern in fingerprint.url:
            match = pattern.rx.search(self.har_wrapper.url)
            if match:
                detections.append(
                    Detection.model_construct(
                        url=self.har_wrapper.url,
                        fingerprint=fingerprint,
                        app_type="url",
                        pattern=pattern,
                        value=self.har_wrapper.url,
                        resolved_version=self.resolve_version(pattern, match),
                    )
                )

        return detections

    def analyze_headers(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []

        for name, patterns in fingerprint.headers.items():
            if name not in self.har_wrapper.headers:
                continue

            content = self.har_wrapper.headers[name]
            for pattern in patterns:
                match = pattern.rx.search(content)
                if match:
                    detections.append(
                        Detection.model_construct(
                            url=self.har_wrapper.url,
                            fingerprint=fingerprint,
                            app_type="headers",
                            pattern=pattern,
                            value=content,
                            key=name,
                            resolved_version=self.resolve_version(pattern, match),
                        )
                    )

        return detections

    def analyze_cookies(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []

        for name_pattern, patterns in fingerprint.cookies.items():
            matching = {
                k: v for k, v in self.har_wrapper.cookies.items()
                if fnmatch.fnmatch(k, name_pattern)
            }
            for cookie_name, content in matching.items():
                for pattern in patterns:
                    match = pattern.rx.search(content)
                    if match:
                        detections.append(Detection.model_construct(
                            url=self.har_wrapper.url,
                            fingerprint=fingerprint,
                            app_type="cookies",
                            pattern=pattern,
                            value=content,
                            key=cookie_name,
                            resolved_version=self.resolve_version(pattern, match),
                        ))

        return detections

    def analyze_scripts(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []
        for pattern in fingerprint.scripts:
            for source_url, script in self.har_wrapper.all_scripts_with_url:
                match = pattern.rx.search(script)
                if match:
                    detections.append(Detection.model_construct(
                        url=self.har_wrapper.url,
                        source_url=source_url,
                        fingerprint=fingerprint,
                        app_type="scripts",
                        pattern=pattern,
                        value=match.group(0)[:100],
                        resolved_version=self.resolve_version(pattern, match),
                    ))
        return detections


    def analyze_css(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []
        for pattern in fingerprint.css:
            for source_url, stylesheet in self.har_wrapper.stylesheets_with_url:
                match = pattern.rx.search(stylesheet)
                if match:
                    detections.append(Detection.model_construct(
                        url=self.har_wrapper.url,
                        source_url=source_url,
                        fingerprint=fingerprint,
                        app_type="css",
                        pattern=pattern,
                        value=match.group(0)[:100],
                        resolved_version=self.resolve_version(pattern, match),
                    ))
        return detections


    def analyze_meta(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []

        for name, patterns in fingerprint.meta.items():
            if name in self.har_wrapper.meta:
                content = self.har_wrapper.meta[name]
                for pattern in patterns:
                    match = pattern.rx.search(content)
                    if match:
                        detections.append(
                            Detection.model_construct(
                                url=self.har_wrapper.url,
                                fingerprint=fingerprint,
                                app_type="meta",
                                pattern=pattern,
                                value=content,
                                key=name,
                                resolved_version=self.resolve_version(pattern, match),
                            )
                        )

        return detections


    def analyze_html(self, fingerprint: Fingerprint) -> list[Detection]:
        if not self.har_wrapper.html:
            return []
        
        detections: list[Detection] = []
        for pattern in fingerprint.html:
            match = pattern.rx.search(self.har_wrapper.html)
            if match:
                detections.append(
                    Detection.model_construct(
                        url=self.har_wrapper.url,
                        fingerprint=fingerprint,
                        app_type="html",
                        pattern=pattern,
                        value=match.group(0)[:100],
                        resolved_version=self.resolve_version(pattern, match),
                    )
                )
        return detections


    def analyze_dom(self, fingerprint: Fingerprint) -> list[Detection]:
        detections: list[Detection] = []

        for selector in fingerprint.dom:
            try:
                elements = list(self._dom.css(selector.selector))
            except ValueError as e:
                # logger.debug("Invalid CSS selector {!r} ({}): {}", selector.selector, fingerprint.id, e)
                continue
            if not elements:
                continue

            if selector.exists:
                detections.append(Detection.model_construct(
                    url=self.har_wrapper.url,
                    source_url="",
                    fingerprint=fingerprint,
                    app_type="dom",
                    pattern=Pattern(string=selector.selector),
                    value="",
                    key="",
                    resolved_version="",
                    via=None,
                    categories=None,
                    groups=None,
                ))

            for item in elements:
                if selector.text:
                    for pattern in selector.text:
                        html = item.html
                        if html:
                            match = pattern.rx.search(html)
                            if match:
                                detections.append(Detection.model_construct(
                                    url=self.har_wrapper.url,
                                    source_url="",
                                    fingerprint=fingerprint,
                                    app_type="dom",
                                    pattern=pattern,
                                    value=html,
                                    key="",
                                    resolved_version=self.resolve_version(pattern, match),
                                    via=None,
                                    categories=None,
                                    groups=None,
                                ))

                if selector.attributes:
                    for name, patterns in selector.attributes.items():
                        content = item.attributes.get(name)
                        if not content:
                            continue
                        content = str(content)
                        for pattern in patterns:
                            match = pattern.rx.search(content)
                            if match:
                                detections.append(Detection.model_construct(
                                    url=self.har_wrapper.url,
                                    source_url="",
                                    fingerprint=fingerprint,
                                    app_type="xhr",
                                    pattern=pattern,
                                    value=content,
                                    key=name,
                                    resolved_version=self.resolve_version(pattern, match),
                                    via=None,
                                    categories=None,
                                    groups=None,
                                ))

        return detections
    
    def analyze_js(self, fingerprint: Fingerprint, js_vars: dict[str, str]) -> list[Detection]:
        detections: list[Detection] = []

        for key, patterns in fingerprint.js.items():
            normalized = key.removeprefix("window.")
            value = js_vars.get(key)
            if value is None:
                value = js_vars.get(normalized)
            if value is None:
                continue

            value_str = str(value)
            for pattern in patterns:
                if not pattern.string:
                    detections.append(Detection.model_construct(
                        url=self.har_wrapper.url,
                        source_url="",
                        fingerprint=fingerprint,
                        app_type="js",
                        pattern=pattern,
                        value=value_str,
                        key=key,
                        resolved_version="",
                        via=None,
                        categories=None,
                        groups=None,
                    ))
                    break

                if value_str == "[object]":
                    continue

                match = pattern.rx.search(value_str)
                if match:
                    detections.append(Detection.model_construct(
                        url=self.har_wrapper.url,
                        source_url="",
                        fingerprint=fingerprint,
                        app_type="js",
                        pattern=pattern,
                        value=value_str,
                        key=key,
                        resolved_version=self.resolve_version(pattern, match),
                        via=None,
                        categories=None,
                        groups=None,
                    ))

        return detections
    
    def analyze_xhr(self, fingerprint: Fingerprint, xhr_urls: list[str]) -> list[Detection]:
        detections: list[Detection] = []
        for pattern in fingerprint.xhr:
            for url in xhr_urls:
                match = pattern.rx.search(url)
                if match:
                    detections.append(Detection.model_construct(
                        url=self.har_wrapper.url,
                        source_url="",
                        fingerprint=fingerprint,
                        app_type="xhr",
                        pattern=pattern,
                        value=url,
                        key="",
                        resolved_version=self.resolve_version(pattern, match),
                        via=None,
                        categories=None,
                        groups=None,
                    ))
        return detections