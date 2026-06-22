from .schemas.detection import Detection
from .schemas.har import Har
from .har_wrapper import HarWrapper
from .analyzer import Analyzer
from .handler import Handler
from .loaders import load_categories, load_fingerprints, load_groups
from .download_data import ensure_fingerprint_files


class PyWappalyzer:
    def analyze(self, har: Har, runtime_data: dict | None = None) -> list[Detection]:
        ensure_fingerprint_files()
        js_vars: dict[str, str] = {}
        live_dom_html: str | None = None
        xhr_urls: list[str] = []

        if runtime_data is not None:
            js_vars = runtime_data.get("js_vars", {})
            live_dom_html = runtime_data.get("dom_html")
            xhr_urls = runtime_data.get("xhr_urls", [])

        fingerprints = load_fingerprints()
        groups = load_groups()
        categories = load_categories()
        har_wrapper = HarWrapper(har=har)
        analyzer = Analyzer(har_wrapper=har_wrapper, live_dom_html=live_dom_html)
        
        handler = Handler(fingerprints=fingerprints, groups=groups, categories=categories)

        detections = []
        analyzers = [
            analyzer.analyze_url,
            analyzer.analyze_headers,
            analyzer.analyze_script_src,
            analyzer.analyze_cookies,
            analyzer.analyze_scripts,
            analyzer.analyze_css,
            analyzer.analyze_meta,
            analyzer.analyze_html,
            analyzer.analyze_dom,
        ]

        for fingerprint in fingerprints.values():
            for fn in analyzers:
                detections.extend(fn(fingerprint))
            if js_vars:
                detections.extend(analyzer.analyze_js(fingerprint, js_vars))
            if xhr_urls:
                detections.extend(analyzer.analyze_xhr(fingerprint, xhr_urls))
            
        detections = handler.filter_by_requires(detections)
        detections = handler.filter_by_requires_category(detections)
        detections = handler.filter_by_excludes(detections)
        detections = handler.resolve_implies(detections)
        detections = handler.build_detection_chains(detections)
        detections = handler.set_categories(detections)
        detections = handler.set_groups(detections)
        detections = handler.deduplicate(detections)

        return detections
