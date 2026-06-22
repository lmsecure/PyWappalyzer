import json
from pathlib import Path

from pywappalyzer import PyWappalyzer, load_har

if __name__ == "__main__":
    wappalyzer = PyWappalyzer()
    har = load_har(path='archive.har')
    runtime_data = json.loads(Path('runtime.json').read_text())

    detections = wappalyzer.analyze(har=har, runtime_data=runtime_data)

    result = {}
    for d in detections:
        name = d.fingerprint.id
        version = d.resolved_version
        if name not in result:
            result[name] = {
                "version": version,
                "type": d.app_type,
                "via": d.via,
                "categories": [c.name for c in d.categories] if d.categories else [],
                "groups": [g.name for g in d.groups] if d.groups else [],
                "oss": d.fingerprint.oss,
                "saas": d.fingerprint.saas,
            }

    for name, info in sorted(result.items()):
        via = info["via"]
        chain = f" [via {via}]" if via else ""
        print(f"{name}{chain}: {info}")