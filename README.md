[Русский](README_RU.md)

# PyWappalyzer

A Python library for web technology detection via HAR file analysis. Implements Wappalyzer logic using the [webappanalyzer](https://github.com/enthec/webappanalyzer) fingerprint database.

## Advantages

This project detects **more technologies** than the original Wappalyzer browser extension. If a technology was detected through another technology, the full implication chain is shown. If one technology cannot exist without another, it will be detected automatically.

## Features

- HAR file analysis: headers, cookies, script URLs, HTML, DOM, CSS, meta tags, XHR
- Automatic fingerprint database download on first run (sparse checkout from GitHub)
- Optional runtime data from the browser (JS variables, live DOM, XHR URLs) for more accurate detection
- Post-processing: `implies` chains, `requires`/`excludes` filtering, deduplication with source-type priority
- Version extraction from fingerprint patterns

## Installation

Requires Python 3.12+. Dependencies are managed via [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url>
cd pywappalyzer
uv sync
```

On the first `analyze()` call, the fingerprint database will be automatically downloaded to the system cache (`~/.cache/pywappalyzer/` on Linux).

## Quick Start

```python
from pywappalyzer import PyWappalyzer

wappalyzer = PyWappalyzer()
har = load_har(path='archive.har')
runtime_data = json.loads(Path('runtime.json').read_text())

detections = wappalyzer.analyze(har=har, runtime_data=runtime_data)

for d in detections:
    version = f" {d.resolved_version}" if d.resolved_version else ""
    cats = ", ".join(c.name for c in d.categories) if d.categories else "—"
    print(f"{d.fingerprint.id}{version}  [{cats}]")
```

## Capturing a HAR File

In Chrome/Edge: DevTools → Network tab → right-click any request → **Save all as HAR with content**.

## Advanced: Runtime Data from the Browser

Some Wappalyzer fingerprint patterns only work with real JavaScript runtime data — variable values (`window.React.version`), live post-hydration DOM, and XHR requests initiated by JS. HAR analysis does not capture this data.

To collect it, use the DevTools snippet below. Open the browser console on the target page and run:

```javascript
function resolvePath(obj, path) {
    return path.split('.').reduce((acc, key) => {
        try { return acc?.[key] } catch { return undefined }
    }, obj);
}

function serializeValue(v) {
    if (v === null || v === undefined) return null;
    if (typeof v === 'function' || typeof v === 'object') return "[object]";
    return String(v);
}

const paths = []; // paste the JS variable list from `~/.cache/pywappalyzer/js_paths.json`
const jsVars = {};
for (const path of paths) {
    const val = serializeValue(resolvePath(window, path));
    if (val !== null)
        jsVars[path] = val;
}

const result = {
    js_vars: jsVars,
    dom_html: document.documentElement.outerHTML,
    xhr_urls: performance.getEntriesByType("resource").map(e => e.name),
};

const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url;
a.download = "result.json";
document.body.appendChild(a);
a.click();
document.body.removeChild(a);
URL.revokeObjectURL(url);

console.log(`js_vars: ${Object.keys(jsVars).length}, xhr_urls: ${result.xhr_urls.length}`);

// or simply `return result;`
```

Save the downloaded file and pass its path as the second argument:

```python
from pywappalyzer import PyWappalyzer

wappalyzer = PyWappalyzer()
har = load_har(path='archive.har')
runtime_data = json.loads(Path('runtime.json').read_text())

detections = wappalyzer.analyze(har=har, runtime_data=runtime_data)
```

## HAR Analysis Limitations

| Wappalyzer Pattern | HAR | Runtime |
|--------------------|-----|---------|
| `headers` | ✅ | — |
| `cookies` | ✅ | — |
| `scriptSrc` | ✅ | — |
| `html`, `meta`, `css`, `url` | ✅ | — |
| `dom` | ✅ (static) | ✅ (live) |
| `xhr` | ⚠️ partial | ✅ |
| `js` (window variables) | ❌ | ✅ |
| `dns`, `robots`, `certIssuer` | ❌ | ❌ |

Some response headers (e.g. `Server` from Nginx) are only accessible via `webRequest.onHeadersReceived` in a browser extension and are absent from DevTools HAR exports.

## API

### `PyWappalyzer.analyze(har, runtime_data=None) → list[Detection]`

| Parameter | Type | Description |
|-----------|------|-------------|
| `har` | `Har` | HAR archive |
| `runtime_data` | `dict \| None` | Runtime JSON data (optional) |

### `Detection`

| Field | Type | Description |
|-------|------|-------------|
| `fingerprint.id` | `str` | Technology name (e.g. `"React"`) |
| `resolved_version` | `str` | Extracted version, if available |
| `app_type` | `str` | Pattern type (`headers`, `scriptSrc`, …) |
| `categories` | `list[Category]` | Wappalyzer categories |
| `groups` | `list[Group]` | Wappalyzer groups |
| `via` | `str \| None` | Technology through which this was detected (`implies`) |

## Related Projects That Failed

[py-wappalyzer](https://github.com/PigeonSec/py-wappalyzer) — returns very little information from HAR archives.

Abandoned projects: [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer), [wappylyzer](https://github.com/vincd/wappylyzer), [pywappalyzer](https://github.com/Kel0/pywappalyzer).

[wappalyzer-next](https://github.com/s0md3v/wappalyzer-next) — runs a real browser with the original Wappalyzer extension under the hood.
