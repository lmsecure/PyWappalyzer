[English](README.md)

# PyWappalyzer

Python-библиотека для определения веб-технологий через анализ HAR-файлов. Реализует логику Wappalyzer на основе fingerprint-базы [webappanalyzer](https://github.com/enthec/webappanalyzer).

## Преимущества

Данный проект находит **больше** технологий, чем оригинальное браузерное расширение Wappalyzer! А также, если технология была обнаружена внутри другой технологии, то эта цепочка будет показана. Если одна технология, не может существовать без другой технологии, она будет автоматически обнаружена.

## Возможности

- Анализ HAR-файлов: заголовки, cookies, URL скриптов, HTML, DOM, CSS, meta-теги, XHR
- Автоматическая загрузка fingerprint-базы при первом запуске (sparse checkout из GitHub)
- Опциональное подключение runtime-данных из браузера (JS-переменные, live DOM, XHR-URLs) для более точного детектирования
- Постобработка: цепочки `implies`, фильтрация по `requires`/`excludes`, дедупликация с приоритетом по типу источника
- Извлечение версий из fingerprint-паттернов

## Установка

Требует Python 3.12+. Зависимости управляются через [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url>
cd pywappalyzer
uv sync
```

При первом запуске `analyze()` автоматически скачает fingerprint-базу в системный кэш (`~/.cache/pywappalyzer/` на Linux).

## Быстрый старт

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

## Получение HAR-файла

В Chrome/Edge: DevTools → вкладка Network → правая кнопка по любому запросу → **Save all as HAR with content**.

## Расширенный режим: runtime-данные из браузера

Часть fingerprint-паттернов Wappalyzer работает только с данными реального JavaScript runtime — значениями переменных (`window.React.version`), живым DOM после гидрации и XHR-запросами, инициированными JS. HAR-анализ эти данные не содержит.

Для их получения используется DevTools-сниппет. Откройте консоль браузера на нужном сайте и выполните:

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

const paths = []; // здесь должен быть список js переменных из `~/.cache/pywappalyzer/js_paths.json`
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

// или просто `return result;`
```

Сохраните скачанный файл и передайте путь вторым аргументом:

```python
from pywappalyzer import PyWappalyzer

wappalyzer = PyWappalyzer()
har = load_har(path='archive.har')
runtime_data = json.loads(Path('runtime.json').read_text())

detections = wappalyzer.analyze(har=har, runtime_data=runtime_data)
```

## Ограничения HAR-анализа

| Паттерн Wappalyzer | HAR | Runtime |
|--------------------|-----|---------|
| `headers` | ✅ | — |
| `cookies` | ✅ | — |
| `scriptSrc` | ✅ | — |
| `html`, `meta`, `css`, `url` | ✅ | — |
| `dom` | ✅ (static) | ✅ (live) |
| `xhr` | ⚠️ частично | ✅ |
| `js` (window variables) | ❌ | ✅ |
| `dns`, `robots`, `certIssuer` | ❌ | ❌ |

Некоторые заголовки (например, `Server` от Nginx) доступны только через `webRequest.onHeadersReceived` браузерного расширения и отсутствуют в HAR-экспорте DevTools.

## API

### `PyWappalyzer.analyze(har, runtime_data=None) → list[Detection]`

| Параметр | Тип | Описание |
|----------|-----|----------|
| `har` | `Har` | HAR-архив |
| `runtime_data` | `dict \| None` | runtime JSON данные (опционально) |

### `Detection`

| Поле | Тип | Описание |
|------|-----|----------|
| `fingerprint.id` | `str` | Название технологии (напр. `"React"`) |
| `resolved_version` | `str` | Версия, если удалось извлечь |
| `app_type` | `str` | Тип паттерна (`headers`, `scriptSrc`, ...) |
| `categories` | `list[Category]` | Категории Wappalyzer |
| `groups` | `list[Group]` | Группы Wappalyzer |
| `via` | `str \| None` | Через какую технологию определено (`implies`) |

## Похожие проекты, которые провалились

Проект, который выдаёт крайне мало информации по har архиву [py-wappalyzer](https://github.com/PigeonSec/py-wappalyzer)
Устаревшие проекты [python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer) [wappylyzer](https://github.com/vincd/wappylyzer) [pywappalyzer](https://github.com/Kel0/pywappalyzer)
Под капотом используется браузер и оригинальное расширение Wappalyzer [wappalyzer-next](https://github.com/s0md3v/wappalyzer-next)
