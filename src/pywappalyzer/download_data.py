import json
import shutil
from pathlib import Path

import git
from platformdirs import user_cache_dir

CACHE_DIR = Path(user_cache_dir("pywappalyzer"))
REPO_URL = "https://github.com/enthec/webappanalyzer.git"

SPARSE_PATHS = [
    "src/categories.json",
    "src/groups.json",
    "src/technologies/",
]


def ensure_fingerprint_files(force: bool = False):
    if force and CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
    tech_dir = CACHE_DIR / "src" / "technologies"
    if tech_dir.exists() and any(tech_dir.glob("*.json")):
        return

    print("Downloading webappanalyzer fingerprints (first run only)...")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    repo = git.Repo.clone_from(
        REPO_URL,
        str(CACHE_DIR),
        multi_options=[
            "--depth=1",
            "--filter=blob:none",
            "--no-checkout",
        ],
    )

    repo.git.sparse_checkout("init", "--no-cone")
    repo.git.sparse_checkout("set", *SPARSE_PATHS)
    repo.git.checkout()

    repo.close()
    shutil.rmtree(CACHE_DIR / ".git")

    print(f"Done, saved to {CACHE_DIR}")
    generate_js_paths()


def collect_js_paths() -> list[str]:
    tech_dir = CACHE_DIR / "src" / "technologies"
    paths: set[str] = set()

    for json_file in sorted(tech_dir.glob("*.json")):
        try:
            technologies: dict = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        for tech in technologies.values():
            js = tech.get("js")
            if isinstance(js, dict):
                paths.update(js.keys())

    return sorted(paths)


def generate_js_paths():
    paths = collect_js_paths()

    output_path = CACHE_DIR / "js_paths.json"
    output_path.write_text(json.dumps(paths, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Generated {len(paths)} JS paths → {output_path}")