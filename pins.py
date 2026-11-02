"""Hash baselines: detect files that changed since a skill was last pinned (rug-pull style swaps)."""
import json
import os
import tempfile


def _path():
    # read env per call so tests can point it at a temp dir
    return os.path.join(os.environ.get("SKILL_SCAN_HOME", os.path.expanduser("~/.skill-scan")), "pins.json")


def _load():
    try:
        with open(_path(), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(pins):
    p = _path()
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(pins, f)
    os.replace(tmp, p)


def check(key, hashes, repin=False):
    """Compare hashes to the stored baseline for key. First sight (or repin) stores the baseline."""
    pins = _load()
    base = pins.get(key)
    if base is None or repin:
        pins[key] = hashes
        _save(pins)
        return {"status": "new" if base is None else "repinned", "changed": [], "added": [], "removed": []}
    changed = sorted(f for f in hashes if f in base and base[f] != hashes[f])
    added = sorted(f for f in hashes if f not in base)
    removed = sorted(f for f in base if f not in hashes)
    return {"status": "changed" if changed or added or removed else "same",
            "changed": changed, "added": added, "removed": removed}
