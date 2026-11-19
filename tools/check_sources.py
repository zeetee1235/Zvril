"""Verify the vendored source subset against its pinned Git blob hashes."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for name in ('sources','corpus'):
    lock = json.loads((root / f"third_party/{name}.lock.json").read_text())
    for item in lock["files"]:
        data = (root / item["path"]).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != item["sha"]:
            raise SystemExit("Source checksum mismatch: " + item["path"])
    print(f"Verified {len(lock['files'])} pinned {name} blobs")
