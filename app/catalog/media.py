"""Image validation and storage (PRD-005, V13-SEC-004, V13-REQ-005, NFR-M06).

Every upload is: size-limited while reading, sniffed by magic bytes (the client's declared
type is ignored), fully decoded by Pillow with a decompression-bomb limit, dimension-checked,
then RE-ENCODED to a clean WebP. Re-encoding drops EXIF (including GPS location), ICC tricks
and any appended payload, so the stored file is always a plain image we produced ourselves.
Storage is behind a small interface so production can use object storage + CDN (M20).
"""

from __future__ import annotations

import hashlib
import io
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 5 * 1024 * 1024          # NFR-M06: 5 MB per image
MAX_SIDE = 6000
MIN_SIDE = 100
OUTPUT_MAX_SIDE = 1600
Image.MAX_IMAGE_PIXELS = 36_000_000   # decompression-bomb guard

MAGIC = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
}


class ImageRejected(ValueError):
    """Raised with a Swahili message suitable for the seller."""


@dataclass(frozen=True)
class CleanImage:
    data: bytes
    content_type: str
    width: int
    height: int
    sha256: str


def sniff(head: bytes) -> str | None:
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WEBP"
    return None


def read_limited(stream, limit: int = MAX_BYTES) -> bytes:
    buf = bytearray()
    while chunk := stream.read(64 * 1024):
        buf.extend(chunk)
        if len(buf) > limit:
            raise ImageRejected("Picha ni kubwa mno (zaidi ya MB 5).")
    if not buf:
        raise ImageRejected("Faili la picha ni tupu.")
    return bytes(buf)


def clean_image(raw: bytes) -> CleanImage:
    if len(raw) > MAX_BYTES:
        raise ImageRejected("Picha ni kubwa mno (zaidi ya MB 5).")
    kind = sniff(raw[:16])
    if kind is None:
        raise ImageRejected("Tunapokea picha za JPEG, PNG au WebP tu.")
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            if probe.format != kind:
                raise ImageRejected("Aina ya faili hailingani na maudhui yake.")
            probe.verify()  # structural check
        with Image.open(io.BytesIO(raw)) as img:
            img.load()      # full decode (catches truncated/corrupt data)
            w, h = img.size
            if max(w, h) > MAX_SIDE or min(w, h) < MIN_SIDE:
                raise ImageRejected(f"Ukubwa wa picha uwe kati ya pikseli {MIN_SIDE} na {MAX_SIDE}.")
            img = ImageOps.exif_transpose(img)
            img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB")
            img.thumbnail((OUTPUT_MAX_SIDE, OUTPUT_MAX_SIDE))
            out = io.BytesIO()
            img.save(out, format="WEBP", quality=82, method=4)  # no exif/icc passed => stripped
    except ImageRejected:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise ImageRejected("Picha imeharibika au si picha halali.") from exc
    data = out.getvalue()
    with Image.open(io.BytesIO(data)) as final:
        fw, fh = final.size
    return CleanImage(data=data, content_type="image/webp", width=fw, height=fh,
                      sha256=hashlib.sha256(data).hexdigest())


# ---------------------------------------------------------------- storage
class Storage(Protocol):
    def put(self, key: str, data: bytes, content_type: str) -> None: ...
    def get(self, key: str) -> bytes | None: ...


class LocalStorage:
    """Filesystem store for development and single-server deployments (object storage in M20)."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not key.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid storage key")
        return self.root / key[:2] / key

    def put(self, key: str, data: bytes, content_type: str) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def get(self, key: str) -> bytes | None:
        try:
            path = self._path(key)
        except ValueError:
            return None
        return path.read_bytes() if path.is_file() else None


def new_storage_key() -> str:
    return secrets.token_urlsafe(24).replace("-", "a").replace("_", "b")
