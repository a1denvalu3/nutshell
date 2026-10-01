"""A transfer envelope never participates in the asset's byte identity."""

import io
import warnings
from typing import Optional, Tuple

from PIL import Image, ImageOps, UnidentifiedImageError

from .imgmeta import embed_token, extract_token

MAX_PIXELS = 25_000_000


def validate_jpg(data: bytes) -> None:
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("Only JPG files are supported.")
    if not data.endswith(b"\xff\xd9"):
        raise ValueError("This JPG is truncated or has bytes after its end marker.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "JPEG":
                    raise ValueError("Only JPG files are supported.")
                if image.width * image.height > MAX_PIXELS:
                    raise ValueError("Use a JPG with at most 25 million pixels.")
                image.verify()
    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        raise ValueError("This JPG is damaged or too large to decode safely.")


def split_transfer_jpg(data: bytes) -> Tuple[bytes, Optional[str]]:
    """Remove only our exact EXIF envelope; preserve every other byte.

    Duplicate envelopes are ambiguous and rejected, including identical copies.
    Matching by the complete segment prevents deleting arbitrary user metadata.
    """
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("Only JPG files are supported.")
    pos = 2
    chunks = [data[:2]]
    token: Optional[str] = None
    while pos < len(data):
        start = pos
        if data[pos] != 0xFF:
            raise ValueError("Invalid JPG marker.")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            raise ValueError("Truncated JPG marker.")
        marker = data[pos]
        pos += 1
        if marker in (0xDA, 0xD9):
            chunks.append(data[start:])
            return b"".join(chunks), token
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            chunks.append(data[start:pos])
            continue
        if pos + 2 > len(data):
            raise ValueError("Truncated JPG segment.")
        length = int.from_bytes(data[pos : pos + 2], "big")
        end = pos + length
        if length < 2 or end > len(data):
            raise ValueError("Truncated JPG segment.")
        segment = data[start:end]
        embedded = extract_token(b"\xff\xd8" + segment + b"\xff\xd9")
        dedicated = (
            embedded is not None
            and embedded.startswith("psnft1")
            and segment == embed_token(b"\xff\xd8\xff\xd9", embedded)[2:-2]
        )
        if dedicated:
            if token is not None:
                raise ValueError("This JPG contains multiple transfer tokens.")
            token = embedded
        else:
            chunks.append(segment)
        pos = end
    raise ValueError("Truncated JPG.")


def normalize_jpg(data: bytes) -> bytes:
    validate_jpg(data)
    _, token = split_transfer_jpg(data)
    if token is not None:
        raise ValueError("This is a transfer JPG. Use Receive JPG to collect it.")
    with Image.open(io.BytesIO(data)) as source:
        icc = source.info.get("icc_profile")
        try:
            # verify() does not decode scan data; truncation surfaces here.
            image = ImageOps.exif_transpose(source).convert("RGB")
        except OSError:
            raise ValueError("This JPG is damaged or too large to decode safely.")
        output = io.BytesIO()
        image.save(
            output,
            format="JPEG",
            quality=95,
            subsampling=0,
            optimize=True,
            icc_profile=icc,
        )
        return output.getvalue()
