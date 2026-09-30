"""Round-trip tests for dependency-free token embedding in JPEG/PNG."""

import struct
import zlib

import pytest

from cashu.nft.imgmeta import embed_token, extract_token

TOKEN1 = "pshow1" + "ab" * 200
TOKEN2 = "psnft1" + "cd" * 100


def minimal_jpeg(with_exif: bool = False) -> bytes:
    """SOI + JFIF APP0 (+ optionally a UserComment-less EXIF APP1) + SOS +
    a byte of entropy data + EOI."""
    app0 = b"\xff\xe0" + (16).to_bytes(2, "big") + b"JFIF\x00" + b"\x00" * 9
    parts = [b"\xff\xd8", app0]
    if with_exif:
        # EXIF APP1 with an empty IFD0: valid enough for our parser to walk
        tiff = b"II" + (42).to_bytes(2, "little") + (8).to_bytes(4, "little")
        tiff += (0).to_bytes(2, "little") + (0).to_bytes(4, "little")
        payload = b"Exif\x00\x00" + tiff
        parts.append(b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload)
    parts.append(b"\xff\xda" + (10).to_bytes(2, "big") + b"\x00" * 8)
    parts.append(b"\x12\x34")  # entropy-coded data
    parts.append(b"\xff\xd9")
    return b"".join(parts)


def png_1x1() -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + ctype
            + data
            + struct.pack(">I", zlib.crc32(ctype + data))
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\x01\x02\x03"  # filter byte + one RGB pixel
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_jpeg_roundtrip():
    data = minimal_jpeg()
    embedded = embed_token(data, TOKEN1)
    assert extract_token(embedded) == TOKEN1
    # our APP1 sits right after SOI, the rest of the file is untouched
    # segment = FF E1 + uint16BE length (= 2 + payload len) + payload
    seg_len = 2 + int.from_bytes(embedded[4:6], "big")
    assert embedded[6:12] == b"Exif\x00\x00"
    assert embedded[2 + seg_len :] == data[2:]


def test_jpeg_embed_after_existing_exif():
    # a file with a UserComment-less EXIF APP1 gets a SECOND APP1 with ours
    data = minimal_jpeg(with_exif=True)
    embedded = embed_token(data, TOKEN1)
    assert embedded.count(b"Exif\x00\x00") == 2
    assert extract_token(embedded) == TOKEN1


def test_jpeg_latest_token_wins():
    data = minimal_jpeg()
    embedded = embed_token(embed_token(data, TOKEN1), TOKEN2)
    assert extract_token(embedded) == TOKEN2
    assert embedded.count(b"Exif\x00\x00") == 2


def test_jpeg_extract_clean_returns_none():
    assert extract_token(minimal_jpeg()) is None
    assert extract_token(minimal_jpeg(with_exif=True)) is None


def test_png_roundtrip():
    data = png_1x1()
    embedded = embed_token(data, TOKEN1)
    assert extract_token(embedded) == TOKEN1
    # the tEXt chunk lands right before IEND; everything else is untouched
    iend = data[-12:]
    assert embedded[-12:] == iend
    assert embedded[: len(data) - 12] == data[:-12]


def test_png_latest_token_wins():
    data = png_1x1()
    embedded = embed_token(embed_token(data, TOKEN1), TOKEN2)
    assert extract_token(embedded) == TOKEN2
    assert embedded.count(b"PSNFT\x00") == 2


def test_png_extract_clean_returns_none():
    assert extract_token(png_1x1()) is None


def test_unsupported_types_rejected():
    gif = b"GIF89a" + b"\x00" * 20
    webp = b"RIFF" + b"\x10\x00\x00\x00" + b"WEBP" + b"\x00" * 8
    for blob in (gif, webp, b"not an image at all"):
        with pytest.raises(ValueError, match="JPEG and PNG only"):
            embed_token(blob, TOKEN1)
        with pytest.raises(ValueError, match="JPEG and PNG only"):
            extract_token(blob)


def test_non_ascii_token_rejected():
    with pytest.raises(ValueError, match="ASCII"):
        embed_token(png_1x1(), "pshow1€")


def test_extract_truncated_png_raises():
    with pytest.raises(ValueError):
        extract_token(png_1x1()[:-10])


def test_extract_truncated_jpeg_returns_none():
    embedded = embed_token(minimal_jpeg(), TOKEN1)
    assert extract_token(embedded[:20]) is None
