from base64 import b32decode as _b32decode
from typing import Callable, Dict, List, TypeVar, cast

from .types import (
    Capability,
    CHKDirectoryRead,
    CHKDirectoryVerify,
    CHKRead,
    CHKVerify,
    DirectoryReadCapability,
    DirectoryWriteCapability,
    ImmutableDirectoryReadCapability,
    ImmutableReadCapability,
    LiteralDirectoryRead,
    LiteralRead,
    MDMFDirectoryRead,
    MDMFDirectoryVerify,
    MDMFDirectoryWrite,
    MDMFRead,
    MDMFVerify,
    MDMFWrite,
    ReadCapability,
    SSKDirectoryRead,
    SSKDirectoryVerify,
    SSKDirectoryWrite,
    SSKRead,
    SSKVerify,
    SSKWrite,
    WriteCapability,
)


class NotRecognized(ValueError):
    def __init__(self, prefix: List[str]) -> None:
        super().__init__(f"Unrecognized capability type {prefix}")


def _unb32str(s: str) -> bytes:
    """
    Base32-decode a text string into a byte string.
    """
    s = s.upper()

    # Add padding back, to make Python's base64 module happy:
    while (len(s) * 5) % 8 != 0:
        s += "="

    return _b32decode(s.encode("ascii"))


def _parse_chk_verify(pieces: List[str]) -> CHKVerify:
    verifykey = _unb32str(pieces[0])
    uri_extension_hash = _unb32str(pieces[1])
    needed = int(pieces[2])
    total = int(pieces[3])
    size = int(pieces[4])
    return CHKVerify(verifykey, uri_extension_hash, needed, total, size)


def _parse_chk_read(pieces: List[str]) -> CHKRead:
    readkey = _unb32str(pieces[0])
    uri_extension_hash = _unb32str(pieces[1])
    needed = int(pieces[2])
    total = int(pieces[3])
    size = int(pieces[4])
    return CHKRead.derive(readkey, uri_extension_hash, needed, total, size)


def _parse_dir2_chk_verify(pieces: List[str]) -> CHKDirectoryVerify:
    return CHKDirectoryVerify(_parse_chk_verify(pieces))


def _parse_dir2_chk_read(pieces: List[str]) -> CHKDirectoryRead:
    return CHKDirectoryRead(_parse_chk_read(pieces))


def _parse_literal(pieces: List[str]) -> LiteralRead:
    return LiteralRead(_unb32str(pieces[0]))


def _parse_dir2_literal_read(pieces: List[str]) -> LiteralDirectoryRead:
    return LiteralDirectoryRead(_parse_literal(pieces))


def _parse_ssk_verify(pieces: List[str]) -> SSKVerify:
    storage_index = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return SSKVerify(storage_index, fingerprint)


def _parse_ssk_read(pieces: List[str]) -> SSKRead:
    readkey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return SSKRead.derive(readkey, fingerprint)


def _parse_dir2_ssk_verify(pieces: List[str]) -> SSKDirectoryVerify:
    return SSKDirectoryVerify(_parse_ssk_verify(pieces))


def _parse_dir2_ssk_read(pieces: List[str]) -> SSKDirectoryRead:
    return SSKDirectoryRead(_parse_ssk_read(pieces))


def _parse_mdmf_verify(pieces: List[str]) -> MDMFVerify:
    storage_index = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return MDMFVerify(storage_index, fingerprint)


def _parse_mdmf_read(pieces: List[str]) -> MDMFRead:
    readkey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return MDMFRead.derive(readkey, fingerprint)


def _parse_dir2_mdmf_read(pieces: List[str]) -> MDMFDirectoryRead:
    return MDMFDirectoryRead(_parse_mdmf_read(pieces))


def _parse_dir2_mdmf_verify(pieces: List[str]) -> MDMFDirectoryVerify:
    return MDMFDirectoryVerify(_parse_mdmf_verify(pieces))


def _parse_ssk_write(pieces: List[str]) -> SSKWrite:
    writekey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return SSKWrite.derive(writekey, fingerprint)


def _parse_dir2_ssk_write(pieces: List[str]) -> SSKDirectoryWrite:
    return SSKDirectoryWrite(_parse_ssk_write(pieces))


def _parse_mdmf_write(pieces: List[str]) -> MDMFWrite:
    writekey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    return MDMFWrite.derive(writekey, fingerprint)


def _parse_dir2_mdmf_write(pieces: List[str]) -> MDMFDirectoryWrite:
    return MDMFDirectoryWrite(_parse_mdmf_write(pieces))


_parsers: Dict[str, Callable[[List[str]], Capability]] = {
    "LIT": _parse_literal,
    "CHK-Verifier": _parse_chk_verify,
    "CHK": _parse_chk_read,
    "SSK-Verifier": _parse_ssk_verify,
    "SSK-RO": _parse_ssk_read,
    "SSK": _parse_ssk_write,
    "MDMF-Verifier": _parse_mdmf_verify,
    "MDMF-RO": _parse_mdmf_read,
    "MDMF": _parse_mdmf_write,
    "DIR2-LIT": _parse_dir2_literal_read,
    "DIR2-CHK-Verifier": _parse_dir2_chk_verify,
    "DIR2-CHK": _parse_dir2_chk_read,
    "DIR2-Verifier": _parse_dir2_ssk_verify,
    "DIR2-RO": _parse_dir2_ssk_read,
    "DIR2": _parse_dir2_ssk_write,
    "DIR2-MDMF-Verifier": _parse_dir2_mdmf_verify,
    "DIR2-MDMF-RO": _parse_dir2_mdmf_read,
    "DIR2-MDMF": _parse_dir2_mdmf_write,
}

_A = TypeVar("_A")


def _uri_parser(s: str, parsers: Dict[str, Callable[[List[str]], _A]]) -> _A:
    pieces = s.split(":")
    if pieces[0] == "URI":
        try:
            parser = parsers[pieces[1]]
        except KeyError:
            raise NotRecognized(pieces[:2])
        else:
            return parser(pieces[2:])
    raise NotRecognized(pieces[:1])


def writeable_from_string(s: str) -> WriteCapability:
    return cast(
        WriteCapability,
        _uri_parser(
            s,
            {
                "SSK": _parse_ssk_write,
                "MDMF": _parse_mdmf_write,
                "DIR2": _parse_dir2_ssk_write,
                "DIR2-MDMF": _parse_dir2_mdmf_write,
            },
        ),
    )


def readable_from_string(s: str) -> ReadCapability:
    return cast(
        ReadCapability,
        _uri_parser(
            s,
            {
                "LIT": _parse_literal,
                "CHK": _parse_chk_read,
                "SSK-RO": _parse_ssk_read,
                "MDMF-RO": _parse_mdmf_write,
            },
        ),
    )


def immutable_readonly_from_string(s: str) -> ImmutableReadCapability:
    return cast(
        ImmutableReadCapability,
        _uri_parser(
            s,
            {
                "LIT": _parse_literal,
                "CHK": _parse_chk_read,
            },
        ),
    )


def immutable_directory_from_string(s: str) -> ImmutableDirectoryReadCapability:
    return cast(
        ImmutableDirectoryReadCapability,
        _uri_parser(
            s,
            {
                "DIR2-LIT": _parse_dir2_literal_read,
                "DIR2-CHK": _parse_dir2_chk_read,
            },
        ),
    )


def readonly_directory_from_string(s: str) -> DirectoryReadCapability:
    """
    Parse a capability string into a read capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is not
        read-only, is not for a mutable, or is not for a directory.
    """
    return cast(
        DirectoryReadCapability,
        _uri_parser(
            s,
            {
                "DIR2-RO": _parse_dir2_ssk_read,
                "DIR2-MDMF-RO": _parse_dir2_mdmf_read,
            },
        ),
    )


def writeable_directory_from_string(s: str) -> DirectoryWriteCapability:
    """
    Parse a capability string into a write capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is writeable
        or is not for a directory.
    """
    return cast(
        DirectoryWriteCapability,
        _uri_parser(
            s,
            {
                "DIR2": _parse_dir2_ssk_write,
                "DIR2-MDMF": _parse_dir2_mdmf_write,
            },
        ),
    )


def capability_from_string(s: str) -> Capability:
    pieces = s.split(":")
    if pieces[0] == "URI":
        parser = _parsers[pieces[1]]
        return parser(pieces[2:])

    raise NotRecognized(pieces[:1])
