from base64 import b32decode as _b32decode
from typing import Callable, Dict, List, TypeVar, cast, Optional

from parsec import Parser, string, many1, many, digit, times, one_of, ParseError

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


def writeable_from_string(s: str) -> WriteCapability:
    cap = capability_from_string(s)
    assert isinstance(
        cap,
        (SSKWrite, MDMFWrite, SSKDirectoryWrite, MDMFDirectoryWrite),
    )
    return cap


def readable_from_string(s: str) -> ReadCapability:
    cap = capability_from_string(s)
    assert isinstance(
        cap,
        (SSKRead, MDMFRead, SSKDirectoryRead, MDMFDirectoryRead),
    )
    return cap


def immutable_readonly_from_string(s: str) -> ImmutableReadCapability:
    cap = capability_from_string(s)
    assert isinstance(cap, (LiteralRead, CHKRead))
    return cap


def immutable_directory_from_string(s: str) -> ImmutableDirectoryReadCapability:
    cap = capability_from_string(s)
    assert isinstance(cap, (LiteralDirectoryRead, CHKDirectoryRead))
    return cap


def readonly_directory_from_string(s: str) -> DirectoryReadCapability:
    """
    Parse a capability string into a read capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is not
        read-only, is not for a mutable, or is not for a directory.
    """
    cap = capability_from_string(s)
    assert isinstance(cap, (SSKDirectoryRead, MDMFDirectoryRead))
    return cap


def writeable_directory_from_string(s: str) -> DirectoryWriteCapability:
    """
    Parse a capability string into a write capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is writeable
        or is not for a directory.
    """
    cap = capability_from_string(s)
    assert isinstance(cap, (SSKDirectoryWrite, MDMFDirectoryWrite))
    return cap


def _b32string(alphabet: str, exact_bits: Optional[int] = None) -> Parser:
    if exact_bits is None:
        return many(one_of(alphabet))

    full, extra = divmod(exact_bits, 5)
    stem = times(
        one_of(alphabet),
        full,
        full,
    )
    if extra == 0:
        return stem
    return (stem + one_of("".join(set(_trailing_b32chars(alphabet, extra))))).parsecmap(
        lambda xs_x: xs_x[0] + [xs_x[1]]
    )


def b32string(exact_bits: Optional[int] = None) -> Parser:
    # RFC3548 standard used by Gnutella, Content-Addressable Web, THEX, Bitzi,
    # Web-Calculus...
    rfc3548_alphabet = "abcdefghijklmnopqrstuvwxyz234567"

    return _b32string(rfc3548_alphabet, exact_bits).parsecmap(
        lambda xs: _unb32str("".join(xs))
    )


def _trailing_b32chars(alphabet: str, bits: int) -> str:
    stem = alphabet[:: 1 << bits]
    if bits == 0:
        return stem
    return stem + _trailing_b32chars(alphabet, bits - 1)


_sep = string(":")
_natural = many1(digit()).parsecmap("".join).parsecmap(int)
_key = b32string(128)
_uri_extension_hash = b32string(256)

_lit = b32string()

_chk_params = times(_sep >> _natural, 3, 3)
_chk = _key + (_sep >> _uri_extension_hash) + _chk_params

# Tahoe-LAFS calls the components of SSK "storage_index" and "fingerprint" but
# they are syntactically the same as "key" and "uri_extension_hash" from CHK.
_ssk = _key + (_sep >> _uri_extension_hash)

# And MDMF is syntactically compatible with SSK
_mdmf = _ssk


def _capability_parser() -> Parser:
    lit_read = string("LIT:") >> _lit.parsecmap(LiteralRead)

    def chk_glue(f):
        def g(values):
            ((key, uri_extension_hash), [a, b, c]) = values
            return f(key, uri_extension_hash, a, b, c)

        return g

    chk_verify = string("CHK-Verifier:") >> _chk.parsecmap(chk_glue(CHKVerify))
    chk = string("CHK:") >> _chk.parsecmap(chk_glue(CHKRead.derive))

    ssk_verify = string("SSK-Verifier:") >> _ssk.parsecmap(lambda p: SSKVerify(*p))
    ssk_read = string("SSK-RO:") >> _ssk.parsecmap(lambda p: SSKRead.derive(*p))
    ssk = string("SSK:") >> _ssk.parsecmap(lambda p: SSKWrite.derive(*p))

    mdmf_verify = string("MDMF-Verifier:") >> _mdmf.parsecmap(lambda p: MDMFVerify(*p))
    mdmf_read = string("MDMF-RO:") >> _mdmf.parsecmap(lambda p: MDMFRead.derive(*p))
    mdmf = string("MDMF:") >> _mdmf.parsecmap(lambda p: MDMFWrite.derive(*p))

    def dir2(file_parser: Parser, dir_type: type) -> Parser:
        return string("DIR2-") >> file_parser.parsecmap(dir_type)

    return string("URI:") >> (
        lit_read
        ^ chk_verify
        ^ chk
        ^ ssk_verify
        ^ ssk_read
        ^ ssk
        ^ mdmf_verify
        ^ mdmf_read
        ^ mdmf
        # Directory variations, starting with ssk which breaks the pattern by
        # leaving "SSK-" out.
        ^ (
            string("DIR2-Verifier:")
            >> _ssk.parsecmap(lambda p: SSKDirectoryVerify(SSKVerify(*p)))
        )
        ^ (
            string("DIR2-RO:")
            >> _ssk.parsecmap(lambda p: SSKDirectoryRead(SSKRead.derive(*p)))
        )
        ^ (
            string("DIR2:")
            >> _ssk.parsecmap(lambda p: SSKDirectoryWrite(SSKWrite.derive(*p)))
        )
        # # And then the rest
        ^ dir2(lit_read, LiteralDirectoryRead)
        ^ dir2(chk_verify, CHKDirectoryVerify)
        ^ dir2(chk, CHKDirectoryRead)
        ^ dir2(mdmf_verify, MDMFDirectoryVerify)
        ^ dir2(mdmf_read, MDMFDirectoryRead)
        ^ dir2(mdmf, MDMFDirectoryWrite)
    )


_capability = _capability_parser()


def capability_from_string(s: str) -> Capability:
    return _capability.parse(s)
