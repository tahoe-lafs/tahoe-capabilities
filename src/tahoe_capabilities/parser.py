
from __future__ import annotations

__all__ = [
    "capability_from_string",
    "ParseError",
]

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


def _b32string(alphabet: str, exact_bits: Optional[int] = None) -> Parser[list[str]]:
    """
    Parse a base32-encoded string.

    :param alphabet: The alphabet to use.  Must be 32 characters long.

    :exact_bits: See ``b32string``.

    :return: A parser that consumes and returns the matched base32 characters
        (still encoded).
    """
    assert len(alphabet) == 32

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


def b32string(exact_bits: Optional[int] = None) -> Parser[bytes]:
    """
    Parse a base32-encoded string.

    :param alphabet: The alphabet to use.  Must be 32 characters long.

    :param exact_bits: If ``None`` parse a string of any length.  Otherwise,
        parse a base32 string that represents an encoded string of exactly
        this many bits.

    :return: A parser that consumes and results in the decoded string.
    """
    # RFC3548 standard used by Gnutella, Content-Addressable Web, THEX, Bitzi,
    # Web-Calculus...
    rfc3548_alphabet = "abcdefghijklmnopqrstuvwxyz234567"

    return _b32string(rfc3548_alphabet, exact_bits).parsecmap(
        lambda xs: _unb32str("".join(xs))
    )


def _trailing_b32chars(alphabet: str, bits: int) -> str:
    """
    Find the part of the base32 alphabet that is required and allowed to
    express the given number of bits of encoded data.

    This is used to match the end of a base32 string where the length of the
    encoded data is not a multiple of 5 bits (the base32 word size).
    """
    stem = alphabet[:: 1 << bits]
    if bits == 0:
        return stem
    return stem + _trailing_b32chars(alphabet, bits - 1)


# Match the common separator between components of capability strings.
_sep = string(":")

# Match a natural number
_natural = many1(digit()).parsecmap("".join).parsecmap(int)

# Match a base32-encoded binary string with the length of a key.
_key = b32string(128)

# Match a base32-encoded binary string with the length of a fingerprint or UEB hash.
_uri_extension_hash = b32string(256)

# Match the base32-encoded data portion of a literal capability.  This is not
# length limited though in practice literals are only used for data of 55
# bytes or less.
_lit = b32string()

# Match the needed shares, total shares, and data size numbers in a CHK
# capability string.
_chk_params = times(_sep >> _natural, 3, 3)

# Match all of the data components (but not the type prefix) of a CHK
# capability string.
_chk = _key + (_sep >> _uri_extension_hash) + _chk_params

# Match all of the data components (but not the type prefix) of an SSK (SDMF
# or MDMF) capability string.
#
# Tahoe-LAFS calls the components of SSK "storage_index" and "fingerprint" but
# they are syntactically the same as "key" and "uri_extension_hash" from CHK.
_ssk = _key + (_sep >> _uri_extension_hash)


def _capability_parser() -> Parser[Capability]:
    """
    Parse any kind of capability string.
    """
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

    mdmf_verify = string("MDMF-Verifier:") >> _ssk.parsecmap(lambda p: MDMFVerify(*p))
    mdmf_read = string("MDMF-RO:") >> _ssk.parsecmap(lambda p: MDMFRead.derive(*p))
    mdmf = string("MDMF:") >> _ssk.parsecmap(lambda p: MDMFWrite.derive(*p))

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
    """
    Parse any known capability string.
    """
    return _capability.parse(s)
