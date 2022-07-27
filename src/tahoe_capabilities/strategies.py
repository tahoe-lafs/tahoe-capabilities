from typing import List, Tuple, TypeVar, Union

from hypothesis.strategies import (
    SearchStrategy,
    binary,
    builds,
    integers,
    lists,
    one_of,
)

from . import (
    Capability,
    CHKDirectoryRead,
    CHKRead,
    CHKVerify,
    LiteralDirectoryRead,
    LiteralRead,
    MDMFDirectoryWrite,
    MDMFRead,
    MDMFVerify,
    MDMFWrite,
    ReadCapability,
    SSKDirectoryWrite,
    SSKRead,
    SSKVerify,
    SSKWrite,
    VerifyCapability,
    WriteCapability,
)
from .hashutil import ssk_readkey_hash as _ssk_readkey_hash
from .hashutil import ssk_storage_index_hash as _ssk_storage_index_hash
from .hashutil import storage_index_hash as _storage_index_hash

_A = TypeVar("_A")


def encoding_parameters() -> SearchStrategy[Tuple[int, int, int]]:
    """
    Build three-tuples of integers that can be used as needed, happy, total
    encoding/share placement parameters for a Tahoe-LAFS client node.

    :return: (n, h, k) such that 1 <= n <= h <= k <= 255
    """

    def order(xs: List[_A]) -> Tuple[_A, _A, _A]:
        xs.sort()
        return (xs[0], xs[1], xs[2])

    return lists(
        integers(min_value=1, max_value=255),
        min_size=3,
        max_size=3,
    ).map(order)


def literal_reads() -> SearchStrategy[LiteralRead]:
    return builds(
        LiteralRead,
        binary(min_size=0, max_size=55),
    )


def chk_reads() -> SearchStrategy[CHKRead]:
    return builds(
        lambda key, uri_extension_hash, encoding: CHKRead(
            key,
            CHKVerify(
                _storage_index_hash(key),
                uri_extension_hash,
                *encoding,
            ),
        ),
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
        encoding_parameters(),
    )


def ssk_writes() -> SearchStrategy[SSKWrite]:
    return builds(
        lambda writekey, fingerprint: SSKWrite(
            writekey,
            SSKRead(
                _ssk_readkey_hash(writekey),
                SSKVerify(
                    _ssk_storage_index_hash(_ssk_readkey_hash(writekey)),
                    fingerprint,
                ),
            ),
        ),
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
    )


def mdmf_writes() -> SearchStrategy[MDMFWrite]:
    return builds(
        lambda writekey, fingerprint: MDMFWrite(
            writekey,
            MDMFRead(
                _ssk_readkey_hash(writekey),
                MDMFVerify(
                    _ssk_storage_index_hash(_ssk_readkey_hash(writekey)),
                    fingerprint,
                ),
            ),
        ),
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
    )


def verify_capabilites() -> SearchStrategy[VerifyCapability]:
    ro = one_of(
        [
            chk_reads(),
            chk_reads().map(CHKDirectoryRead),
            write_capabilities().map(lambda rw: rw.reader),
        ]
    )

    def verifier(ro: Union[CHKRead, SSKRead, MDMFRead]) -> VerifyCapability:
        return ro.verifier

    verify = ro.map(verifier)
    return verify


def read_capabilities() -> SearchStrategy[ReadCapability]:
    return one_of(
        [
            literal_reads(),
            literal_reads().map(LiteralDirectoryRead),
            chk_reads(),
            chk_reads().map(CHKDirectoryRead),
            write_capabilities().map(lambda rw: rw.reader),
        ]
    )


def write_capabilities() -> SearchStrategy[WriteCapability]:
    return one_of(
        [
            ssk_writes(),
            ssk_writes().map(SSKDirectoryWrite),
            mdmf_writes(),
            mdmf_writes().map(MDMFDirectoryWrite),
        ]
    )


def capabilities() -> SearchStrategy[Capability]:
    return one_of(
        [
            verify_capabilites(),
            read_capabilities(),
            write_capabilities(),
        ]
    )
