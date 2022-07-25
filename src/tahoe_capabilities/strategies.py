from typing import Tuple, List, TypeVar
from hypothesis.strategies import builds, binary, lists, integers, one_of
from hypothesis.strategies import SearchStrategy

from .hashutil import ssk_storage_index_hash as _ssk_storage_index_hash
from . import CHKRead, CHKDirectoryRead, SSKWrite, SSKDirectoryWrite, MDMFWrite, WriteCapability, ReadCapability, LiteralRead, VerifyCapability, Capability, CHKVerify

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
                _ssk_storage_index_hash(o.readkey),
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
        SSKWrite,
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
    )

def mdmf_writes() -> SearchStrategy[MDMFWrite]:
    return builds(
        MDMFWrite,
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
    )

def verify_capabilites() -> SearchStrategy[VerifyCapability]:
    return one_of([
        chk_reads(),
        write_capabilities().map(lambda rw: rw.reader),
    ]).map(lambda ro: ro.verifier)

def read_capabilities() -> SearchStrategy[ReadCapability]:
    return one_of([
        literal_reads(),
        chk_reads(),
        write_capabilities().map(lambda rw: rw.reader),
    ])

def write_capabilities() -> SearchStrategy[WriteCapability]:
    return one_of([
        ssk_writes(),
        mdmf_writes(),
    ])

def capabilities() -> SearchStrategy[Capability]:
    return one_of([
        verify_capabilites(),
        read_capabilities(),
        write_capabilities(),
    ])
