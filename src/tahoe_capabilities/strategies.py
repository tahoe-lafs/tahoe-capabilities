from hypothesis.strategies import builds, binary, lists, integers
from hypothesis.strategies import SearchStrategy

from . import CHKRead, CHKDirectoryRead, SSKWrite, SSKDirectoryWrite

def encoding_parameters() -> SearchStrategy[tuple[int, int, int]]:
    """
    Build three-tuples of integers that can be used as needed, happy, total
    encoding/share placement parameters for a Tahoe-LAFS client node.

    :return: (n, h, k) such that 1 <= n <= h <= k <= 255
    """

    def order(xs):
        xs.sort()
        return (xs[0], xs[1], xs[2])

    return lists(
        integers(min_value=1, max_value=255),
        min_size=3,
        max_size=3,
    ).map(order)


def chk_objects() -> SearchStrategy[CHKRead]:
    return builds(
        lambda key, uri_extension_hash, encoding: CHKRead(key, uri_extension_hash, *encoding),
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
        encoding_parameters(),
    )

def chk_directories() -> SearchStrategy[CHKDirectoryRead]:
    return chk_objects().map(CHKDirectoryRead)

def ssk_objects() -> SearchStrategy[SSKWrite]:
    return builds(
        SSKWrite,
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
    )

def ssk_directories() -> SearchStrategy[SSKDirectoryWrite]:
    return ssk_objects().map(SSKDirectoryWrite)
