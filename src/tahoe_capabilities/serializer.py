from base64 import b32encode as _b32encode
from hashlib import shake_128

from .types import Capability


def _b32str(b: bytes) -> str:
    """
    Base32-encode a byte string to a text string.
    """
    return _b32encode(b).decode("ascii").rstrip("=").lower()


def _scrub(b: bytes) -> str:
    """
    Compute a short cryptographic digest using the base32 alphabet.  The
    digest is not particularly collision resistant due to its short length.
    """
    return _b32str(shake_128(b).digest(8))


def digested_capability_string(cap: Capability) -> str:
    """
    Return a string representation of the given capability where all of the
    secrets have been passed through a one-way hash function such that the
    string cannot be used to recover the capability.

    Most pairs of capability inputs will still result in different string
    outputs but due to the use of a hash function this is not guaranteed for
    every pair of inputs.
    """
    scrubbed = _scrub(b"".join(cap.secrets))
    suffix = ":".join(map(str, cap.suffix))
    if suffix:
        suffix = ":" + suffix
    return f"D:URI:{cap.prefix}:{scrubbed}{suffix}"


def danger_real_capability_string(cap: Capability) -> str:
    """
    Return a string representation of the given capability including all
    of its secrets.  This string is *equivalent to the capability object*.
    Anyone who has the string has the capability.
    """
    secrets: str = ":".join(map(_b32str, cap.secrets))
    suffix: str = ":".join(map(str, cap.suffix))
    if suffix:
        suffix = ":" + suffix
    return f"URI:{cap.prefix}:{secrets}{suffix}"
