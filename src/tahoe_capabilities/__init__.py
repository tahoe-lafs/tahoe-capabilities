from base64 import b32encode as _b32encode, b32decode as _b32decode
from hashlib import sha256
from attrs import frozen, field
from typing import Union, Dict, Callable, List, Type, TypeVar
from .hashutil import ssk_readkey_hash as _ssk_readkey_hash, ssk_storage_index_hash as _ssk_storage_index_hash
from typing import Tuple

class NotWriteable(ValueError):
    def __init__(self) -> None:
        super().__init__("Capability is not writeable")

class NotDirectory(ValueError):
    def __init__(self) -> None:
        super().__init__("Capability is not a directory")

class NotReadOnly(ValueError):
    def __init__(self) -> None:
        super().__init__("Capability is not read-only")

class NotImmutable(ValueError):
    def __init__(self) -> None:
        super().__init__("Capability is not immutable")

class NotRecognized(ValueError):
    def __init__(self, cap: object) -> None:
        super().__init__(f"Capability of unrecognized type {type(cap)}")

def _b32str(b: bytes) -> str:
    """
    Base32-encode a byte string to a text string.
    """
    return _b32encode(b).decode("ascii").rstrip("=").lower()

def _unb32str(s: str) -> bytes:
    """
    Base32-decode a text string into a byte string.
    """
    s = s.upper()

    # Add padding back, to make Python's base64 module happy:
    while (len(s) * 5) % 8 != 0:
        s += "="

    return _b32decode(s.encode("ascii"))

def _scrub(b: bytes) -> str:
    """
    Compute a short cryptographic digest using the base32 alphabet.  The
    digest is not very collision resistant due to its short length.
    """
    return _b32str(sha256(b).digest()[:6])

@frozen
class Unknown:
    data: bytes
    prefix: str
    suffix: Tuple[str, ...] = ()

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.data,)

@frozen
class LiteralRead:
    data: bytes
    prefix: str = "LIT"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.data,)

@frozen
class LiteralDirectoryRead:
    cap_object: LiteralRead
    prefix: str = "DIR2-LIT"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

@frozen
class CHKVerify:
    storage_index: bytes
    uri_extension_hash: bytes
    needed: int
    total: int
    size: int
    prefix: str = "CHK-Verifier"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.storage_index, self.uri_extension_hash)

    @property
    def suffix(self) -> Tuple[str, ...]:
        return (str(self.needed), str(self.total), str(self.size))

@frozen
class CHKRead:
    readkey: bytes = field(repr=False)
    verifier: CHKVerify
    prefix: str = "CHK"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.readkey, self.verifier.uri_extension_hash)

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.verifier.suffix

@frozen
class CHKDirectoryVerify:
    cap_object: CHKVerify
    prefix: str = "DIR2-CHK-Verifier"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class CHKDirectoryRead:
    cap_object: CHKRead
    prefix: str = "DIR2-CHK"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class SSKVerify:
    storage_index: bytes
    fingerprint: bytes
    prefix: str = "SSK-Verifier"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.storage_index, self.fingerprint)

@frozen
class SSKRead:
    readkey: bytes = field(repr=False)
    verifier: SSKVerify
    prefix: str = "SSK-RO"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.readkey, self.verifier.fingerprint)

@frozen
class SSKWrite:
    writekey: bytes = field(repr=False)
    reader: SSKRead
    prefix: str = "SSK"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.writekey, self.reader.verifier.fingerprint)

@frozen
class SSKDirectoryVerify:
    cap_object: SSKVerify
    prefix: str = "DIR2-Verifier"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class SSKDirectoryRead:
    cap_object: SSKRead
    prefix: str = "DIR2-RO"

    @property
    def verifier(self) -> SSKDirectoryVerify:
        return SSKDirectoryVerify(self.cap_object.verifier)

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class SSKDirectoryWrite:
    cap_object: SSKWrite
    prefix: str = "DIR2"

    @property
    def reader(self) -> SSKDirectoryRead:
        return SSKDirectoryRead(self.cap_object.reader)

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class MDMFVerify:
    storage_index: bytes
    fingerprint: bytes
    prefix: str = "MDMF-Verifier"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.storage_index, self.fingerprint)

@frozen
class MDMFRead:
    readkey: bytes = field(repr=False)
    verifier: MDMFVerify
    prefix: str = "MDMF-RO"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.readkey, self.verifier.fingerprint)

@frozen
class MDMFWrite:
    writekey: bytes = field(repr=False)
    reader: MDMFRead
    prefix: str = "MDMF"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.writekey, self.reader.verifier.fingerprint)

@frozen
class MDMFDirectoryVerify:
    cap_object: MDMFVerify
    prefix: str = "DIR2-MDMF-Verifier"

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class MDMFDirectoryRead:
    cap_object: MDMFRead
    prefix: str = "DIR2-MDMF-RO"

    @property
    def verifier(self) -> MDMFDirectoryVerify:
        return MDMFDirectoryVerify(self.cap_object.verifier)

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

@frozen
class MDMFDirectoryWrite:
    cap_object: MDMFWrite
    prefix: str = "DIR2-MDMF"

    @property
    def reader(self) -> MDMFDirectoryRead:
        return MDMFDirectoryRead(self.cap_object.reader)

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return self.cap_object.secrets

    @property
    def suffix(self) -> Tuple[str, ...]:
        return self.cap_object.suffix

VerifyCapability = Union[
    CHKVerify,
    SSKVerify,
    MDMFVerify,
    CHKDirectoryVerify,
    SSKDirectoryVerify,
    MDMFDirectoryVerify,
]

ReadCapability = Union[
    LiteralRead,
    CHKRead,
    SSKRead,
    MDMFRead,
    LiteralDirectoryRead,
    CHKDirectoryRead,
    SSKDirectoryRead,
    MDMFDirectoryRead,
]

WriteCapability = Union[
    SSKWrite,
    MDMFWrite,
    SSKDirectoryWrite,
    MDMFDirectoryWrite,
]

DirectoryVerifyCapability = Union[
    CHKDirectoryVerify,
    SSKDirectoryVerify,
    MDMFDirectoryVerify,
]

DirectoryReadCapability = Union[
    LiteralDirectoryRead,
    CHKDirectoryRead,
    SSKDirectoryRead,
    MDMFDirectoryRead,
]

DirectoryWriteCapability = Union[
    SSKDirectoryWrite,
    MDMFDirectoryWrite,
]

DirectoryCapability = Union[
    DirectoryVerifyCapability,
    DirectoryReadCapability,
    DirectoryWriteCapability,
]

ImmutableVerifyCapability = Union[
    CHKVerify,
    CHKDirectoryVerify,
]

ImmutableReadCapability = Union[
    LiteralRead,
    CHKRead,
]

ImmutableDirectoryReadCapability = Union[
    LiteralDirectoryRead,
    CHKDirectoryRead,
]

ImmutableCapability = Union[
    ImmutableVerifyCapability,
    ImmutableReadCapability,
    ImmutableDirectoryReadCapability,
]

MutableCapability = Union[
    SSKWrite,
    SSKRead,
    SSKVerify,
    MDMFWrite,
    MDMFRead,
    MDMFVerify,
    SSKDirectoryWrite,
    SSKDirectoryRead,
    SSKDirectoryVerify,
    MDMFDirectoryWrite,
    MDMFDirectoryRead,
    MDMFDirectoryVerify,
]

Capability = Union[
    ImmutableCapability,
    MutableCapability,
    Unknown,
]

def _parse_chk_read(pieces: List[str]) -> CHKRead:
    readkey = _unb32str(pieces[0])
    uri_extension_hash = _unb32str(pieces[1])
    needed = int(pieces[2])
    total = int(pieces[3])
    size = int(pieces[4])
    return CHKRead(
        readkey,
        CHKVerify(
            _ssk_storage_index_hash(readkey),
            uri_extension_hash,
            needed,
            total,
            size,
        ),
    )

def _parse_chk_verify(pieces: List[str]) -> CHKVerify:
    verifykey = _unb32str(pieces[0])
    uri_extension_hash = _unb32str(pieces[1])
    needed = int(pieces[2])
    total = int(pieces[3])
    size = int(pieces[4])
    return CHKVerify(verifykey, uri_extension_hash, needed, total, size)

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
    storage_index = _ssk_storage_index_hash(readkey)
    return SSKRead(readkey, SSKVerify(storage_index, fingerprint))

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
    storage_index = _ssk_storage_index_hash(readkey)
    return MDMFRead(readkey, MDMFVerify(storage_index, fingerprint))

def _parse_dir2_mdmf_read(pieces: List[str]) -> MDMFDirectoryRead:
    return MDMFDirectoryRead(_parse_mdmf_read(pieces))

def _parse_dir2_mdmf_verify(pieces: List[str]) -> MDMFDirectoryVerify:
    return MDMFDirectoryVerify(_parse_mdmf_verify(pieces))

def writeable_from_string(s: str) -> WriteCapability:
    return _uri_parser(s, {
        "SSK": _parse_ssk_write,
        "MDMF": _parse_mdmf_write,
        "DIR2": _parse_dir2_ssk_write,
        "DIR2-MDMF": _parse_dir2_mdmf_write,
    })

def _parse_ssk_write(pieces: List[str]) -> SSKWrite:
    writekey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    readkey = _ssk_readkey_hash(writekey)
    storage_index = _ssk_storage_index_hash(readkey)
    return SSKWrite(writekey, SSKRead(readkey, SSKVerify(storage_index, fingerprint)))

def _parse_dir2_ssk_write(pieces: List[str]) -> SSKDirectoryWrite:
    return SSKDirectoryWrite(_parse_ssk_write(pieces))

def _parse_mdmf_write(pieces: List[str]) -> MDMFWrite:
    writekey = _unb32str(pieces[0])
    fingerprint = _unb32str(pieces[1])
    readkey = _ssk_readkey_hash(writekey)
    storage_index = _ssk_storage_index_hash(readkey)
    return MDMFWrite(writekey, MDMFRead(readkey, MDMFVerify(storage_index, fingerprint)))

def _parse_dir2_mdmf_write(pieces: List[str]) -> MDMFDirectoryWrite:
    return MDMFDirectoryWrite(_parse_mdmf_write(pieces))

def immutable_directory_from_string(s: str) -> ImmutableDirectoryReadCapability:
    return _uri_parser(s, {
        "DIR2-LIT": _parse_dir2_literal_read,
        "DIR2-CHK": _parse_dir2_chk_read,
    })

def readonly_directory_from_string(s: str) -> DirectoryReadCapability:
    """
    Parse a capability string into a read capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is not
        read-only, is not for a mutable, or is not for a directory.
    """
    return _uri_parser(s, {
        "DIR2-RO": _parse_dir2_ssk_read,
        "DIR2-MDMF-RO": _parse_dir2_mdmf_read,
    })

def writeable_directory_from_string(s: str) -> DirectoryWriteCapability:
    """
    Parse a capability string into a write capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is writeable
        or is not for a directory.
    """
    return _uri_parser(s, {
        "DIR2": _parse_dir2_ssk_write,
        "DIR2-MDMF": _parse_dir2_mdmf_write,
    })

def scrubbed_string(cap: Capability) -> str:
    scrubbed = _scrub(b"".join(cap.secrets))
    suffix = ":".join(map(str, cap.suffix))
    if suffix:
        suffix = ":" + suffix
    return f"S:URI:{cap.prefix}:{scrubbed}{suffix}"

def danger_real_capability_string(cap: Capability) -> str:
    secrets: str = ":".join(map(_b32str, cap.secrets))
    suffix: str = ":".join(map(str, cap.suffix))
    if suffix:
        suffix = ":" + suffix
    return f"URI:{cap.prefix}:{secrets}{suffix}"

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

    "DIR2-CHK": _parse_dir2_chk_read,

    "DIR2-Verifier": _parse_dir2_ssk_verify,
    "DIR2-RO": _parse_dir2_ssk_read,
    "DIR2": _parse_dir2_ssk_write,

    "DIR2-MDMF-Verifier": _parse_dir2_mdmf_verify,
    "DIR2-MDMF-RO": _parse_dir2_mdmf_read,
    "DIR2-MDMF": _parse_dir2_mdmf_write,
}

def capability_from_string(s: str) -> Capability:
    pieces = s.split(":")
    if pieces[0] == "URI":
        parser = _parsers[pieces[1]]
        return parser(pieces[2:])

    _, prefix, data = s.split(":", 2)
    return Unknown(data.encode("ascii"), prefix)

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
