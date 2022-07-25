from base64 import b32encode as _b32encode
from hashlib import sha256
from attrs import frozen, field
from typing import Union
from .hashutil import ssk_readkey_hash as _ssk_readkey_hash, ssk_storage_index_hash as _ssk_storage_index_hash
from allmydata import uri as _uri
from typing import Tuple

def _b32str(b: bytes) -> str:
    """
    Base32-encode a byte string to a text string.
    """
    return _b32encode(b).decode("ascii").rstrip("=").lower()

def _scrub(b: bytes) -> str:
    """
    Compute a short cryptographic digest using the base32 alphabet.  The
    digest is not very collision resistant due to its short length.
    """
    return _b32str(sha256(b).digest()[:6])

def scrubbed_string(cap: Capability) -> str:
    scrubbed = _scrub(b"".join(cap.secrets))
    suffix = ":".join(map(str, cap.suffix))
    return f"S:URI:{cap.prefix}:{scrubbed}{suffix}"

def danger_real_capability_string(cap: Capability) -> str:
    secrets: str = ":".join(map(_b32str, cap.secrets))
    suffix: str = ":".join(map(str, cap.suffix))
    return f"URI:{cap.prefix}:{cap.secrets}{suffix}"

@frozen
class Unknown:
    prefix: str
    data: bytes
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
    prefix: str = "CHK"

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

DirectoryCapability = Union[
    LiteralDirectoryRead,
    CHKDirectoryRead,
    CHKDirectoryVerify,
    SSKDirectoryWrite,
    SSKDirectoryRead,
    SSKDirectoryVerify,
    MDMFDirectoryWrite,
    MDMFDirectoryRead,
    MDMFDirectoryVerify,
]

ImmutableDirectoryReadCapability = Union[
    LiteralDirectoryRead,
    CHKDirectoryRead,
    CHKDirectoryVerify,
]

ImmutableCapability = Union[
    LiteralRead,
    CHKRead,
    CHKVerify,
    LiteralDirectoryRead,
    CHKDirectoryRead,
    CHKDirectoryVerify,
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

Capability = Union[
    ImmutableCapability,
    MutableCapability,
    Unknown,
]

def immutable_directory_from_string(s: str) -> ImmutableDirectoryReadCapability:
    cap = _uri.from_string(s)

    if isinstance(cap, _uri.LiteralDirectoryURI):
        return LiteralDirectoryRead(LiteralRead(cap.data))
    elif isinstance(cap, _uri.ImmutableDirectoryURI):
        o = cap._filenode_uri
        return CHKDirectoryRead(
            CHKRead(
                o.key,
                CHKVerify(
                    _ssk_storage_index_hash(o.readkey),
                    o.uri_extension_hash,
                    o.needed_shares,
                    o.total_shares,
                    o.size,
                ),
            ),
        )

    if cap.is_mutable():
        raise NotImmutable()
    if not _uri.IDirnodeURI.providedBy(cap):
        raise NotDirectory()

    raise NotRecognized(cap)

def readonly_directory_from_string(s: str) -> DirectoryReadCapability:
    """
    Parse a capability string into a read capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is not
        read-only, is not for a mutable, or is not for a directory.
    """
    cap = _uri.from_string(s)

    if isinstance(cap, _uri.ReadonlyDirectoryURI):
        o = cap._filenode_uri
        reader = SSKRead(
            o.readkey,
            SSKVerify(
                _ssk_storage_index_hash(o.readkey),
                o.fingerprint,
            ),
        )
        return SSKDirectoryRead(reader)
    elif isinstance(cap, _uri.ReadonlyMDMFDirectoryURI):
        o = cap._filenode_uri
        return MDMFDirectoryRead(MDMFRead(o.readkey, o.fingerprint))

    if not cap.is_readonly():
        raise NotReadOnly()
    if not _uri.IDirnodeURI.providedBy(cap):
        raise NotDirectory()

    raise NotRecognized(cap)

def writeable_from_string(s: str) -> WriteCapability:
    cap = _uri.from_string(s)

    if isinstance(cap, _uri.WriteableSSKFileURI):
        return SSKWrite(cap.writekey, cap.fingerprint)
    if isinstance(cap, _uri.WriteableMDMFFileURI):
        return MDMFWrite(cap.writekey, cap.fingerprint)
    if isinstance(cap, _uri.DirectoryURI):
        o = cap._filenode_uri
        return SSKDirectoryWrite(SSKWrite(o.writekey, o.fingerprint))
    if isinstance(cap, _uri.MDMFDirectoryURI):
        o = cap._filenode_uri
        return MDMFDirectoryWrite(MDMFWrite(o.writekey, o.fingerprint))

    if cap.is_readonly():
        raise NotWriteable()

    raise NotRecognized(cap)

def writeable_directory_from_string(s: str) -> DirectoryWriteCapability:
    """
    Parse a capability string into a write capability for a mutable
    directory.

    :raise ValueError: If the string represents a capability that is writeable
        or is not for a directory.
    """
    cap = _uri.from_string(s)

    if isinstance(cap, _uri.DirectoryURI):
        o = cap._filenode_uri
        return SSKDirectoryWrite(SSKWrite(o.writekey, o.fingerprint))
    elif isinstance(cap, _uri.MDMFDirectoryURI):
        o = cap._filenode_uri
        return MDMFDirectoryWrite(MDMFWrite(o.writekey, o.fingerprint))

    if cap.is_readonly():
        raise NotWriteable()
    if not _uri.IDirnodeURI.providedBy(cap):
        raise NotDirectory()

    raise NotRecognized(cap)


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
