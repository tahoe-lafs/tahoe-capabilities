from hashlib import sha256
from attrs import frozen, field
from typing import Union
from allmydata.util.base32 import b2a as _b2a
from allmydata.util.hashutil import ssk_readkey_hash as _ssk_readkey_hash, ssk_storage_index_hash as _ssk_storage_index_hash
from allmydata import uri as _uri

def _b32str(b: bytes) -> str:
    return _b2a(b).decode("ascii")

def _scrub(b: bytes) -> str:
    return _b32str(sha256(b).digest()[:6])

class LiteralRead:
    pass

@frozen
class CHKRead:
    key: bytes = field(repr=False)
    uri_extension_hash: bytes
    needed: int
    total: int
    size: int

    def scrubbed_string(self) -> str:
        return f"S:URI:CHK:{_scrub(self.key + self.uri_extension_hash)}"

    def danger_real_capability_string(self) -> str:
        return f"URI:CHK:{_b32str(self.key)}:{_b32str(self.uri_extension_hash)}:{self.needed}:{self.total}:{self.size}"


class CHKVerify:
    pass

class SSKVerify:
    pass

@frozen
class SSKRead:
    readkey: bytes = field(repr=False)
    fingerprint: bytes
    storage_index: bytes = field(init=False)

    @storage_index.default
    def _storage_index_default(self) -> bytes:
        return _ssk_storage_index_hash(self.readkey)

    def scrubbed_string(self) -> str:
        return f"S:URI:SSK-RO:{_scrub(self.readkey + self.fingerprint)}"

    def danger_real_capability_string(self) -> str:
        return f"URI:SSK-RO:{_b32str(self.readkey)}:{_b32str(self.fingerprint)}"

@frozen
class SSKWrite:
    writekey: bytes = field(repr=False)
    fingerprint: bytes
    readkey: bytes = field(init=False, repr=False)
    storage_index: bytes = field(init=False)

    @readkey.default
    def _readkey_default(self) -> bytes:
        return _ssk_readkey_hash(self.writekey)

    @storage_index.default
    def _storage_index_default(self) -> bytes:
        return _ssk_storage_index_hash(self.readkey)

    # Callable[[SSKWrite], SSKRead]
    # XX naming?
    def get_readonly(self) -> SSKRead:
        return SSKRead(self.readkey, self.fingerprint)

class MDMFVerify:
    pass

class MDMFRead:
    pass

class MDMFWrite:
    def get_readonly(self) -> MDMFRead:
        return MDMFRead(self.readkey, self.fingerprint)

class LiteralDirectoryRead:
    pass

@frozen
class CHKDirectoryRead:
    object_cap: CHKRead

    def scrubbed_string(self) -> str:
        return f"S:URI:DIR2-CHK:{_scrub(self.object_cap.key + self.object_cap.uri_extension_hash)}"

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2-CHK:{_b32str(self.object_cap.key)}:{_b32str(self.object_cap.uri_extension_hash)}:{self.object_cap.needed}:{self.object_cap.total}:{self.object_cap.size}"

class CHKDirectoryVerify:
    pass

class SSKDirectoryVerify:
    pass

@frozen
class SSKDirectoryRead:
    object_cap: SSKRead

    def scrubbed_string(self) -> str:
        return f"S:URI:DIR2-RO:{_scrub(self.object_cap.readkey + self.object_cap.fingerprint)}"

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2-RO:{_b32str(self.object_cap.readkey)}:{_b32str(self.object_cap.fingerprint)}"

@frozen
class SSKDirectoryWrite:
    object_cap: SSKWrite

    def get_readonly(self) -> SSKDirectoryRead:
        return SSKDirectoryRead(self.object_cap.get_readonly())

    def scrubbed_string(self) -> str:
        return f"S:URI:DIR2:{_scrub(self.object_cap.writekey + self.object_cap.fingerprint)}"

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2:{_b32str(self.object_cap.writekey)}:{_b32str(self.object_cap.fingerprint)}"


class MDMFDirectoryVerify:
    pass

class MDMFDirectoryRead:
    pass

@frozen
class MDMFDirectoryWrite:
    object_cap: MDMFWrite

    def get_readonly(self) -> MDMFDirectoryRead:
        return MDMFDirectoryRead(self.object_cap.get_readonly())

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2-MDMF:{_b32str(self.object_cap.writekey)}:{_b32str(self.object_cap.fingerprint)}"


class Unknown:
    pass

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

VerifyCapability = Union[
    CHKVerify,
    SSKVerify,
    MDMFVerify,
    CHKDirectoryVerify,
    SSKDirectoryVerify,
    MDMFDirectoryVerify,
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
        return LiteralDirectoryRead()
    elif isinstance(cap, _uri.ImmutableDirectoryURI):
        o = cap._filenode_uri
        return CHKDirectoryRead(CHKRead(o.key, o.uri_extension_hash, o.needed_shares, o.total_shares, o.size))

    if cap.is_mutable():
        raise NotImmutable()
    if not _uri.IDirnodeURI.providedBy(cap):
        raise NotDirectory()

    raise NotRecognize(cap)

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
        return SSKDirectoryRead(SSKRead(o.readkey, o.fingerprint))
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
    if not IDirnodeURI.providedBy(cap):
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
