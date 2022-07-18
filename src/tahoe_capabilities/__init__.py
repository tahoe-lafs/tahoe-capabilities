from attrs import frozen, field
from typing import Union
from allmydata.util.base32 import b2a as _b2a
from allmydata.util.hashutil import ssk_readkey_hash as _ssk_readkey_hash, ssk_storage_index_hash as _ssk_storage_index_hash
from allmydata import uri as _uri

def _b32str(b: bytes) -> str:
    return _b2a(b).decode("ascii")

class LiteralRead:
    pass

@frozen
class CHKRead:
    key: bytes = field(repr=False)
    uri_extension_hash: bytes
    needed: int
    total: int
    size: int

    def danger_real_capability_string(self):
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
    def _storage_index_default(self):
        return _ssk_storage_index_hash(self.readkey)

    def danger_real_capability_string(self) -> str:
        return f"URI:SSK-RO:{_b32str(self.readkey)}:{_b32str(self.fingerprint)}"

@frozen
class SSKWrite:
    writekey: bytes = field(repr=False)
    fingerprint: bytes
    readkey: bytes = field(init=False, repr=False)
    storage_index: bytes = field(init=False)

    @readkey.default
    def _readkey_default(self):
        return _ssk_readkey_hash(self.writekey)

    @storage_index.default
    def _storage_index_default(self):
        return _ssk_storage_index_hash(self.readkey)

    def to_readonly(self) -> SSKRead:
        return SSKRead(self.readkey, self.fingerprint)

class MDMFWrite:
    pass

class MDMFRead:
    pass

class MDMFVerify:
    pass

class LiteralDirectoryRead:
    pass

@frozen
class CHKDirectoryRead:
    object_cap: CHKRead

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2-CHK:{_b32str(self.object_cap.key)}:{_b32str(self.object_cap.uri_extension_hash)}:{self.object_cap.needed}:{self.object_cap.total}:{self.object_cap.size}"

class CHKDirectoryVerify:
    pass

class SSKDirectoryVerify:
    pass

@frozen
class SSKDirectoryRead:
    object_cap: SSKRead

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2-RO:{_b32str(self.object_cap.readkey)}:{_b32str(self.object_cap.fingerprint)}"

@frozen
class SSKDirectoryWrite:
    object_cap: SSKWrite

    def to_readonly(self) -> SSKDirectoryRead:
        return SSKDirectoryRead(self.object_cap.to_readonly())

    def danger_real_capability_string(self) -> str:
        return f"URI:DIR2:{_b32str(self.object_cap.writekey)}:{_b32str(self.object_cap.fingerprint)}"


class MDMFDirectoryWrite:
    pass

class MDMFDirectoryRead:
    pass

class MDMFDirectoryVerify:
    pass

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
        raise ValueError("Capability is not immutable")
    if not _uri.IDirnodeURI.providedBy(cap):
        raise ValueError("Capability is not a directory")

    raise ValueError(f"Capability of unrecognized type {type(cap)}")

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
        raise ValueError("Capability is not read-only")
    if not _uri.IDirnodeURI.providedBy(cap):
        raise ValueError("Capability is not a directory")

    raise ValueError(f"Capability of unrecognized type {type(cap)}")

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
        raise ValueError("Capability is not writeable")
    if not IDirnodeURI.providedBy(cap):
        raise ValueError("Capability is not a directory")

    raise ValueError(f"Capability of unrecognized type {type(cap)}")
