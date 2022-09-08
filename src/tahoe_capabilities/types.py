from typing import Tuple, Union

from attrs import field, frozen

from .hashutil import ssk_readkey_hash, ssk_storage_index_hash, storage_index_hash


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

    @classmethod
    def derive(
        cls,
        readkey: bytes,
        uri_extension_hash: bytes,
        needed: int,
        total: int,
        size: int,
    ) -> "CHKRead":
        storage_index = storage_index_hash(readkey)
        return CHKRead(
            readkey, CHKVerify(storage_index, uri_extension_hash, needed, total, size)
        )

    @property
    def needed(self) -> int:
        return self.verifier.needed

    @property
    def total(self) -> int:
        return self.verifier.total

    @property
    def size(self) -> int:
        return self.verifier.size

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
    def verifier(self) -> CHKDirectoryVerify:
        return CHKDirectoryVerify(self.cap_object.verifier)

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

    @classmethod
    def derive(cls, readkey: bytes, fingerprint: bytes) -> "SSKRead":
        storage_index = ssk_storage_index_hash(readkey)
        return SSKRead(readkey, SSKVerify(storage_index, fingerprint))

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.readkey, self.verifier.fingerprint)


@frozen
class SSKWrite:
    writekey: bytes = field(repr=False)
    reader: SSKRead
    prefix: str = "SSK"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @classmethod
    def derive(cls, writekey: bytes, fingerprint: bytes) -> "SSKWrite":
        readkey = ssk_readkey_hash(writekey)
        return SSKWrite(writekey, SSKRead.derive(readkey, fingerprint))

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

    @classmethod
    def derive(cls, readkey: bytes, fingerprint: bytes) -> "MDMFRead":
        storage_index = ssk_storage_index_hash(readkey)
        return MDMFRead(readkey, MDMFVerify(storage_index, fingerprint))

    @property
    def secrets(self) -> Tuple[bytes, ...]:
        return (self.readkey, self.verifier.fingerprint)


@frozen
class MDMFWrite:
    writekey: bytes = field(repr=False)
    reader: MDMFRead
    prefix: str = "MDMF"
    suffix: Tuple[str, ...] = field(init=False, default=())

    @classmethod
    def derive(cls, writekey: bytes, fingerprint: bytes) -> "MDMFWrite":
        readkey = ssk_readkey_hash(writekey)
        return MDMFWrite(writekey, MDMFRead.derive(readkey, fingerprint))

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
]

WriteCapability = Union[
    SSKWrite,
    MDMFWrite,
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
]
