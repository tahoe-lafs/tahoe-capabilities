from . import types as t

_VERIFYTYPES = (
    t.CHKVerify,
    t.SSKVerify,
    t.MDMFVerify,
    t.CHKDirectoryVerify,
    t.SSKDirectoryVerify,
    t.MDMFDirectoryVerify,
)

_READTYPES = (
    t.LiteralRead,
    t.CHKRead,
    t.SSKRead,
    t.MDMFRead,
    t.LiteralDirectoryRead,
    t.CHKDirectoryRead,
    t.SSKDirectoryRead,
    t.MDMFDirectoryRead,
)

_WRITETYPES = (
    t.SSKWrite,
    t.MDMFWrite,
    t.SSKDirectoryWrite,
    t.MDMFDirectoryWrite,
)

_MUTABLETYPES = (
    t.SSKVerify,
    t.SSKRead,
    t.SSKWrite,
    t.MDMFVerify,
    t.MDMFRead,
    t.MDMFWrite,
    t.SSKDirectoryVerify,
    t.SSKDirectoryRead,
    t.SSKDirectoryWrite,
    t.MDMFDirectoryVerify,
    t.MDMFDirectoryRead,
    t.MDMFDirectoryWrite,
)

_DIRECTORYTYPES = (
    t.LiteralDirectoryRead,
    t.CHKDirectoryVerify,
    t.CHKDirectoryRead,
    t.SSKDirectoryVerify,
    t.SSKDirectoryRead,
    t.SSKDirectoryWrite,
    t.MDMFDirectoryVerify,
    t.MDMFDirectoryRead,
    t.MDMFDirectoryWrite,
)


def is_verify(cap: t.Capability) -> bool:
    return isinstance(cap, _VERIFYTYPES)


def is_read(cap: t.Capability) -> bool:
    return isinstance(cap, _READTYPES)


def is_write(cap: t.Capability) -> bool:
    return isinstance(cap, _WRITETYPES)


def is_mutable(cap: t.Capability) -> bool:
    return isinstance(cap, _MUTABLETYPES)


def is_directory(cap: t.Capability) -> bool:
    return isinstance(cap, _DIRECTORYTYPES)
