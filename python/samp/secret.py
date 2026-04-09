from __future__ import annotations

from samp.error import SampError


class Seed:
    __slots__ = ("_bytes",)

    def __init__(self, b: bytes) -> None:
        if len(b) != 32:
            raise SampError(f"seed must be 32 bytes, got {len(b)}")
        self._bytes = bytes(b)

    @classmethod
    def from_bytes(cls, b: bytes) -> "Seed":
        return cls(b)

    # WHY: every caller is an audit point - grep `expose_secret` to enumerate them.
    def expose_secret(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:
        return "Seed([REDACTED])"

    def __str__(self) -> str:
        return "Seed([REDACTED])"


class ViewScalar:
    __slots__ = ("_bytes",)

    def __init__(self, b: bytes) -> None:
        if len(b) != 32:
            raise SampError(f"view_scalar must be 32 bytes, got {len(b)}")
        self._bytes = bytes(b)

    @classmethod
    def from_bytes(cls, b: bytes) -> "ViewScalar":
        return cls(b)

    def expose_secret(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:
        return "ViewScalar([REDACTED])"

    def __str__(self) -> str:
        return "ViewScalar([REDACTED])"


class ContentKey:
    __slots__ = ("_bytes",)

    def __init__(self, b: bytes) -> None:
        if len(b) != 32:
            raise SampError(f"content_key must be 32 bytes, got {len(b)}")
        self._bytes = bytes(b)

    @classmethod
    def from_bytes(cls, b: bytes) -> "ContentKey":
        return cls(b)

    def expose_secret(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:
        return "ContentKey([REDACTED])"

    def __str__(self) -> str:
        return "ContentKey([REDACTED])"
