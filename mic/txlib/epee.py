"""
MIC - Monero Inflation Checker - is licensed under GPL 3.0 by DangerousFreedom.

Minimal epee portable-storage codec (read + write).

Format reference: epee/include/storages/portable_storage_*.h
"""



import struct

SIG_A = 0x01011101
SIG_B = 0x01020101
FORMAT_VER = 1
_HEADER = struct.pack("<IIB", SIG_A, SIG_B, FORMAT_VER)

T_INT64 = 1
T_INT32 = 2
T_INT16 = 3
T_INT8 = 4
T_UINT64 = 5
T_UINT32 = 6
T_UINT16 = 7
T_UINT8 = 8
T_DOUBLE = 9
T_STRING = 10
T_BOOL = 11
T_OBJECT = 12
T_ARRAY = 13
FLAG_ARRAY = 0x80

_FIXED = {
    T_INT64: ("<q", 8),
    T_INT32: ("<i", 4),
    T_INT16: ("<h", 2),
    T_INT8: ("<b", 1),
    T_UINT64: ("<Q", 8),
    T_UINT32: ("<I", 4),
    T_UINT16: ("<H", 2),
    T_UINT8: ("<B", 1),
    T_DOUBLE: ("<d", 8),
    T_BOOL: ("<B", 1),
}


# --------------------------------------------------------------------------- #
#  reader
# --------------------------------------------------------------------------- #
class _R:
    def __init__(self, d):
        self.d = d
        self.i = 0

    def take(self, n):
        b = self.d[self.i : self.i + n]
        self.i += n
        return b

    def u8(self):
        return self.take(1)[0]

    def varin(self):
        b0 = self.u8()
        mark = b0 & 0x03
        if mark == 0:
            return b0 >> 2
        if mark == 1:
            b1 = self.u8()
            return (b0 | (b1 << 8)) >> 2
        if mark == 2:
            rest = self.take(3)
            v = b0 | (rest[0] << 8) | (rest[1] << 16) | (rest[2] << 24)
            return v >> 2
        rest = self.take(7)
        v = b0
        for k, byte in enumerate(rest):
            v |= byte << (8 * (k + 1))
        return v >> 2


def _read_value(r, type_byte):
    base = type_byte & 0x7F
    if type_byte & FLAG_ARRAY:
        n = r.varin()
        return [_read_single(r, base) for _ in range(n)]
    return _read_single(r, base)


def _read_single(r, base):
    if base in _FIXED:
        fmt, size = _FIXED[base]
        return struct.unpack(fmt, r.take(size))[0]
    if base == T_STRING:
        n = r.varin()
        return r.take(n)
    if base == T_OBJECT:
        return _read_section(r)
    if base == T_ARRAY:
        # array-of-arrays marker: next byte gives element type
        inner = r.u8()
        n = r.varin()
        return [_read_single(r, inner & 0x7F) for _ in range(n)]
    raise ValueError(f"epee: unknown type {base}")


def _read_section(r):
    count = r.varin()
    out = {}
    for _ in range(count):
        name_len = r.u8()
        name = r.take(name_len).decode("ascii")
        type_byte = r.u8()
        out[name] = _read_value(r, type_byte)
    return out


def loads(data: bytes) -> dict:
    if data[:9] != _HEADER:
        raise ValueError("bad epee header")
    r = _R(data)
    r.i = 9
    return _read_section(r)


# --------------------------------------------------------------------------- #
#  writer
# --------------------------------------------------------------------------- #
def _varin(n: int) -> bytes:
    if n <= 0x3F:
        return bytes([(n << 2) | 0])
    if n <= 0x3FFF:
        return struct.pack("<H", (n << 2) | 1)
    if n <= 0x3FFFFFFF:
        return struct.pack("<I", (n << 2) | 2)
    return struct.pack("<Q", (n << 2) | 3)


class U64(int):
    """Marker so the writer emits a uint64 field."""


def _write_value(v) -> bytes:
    if isinstance(v, U64):
        return bytes([T_UINT64]) + struct.pack("<Q", int(v))
    if isinstance(v, bool):
        return bytes([T_BOOL]) + struct.pack("<B", 1 if v else 0)
    if isinstance(v, int):
        return bytes([T_UINT64]) + struct.pack("<Q", v)
    if isinstance(v, (bytes, bytearray)):
        return bytes([T_STRING]) + _varin(len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return bytes([T_STRING]) + _varin(len(b)) + b
    if isinstance(v, dict):
        return bytes([T_OBJECT]) + _write_section(v)
    if isinstance(v, list):
        if not v:
            # empty array of uint64 by default
            return bytes([T_UINT64 | FLAG_ARRAY]) + _varin(0)
        first = v[0]
        if isinstance(first, (int,)) and not isinstance(first, bool):
            body = b"".join(struct.pack("<Q", int(x)) for x in v)
            return bytes([T_UINT64 | FLAG_ARRAY]) + _varin(len(v)) + body
        if isinstance(first, (bytes, bytearray, str)):
            body = b"".join(_write_value(x)[1:] for x in v)
            return bytes([T_STRING | FLAG_ARRAY]) + _varin(len(v)) + body
        if isinstance(first, dict):
            body = b"".join(_write_section(x) for x in v)
            return bytes([T_OBJECT | FLAG_ARRAY]) + _varin(len(v)) + body
    raise ValueError(f"epee: cannot encode {type(v)}")


def _write_section(d: dict) -> bytes:
    out = bytearray()
    out += _varin(len(d))
    for name, v in d.items():
        nb = name.encode("ascii")
        out.append(len(nb))
        out += nb
        out += _write_value(v)
    return bytes(out)


def dumps(d: dict) -> bytes:
    return _HEADER + _write_section(d)
