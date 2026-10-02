"""测试夹具：按 Git Pack v2 规范手工合成 pack（含 OFS_DELTA 与损坏变体）。"""

from __future__ import annotations

import hashlib
import zlib

OBJ_COMMIT = 1
OBJ_TREE = 2
OBJ_BLOB = 3
OBJ_TAG = 4
OBJ_OFS_DELTA = 6
OBJ_REF_DELTA = 7


def encode_obj_header(obj_type: int, size: int) -> bytes:
    first = (size & 0x0F) | ((obj_type & 7) << 4)
    size >>= 4
    out = bytearray()
    while size:
        out.append(first | 0x80)
        first = size & 0x7F
        size >>= 7
    out.append(first)
    return bytes(out)


def encode_ofs(negative: int) -> bytes:
    out = bytearray([negative & 0x7F])
    negative >>= 7
    while negative:
        negative -= 1
        out.append(0x80 | (negative & 0x7F))
        negative >>= 7
    out.reverse()
    return bytes(out)


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def op_copy(src: int, length: int) -> bytes:
    opcode = 0x80
    payload = bytearray()
    if src:
        for shift in (0, 8, 16, 24):
            if (src >> shift) & 0xFF:
                opcode |= 1 << (shift // 8)
                payload.append((src >> shift) & 0xFF)
    if length:
        for shift in (0, 8, 16):
            bit = 0x10 << (shift // 8)
            if (length >> shift) & 0xFF:
                opcode |= bit
                payload.append((length >> shift) & 0xFF)
    else:
        pass  # length==0 编码为 0x10000，所有长度位清零
    return bytes([opcode]) + bytes(payload)


def op_insert(data: bytes) -> bytes:
    assert 1 <= len(data) <= 127
    return bytes([len(data)]) + data


def make_delta(declared_source: int, declared_target: int, ops: bytes) -> bytes:
    return varint(declared_source) + varint(declared_target) + ops


def apply_ops_reference(base: bytes, ops: bytes) -> bytes:
    """独立的第二份 delta 应用实现，用于交叉核对。"""
    out = bytearray()
    p = 0
    while p < len(ops):
        op = ops[p]
        p += 1
        if op == 0:
            raise ValueError("bad opcode")
        if op & 0x80:
            src = size = 0
            for shift, mask in ((0, 1), (8, 2), (16, 4), (24, 8)):
                if op & mask:
                    src |= ops[p] << shift
                    p += 1
            for shift, mask in ((0, 0x10), (8, 0x20), (16, 0x40)):
                if op & mask:
                    size |= ops[p] << shift
                    p += 1
            if size == 0:
                size = 0x10000
            out += base[src:src + size]
        else:
            out += ops[p:p + op]
            p += op
    return bytes(out)


class PackBuilder:
    def __init__(self) -> None:
        # 每项：dict(type=, data=, base_idx=, level=)
        self.items: list[dict] = []

    def add(self, obj_type: int, data: bytes, base_idx: int | None = None,
            level: int = 6) -> int:
        idx = len(self.items)
        self.items.append(dict(type=obj_type, data=data,
                               base_idx=base_idx, level=level))
        return idx

    def build(self, *, corrupt_trailer: bool = False,
              inject_trailing_byte: bool = False,
              override_count: int | None = None,
              bad_version: int | None = None,
              bad_signature: bool = False,
              ofs_override: dict[int, int] | None = None) -> bytes:
        chunks: list[bytes] = []
        offsets: list[int] = []
        cursor = 12
        for i, it in enumerate(self.items):
            offsets.append(cursor)
            head = encode_obj_header(it["type"], len(it["data"]))
            if it["type"] == OBJ_OFS_DELTA:
                assert it["base_idx"] is not None
                negative = cursor - offsets[it["base_idx"]]
                if ofs_override and i in ofs_override:
                    negative = ofs_override[i]
                head += encode_ofs(negative)
            payload = zlib.compress(it["data"], it.get("level", 6))
            chunks.append(head + payload)
            cursor += len(head) + len(payload)

        sig = b"XXXX" if bad_signature else b"PACK"
        version = 2 if bad_version is None else bad_version
        count = len(self.items) if override_count is None else override_count
        out = sig + version.to_bytes(4, "big") + count.to_bytes(4, "big")
        for c in chunks:
            out += c
        if inject_trailing_byte:
            out += b"\x00"
        digest = hashlib.sha1(out).digest()
        if corrupt_trailer:
            digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
        return out + digest
