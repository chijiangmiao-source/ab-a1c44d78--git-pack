"""供单元测试与 HTTP 冒烟复用的 pack 构造夹具。"""

from __future__ import annotations

import hashlib
import struct
import zlib

from packv import OBJ_BLOB, OBJ_OFS_DELTA


def enc_obj_header(type_code: int, size: int) -> bytearray:
    out = bytearray()
    first = (size & 0x0F) | (type_code << 4)
    size >>= 4
    if size:
        first |= 0x80
    out.append(first)
    while size:
        b = size & 0x7F
        size >>= 7
        if size:
            b |= 0x80
        out.append(b)
    return out


def enc_ofs(negative: int) -> bytes:
    assert negative >= 1
    vals: list[int] = [negative & 0x7F]
    v = negative >> 7
    while v:
        vals.append((v - 1) & 0x7F)
        v = (v - 1) >> 7
    vals.reverse()
    out = bytearray()
    for i, val in enumerate(vals):
        b = val & 0x7F
        if i < len(vals) - 1:
            b |= 0x80
        out.append(b)
    return bytes(out)


def enc_delta_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def make_delta(base_size: int, ops: bytes, result_size: int) -> bytes:
    return enc_delta_varint(base_size) + enc_delta_varint(result_size) + ops


def copy_op(off: int, length: int) -> bytes:
    op = 0x80
    payload = bytearray()
    for i, bit in enumerate((0x01, 0x02, 0x04, 0x08)):
        byte = (off >> (8 * i)) & 0xFF
        if byte:
            op |= bit
            payload.append(byte)
    for i, bit in enumerate((0x10, 0x20, 0x40)):
        byte = (length >> (8 * i)) & 0xFF
        if byte:
            op |= bit
            payload.append(byte)
    return bytes([op]) + bytes(payload)


def insert_op(data: bytes) -> bytes:
    assert 1 <= len(data) <= 127
    return bytes([len(data)]) + data


def finish_pack(body: bytes, count: int, bad_sha: bool = False) -> bytes:
    pack = b"PACK" + struct.pack(">II", 2, count) + body
    digest = hashlib.sha1(pack).digest()
    if bad_sha:
        digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
    return pack + digest


def build_nested_pack() -> dict:
    """构造 blob <- OFS_DELTA <- OFS_DELTA（两层嵌套）的合法包。"""
    base = b"AAAA" + b"0123456789" * 4 + b"ZZZZ"  # 48 字节

    ops1 = insert_op(b"BBBB") + copy_op(4, 44)
    v1 = b"BBBB" + base[4:]
    d1 = make_delta(len(base), ops1, len(v1))

    p_blob = bytes(enc_obj_header(OBJ_BLOB, len(base))) + zlib.compress(base)
    blob_off = 12

    p1 = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(d1)))
          + enc_ofs(len(p_blob)) + zlib.compress(d1))
    off1 = blob_off + len(p_blob)

    ops2 = copy_op(0, 8) + insert_op(b"INSERTED!") + copy_op(8, 40)
    v2 = v1[:8] + b"INSERTED!" + v1[8:]
    d2 = make_delta(len(v1), ops2, len(v2))
    p2 = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(d2)))
          + enc_ofs(len(p1)) + zlib.compress(d2))
    off2 = off1 + len(p1)

    pack = finish_pack(p_blob + p1 + p2, 3)
    return {
        "pack": pack,
        "blob_off": blob_off,
        "delta1_off": off1,
        "delta2_off": off2,
        "v1": v1,
        "v2": v2,
    }


def build_copy_oob_pack() -> bytes:
    """构造含复制越界指令的包（包尾 SHA-1 正确，失败发生在差分应用）。"""
    base = b"0123456789"
    ops = copy_op(8, 10)  # 8 + 10 > 10
    delta = make_delta(len(base), ops, 18)
    p_blob = bytes(enc_obj_header(OBJ_BLOB, len(base))) + zlib.compress(base)
    p_delta = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
               + enc_ofs(len(p_blob)) + zlib.compress(delta))
    return finish_pack(p_blob + p_delta, 2), len(p_blob) + 12


def flip_trailer_byte(pack: bytes) -> bytes:
    """损坏覆盖正文的尾部 SHA-1 首字节。"""
    return pack[:-20] + bytes([pack[-20] ^ 0x01]) + pack[-19:]
