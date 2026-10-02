"""Git Pack v2 严格解析与 OFS_DELTA 链复原校验（仅依赖标准库）。

校验顺序：
  1. Pack 头（魔数 PACK、版本号 2）与对象计数；
  2. 逐对象走查：变长对象头、OFS 负偏移编码，并精确定位每段 zlib 流；
  3. 包正文必须被对象流完整覆盖，随后核对尾部 20 字节 SHA-1；
  4. 定位目标对象（偏移必须落在对象起点），沿 OFS 链还原到 blob 基对象；
  5. 逐层应用 delta，核对声明源/目标长度、复制不越界，给出复制与插入证据。

任何失败都抛出 :class:`PackError`，其中 ``offset`` 为包内首个失败字节的绝对偏移。
"""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass, field
from typing import Any

PACK_SIGNATURE = b"PACK"
SUPPORTED_VERSION = 2
TRAILER_LEN = 20
HEADER_LEN = 12
MAX_PACK_SIZE = 256 * 1024

OBJ_COMMIT = 1
OBJ_TREE = 2
OBJ_BLOB = 3
OBJ_TAG = 4
OBJ_OFS_DELTA = 6
OBJ_REF_DELTA = 7

TYPE_NAMES = {
    OBJ_COMMIT: "commit",
    OBJ_TREE: "tree",
    OBJ_BLOB: "blob",
    OBJ_TAG: "tag",
    OBJ_OFS_DELTA: "ofs_delta",
    OBJ_REF_DELTA: "ref_delta",
}

# 目标对象及其基链只接受 blob 与以 blob 为根的嵌套 OFS_DELTA。
ACCEPTED_TARGET_TYPES = (OBJ_BLOB, OBJ_OFS_DELTA)


class PackError(Exception):
    """携带首个失败字节偏移的解析/校验错误。"""

    def __init__(self, code: str, message: str, offset: int | None = None,
                 detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.offset is not None:
            d["offset"] = self.offset
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class CopyOp:
    src: int
    len: int
    dst: int  # 在复原结果中的起始位置


@dataclass
class InsertOp:
    dst: int
    data: bytes

    @property
    def len(self) -> int:
        return len(self.data)


@dataclass
class ObjectRecord:
    offset: int               # 对象头起点
    type: int
    declared_size: int        # 变长头声明的解压长度
    data_start: int           # zlib 流起点
    stream_end: int           # zlib 流结束后的下一字节
    inflated: bytes
    ofs_negative: int | None = None       # OFS_DELTA 的负偏移值
    base_offset: int | None = None        # 解析后的基对象绝对偏移
    ofs_field_start: int | None = None    # OFS 变长字段首字节
    ref_name: bytes | None = None         # REF_DELTA 的 20 字节基名


@dataclass
class DeltaLayer:
    index: int
    delta_offset: int        # 本层 delta 对象起点
    base_offset: int         # 基对象起点
    source_size_declared: int
    source_size_actual: int
    target_size_declared: int
    target_size_actual: int
    source_size_field: int   # 包内绝对偏移
    target_size_field: int
    copies: list[CopyOp] = field(default_factory=list)
    inserts: list[InsertOp] = field(default_factory=list)


@dataclass
class VerifyResult:
    target_offset: int
    object_count: int
    pack_size: int
    records: list[ObjectRecord]
    root: ObjectRecord
    chain: list[ObjectRecord]          # 根 blob -> ... -> 目标（含两端）
    layers: list[DeltaLayer]           # 根之后逐层 delta
    content: bytes

    @property
    def sha1(self) -> str:
        return canonical_blob_sha1(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "target_offset": self.target_offset,
            "type": "blob",  # 允许的目标经 OFS 链复原后恒为 blob
            "length": len(self.content),
            "sha1": self.sha1,
            "object_count": self.object_count,
            "pack_size": self.pack_size,
            "chain": [
                {
                    "offset": r.offset,
                    "type": TYPE_NAMES[r.type],
                    "inflated_size": len(r.inflated),
                    "declared_size": r.declared_size,
                    "data_start": r.data_start,
                    "stream_end": r.stream_end,
                    **(
                        {"base_offset": r.base_offset,
                         "ofs_negative": r.ofs_negative}
                        if r.type == OBJ_OFS_DELTA else {}
                    ),
                }
                for r in self.chain
            ],
            "layers": [
                {
                    "layer": layer.index,
                    "delta_offset": layer.delta_offset,
                    "base_offset": layer.base_offset,
                    "declared_source_size": layer.source_size_declared,
                    "actual_source_size": layer.source_size_actual,
                    "declared_target_size": layer.target_size_declared,
                    "actual_target_size": layer.target_size_actual,
                    "source_size_field": layer.source_size_field,
                    "target_size_field": layer.target_size_field,
                    "copies": [
                        {"src": c.src, "len": c.len, "dst": c.dst}
                        for c in layer.copies
                    ],
                    "inserts": [
                        {"dst": i.dst, "len": i.len, "data_hex": i.data.hex()}
                        for i in layer.inserts
                    ],
                }
                for layer in self.layers
            ],
        }


def canonical_blob_sha1(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()


# --------------------------------------------------------------------------
# 基础变长编码
# --------------------------------------------------------------------------

def decode_size_header(buf: bytes, pos: int) -> tuple[int, int, int]:
    """解析对象头首字节起的 MSB 续位变长整数。

    返回 (type, size, next_pos)。首字节低 4 位为尺寸低位，bits[6:4] 为类型。
    """
    if pos >= len(buf):
        raise PackError("TRUNCATED_HEADER", "对象头被截断：缺少首字节", pos)
    start = pos
    first = buf[pos]
    obj_type = (first >> 4) & 0x07
    size = first & 0x0F
    shift = 4
    pos += 1
    while first & 0x80:
        if pos >= len(buf):
            raise PackError(
                "TRUNCATED_HEADER", "对象变长尺寸编码被截断", start)
        b = buf[pos]
        size |= (b & 0x7F) << shift
        shift += 7
        pos += 1
        first = b
    return obj_type, size, pos


def encode_size_header(obj_type: int, size: int) -> bytes:
    """编码对象头（尺寸 MSB 续位变长，类型在首字节 bits[6:4]）。"""
    out = bytearray()
    first = True
    while True:
        if first:
            b = (size & 0x0F) | ((obj_type & 0x07) << 4)
            size >>= 4
            first = False
        else:
            b = size & 0x7F
            size >>= 7
        if size:
            b |= 0x80
        out.append(b)
        if not size:
            break
    return bytes(out)


def decode_ofs_negative(buf: bytes, pos: int) -> tuple[int, int]:
    """解析 OFS_DELTA 的负偏移变长编码，返回 (negative, next_pos)。"""
    if pos >= len(buf):
        raise PackError("TRUNCATED_HEADER", "OFS 负偏移编码被截断", pos)
    start = pos
    b = buf[pos]
    pos += 1
    negative = b & 0x7F
    while b & 0x80:
        if pos >= len(buf):
            raise PackError(
                "TRUNCATED_HEADER", "OFS 负偏移续位字节被截断", start)
        negative += 1
        b = buf[pos]
        pos += 1
        negative = (negative << 7) | (b & 0x7F)
    return negative, pos


def encode_ofs_negative(negative: int) -> bytes:
    """OFS 负偏移编码（Git 规则：每进一位先减 1，高位字节在前）。"""
    out = bytearray([negative & 0x7F])
    negative >>= 7
    while negative:
        negative -= 1
        out.append(0x80 | (negative & 0x7F))
        negative >>= 7
    out.reverse()
    return bytes(out)


def _decode_delta_size(data: bytes, pos: int, field_start: int) -> tuple[int, int]:
    """delta 数据中的 LEB128 源/目标长度（无类型位）。

    截断时报该变长字段的起点 ``field_start``（首个承诺续位却无终止的字节），
    与对象头截断报告对象起点的做法保持一致。
    """
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise PackError(
                "DELTA_HEADER_TRUNCATED",
                "delta 长度字段被截断", field_start)
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


# --------------------------------------------------------------------------
# zlib 流精确定位
# --------------------------------------------------------------------------

def _inflate_stream(buf: bytes, start: int) -> tuple[bytes, int]:
    """解压从 ``start`` 开始的 zlib 流，返回 (解压数据, 流结束偏移)。

    一次性喂入剩余全部字节并借助 ``unused_data`` 精确确定流边界，保证后随
    对象头与 20 字节包摘要不会被误吞；解压报错时退回逐字节重放，定位首个
    触发 zlib 错误的字节偏移。
    """
    tail = buf[start:]
    try:
        dec = zlib.decompressobj()
        out = dec.decompress(tail)
        out += dec.flush()
    except zlib.error as exc:
        msg = str(exc)
        if "incomplete" in msg or "truncated" in msg:
            raise PackError(
                "ZLIB_TRUNCATED",
                "zlib 流在包结束前未正常终止", start)
        # 其它损坏：逐字节重放以定位首个触发错误的字节。
        pinpoint = zlib.decompressobj()
        pos = start
        while pos < len(buf):
            try:
                pinpoint.decompress(buf[pos:pos + 1])
            except zlib.error as exc2:
                raise PackError(
                    "ZLIB_ERROR", f"zlib 解压失败：{exc2}", pos) from exc2
            pos += 1
        raise PackError(
            "ZLIB_ERROR", f"zlib 解压失败：{msg}", start)
    if not dec.eof:
        raise PackError(
            "ZLIB_TRUNCATED", "zlib 流在包结束前未正常终止", start)
    end = start + len(tail) - len(dec.unused_data)
    return bytes(out), end


# --------------------------------------------------------------------------
# Pack 级走查
# --------------------------------------------------------------------------

def _walk_pack(buf: bytes) -> tuple[int, list[ObjectRecord]]:
    if len(buf) < HEADER_LEN:
        raise PackError(
            "TRUNCATED_HEADER",
            f"数据短于 {HEADER_LEN} 字节的 Pack 头", len(buf))
    if buf[:4] != PACK_SIGNATURE:
        raise PackError("BAD_SIGNATURE", "Pack 魔数不是 'PACK'", 0)
    version = int.from_bytes(buf[4:8], "big")
    if version != SUPPORTED_VERSION:
        raise PackError(
            "UNSUPPORTED_VERSION",
            f"仅支持 Pack v2，实际版本为 {version}", 4)
    count = int.from_bytes(buf[8:12], "big")
    body_end = len(buf) - TRAILER_LEN

    records: list[ObjectRecord] = []
    pos = HEADER_LEN
    for _ in range(count):
        if pos >= body_end:
            raise PackError(
                "TRUNCATED_OBJECT",
                f"对象计数为 {count}，但偏移 {pos} 已到包正文之外", pos)
        obj_start = pos
        obj_type, declared, pos = decode_size_header(buf, pos)

        if obj_type not in TYPE_NAMES:
            raise PackError(
                "INVALID_OBJECT_TYPE",
                f"对象类型 {obj_type} 不是合法的 Pack 对象类型",
                obj_start)

        ofs_negative = None
        base_offset = None
        ofs_field = None
        ref_name = None

        if obj_type == OBJ_OFS_DELTA:
            ofs_field = pos
            ofs_negative, pos = decode_ofs_negative(buf, pos)
            if ofs_negative <= 0:
                raise PackError(
                    "BAD_OFS_OFFSET",
                    "OFS 负偏移必须为正数", ofs_field)
            base_offset = obj_start - ofs_negative
            if base_offset < 0:
                raise PackError(
                    "BASE_NOT_PRIOR",
                    f"基对象偏移 {base_offset} 位于包起点之前",
                    base_offset)
        elif obj_type == OBJ_REF_DELTA:
            if pos + 20 > body_end:
                raise PackError(
                    "TRUNCATED_HEADER",
                    "REF_DELTA 缺少 20 字节基对象名", obj_start)
            ref_name = bytes(buf[pos:pos + 20])
            pos += 20

        data_start = pos
        inflated, stream_end = _inflate_stream(buf, data_start)
        if declared != len(inflated):
            raise PackError(
                "DECLARED_SIZE_MISMATCH",
                (f"对象头声明解压长度 {declared}，"
                 f"实际 zlib 流解压长度 {len(inflated)}"),
                obj_start,
                {"declared": declared, "actual": len(inflated)})

        rec = ObjectRecord(
            offset=obj_start,
            type=obj_type,
            declared_size=declared,
            data_start=data_start,
            stream_end=stream_end,
            inflated=inflated,
            ofs_negative=ofs_negative,
            base_offset=base_offset,
            ofs_field_start=ofs_field,
            ref_name=ref_name,
        )
        records.append(rec)
        pos = stream_end

    if pos != body_end:
        # 最后一个 zlib 流与尾部摘要之间存在未被对象覆盖的尾随字节。
        raise PackError(
            "TRAILING_BODY_BYTES",
            (f"包正文存在 {body_end - pos} 字节未被对象流覆盖的尾随数据"),
            pos)

    # 尾部 SHA-1 覆盖从 'PACK' 到正文最后一个字节的全部内容。
    expected = hashlib.sha1(buf[:body_end]).digest()
    actual = bytes(buf[body_end:body_end + TRAILER_LEN])
    if expected != actual:
        raise PackError(
            "TRAILER_MISMATCH",
            "尾部 SHA-1 与包正文摘要不匹配",
            body_end,
            {"expected": expected.hex(), "actual": actual.hex()})

    # 全局核对所有 OFS_DELTA 的基对象必须指向更早的对象起点。
    starts = {r.offset: r for r in records}
    for rec in records:
        if rec.type == OBJ_OFS_DELTA:
            base = starts.get(rec.base_offset)  # type: ignore[arg-type]
            if base is None or base.offset >= rec.offset:
                raise PackError(
                    "BASE_NOT_PRIOR",
                    (f"偏移 {rec.offset} 处 OFS_DELTA 声明的基对象偏移 "
                     f"{rec.base_offset} 不是更早的对象起点"),
                    rec.base_offset)

    return count, records


# --------------------------------------------------------------------------
# delta 应用
# --------------------------------------------------------------------------

def apply_delta(base: bytes, delta: bytes, record: ObjectRecord,
                layer_index: int) -> tuple[bytes, DeltaLayer]:
    """对单层 delta 做严格应用，返回 (结果, 证据层)。

    ``record`` 为该 delta 对象的包内记录，用于把相对偏移换算成包内绝对偏移。
    """
    base_off = record.data_start  # delta 数据首字节在包内的绝对偏移

    source_field = base_off
    source_size, p = _decode_delta_size(delta, 0, base_off)
    target_field = base_off + p
    target_size, p = _decode_delta_size(delta, p, base_off)

    if source_size != len(base):
        raise PackError(
            "DELTA_SOURCE_SIZE_MISMATCH",
            (f"delta 声明源长度 {source_size}，"
             f"实际基对象长度 {len(base)}"),
            source_field,
            {"declared": source_size, "actual": len(base)})

    out = bytearray()
    copies: list[CopyOp] = []
    inserts: list[InsertOp] = []
    dlen = len(delta)

    while p < dlen:
        op = delta[p]
        op_abs = base_off + p
        if op == 0:
            raise PackError(
                "INVALID_DELTA_OPCODE",
                "delta 操作码 0x00 为 Git 保留非法值", op_abs)
        if op & 0x80:
            # copy 指令：1 字节掩码 + 最多 4 字节源偏移 + 最多 3 字节长度。
            p += 1
            cp_offset = 0
            cp_size = 0
            try:
                for shift, mask in ((0, 0x01), (8, 0x02),
                                    (16, 0x04), (24, 0x08)):
                    if op & mask:
                        cp_offset |= delta[p] << shift
                        p += 1
                for shift, mask in ((0, 0x10), (8, 0x20), (16, 0x40)):
                    if op & mask:
                        cp_size |= delta[p] << shift
                        p += 1
            except IndexError:
                raise PackError(
                    "DELTA_OPERAND_TRUNCATED",
                    "copy 指令操作数超出 delta 数据结尾",
                    base_off + min(p, dlen))
            if cp_size == 0:
                cp_size = 0x10000
            if cp_offset + cp_size > len(base) or cp_offset > len(base):
                raise PackError(
                    "DELTA_COPY_OUT_OF_RANGE",
                    (f"copy 越界：源偏移 {cp_offset}、长度 {cp_size}，"
                     f"基对象长度仅 {len(base)}"),
                    op_abs,
                    {"copy_offset": cp_offset, "copy_size": cp_size,
                     "source_len": len(base)})
            dst = len(out)
            out += base[cp_offset:cp_offset + cp_size]
            copies.append(CopyOp(src=cp_offset, len=cp_size, dst=dst))
        else:
            # insert 指令：低 7 位为字面量字节数（1..127）。
            length = op & 0x7F
            p += 1
            if p + length > dlen:
                raise PackError(
                    "DELTA_OPERAND_TRUNCATED",
                    f"insert 指令需要 {length} 字节，delta 数据不足",
                    op_abs)
            dst = len(out)
            data = bytes(delta[p:p + length])
            out += data
            inserts.append(InsertOp(dst=dst, data=data))
            p += length

    if target_size != len(out):
        raise PackError(
            "DELTA_TARGET_SIZE_MISMATCH",
            (f"delta 声明目标长度 {target_size}，"
             f"实际复制/插入结果长度 {len(out)}"),
            target_field,
            {"declared": target_size, "actual": len(out)})

    layer = DeltaLayer(
        index=layer_index,
        delta_offset=record.offset,
        base_offset=record.base_offset,  # type: ignore[arg-type]
        source_size_declared=source_size,
        source_size_actual=len(base),
        target_size_declared=target_size,
        target_size_actual=len(out),
        source_size_field=source_field,
        target_size_field=target_field,
        copies=copies,
        inserts=inserts,
    )
    return bytes(out), layer


# --------------------------------------------------------------------------
# 对外入口
# --------------------------------------------------------------------------

def verify_pack(buf: bytes, target_offset: int) -> VerifyResult:
    """完整校验入口，成功返回 :class:`VerifyResult`，失败抛 :class:`PackError`。"""
    if not isinstance(target_offset, int) or isinstance(target_offset, bool):
        raise PackError(
            "BAD_OFFSET", "目标对象偏移必须为非负整数", target_offset)
    if target_offset < 0:
        raise PackError(
            "BAD_OFFSET", "目标对象偏移不能为负数", target_offset)

    count, records = _walk_pack(buf)

    by_start = {r.offset: r for r in records}
    target = by_start.get(target_offset)
    if target is None:
        if target_offset >= len(buf):
            raise PackError(
                "OFFSET_OUT_OF_RANGE",
                f"偏移 {target_offset} 超出包长度 {len(buf)}", target_offset)
        raise PackError(
            "OFFSET_NOT_OBJECT_START",
            (f"偏移 {target_offset} 未落在任何对象的起点"
             f"（对象起点：{', '.join(str(r.offset) for r in records) or '无'}）"),
            target_offset)

    if target.type not in ACCEPTED_TARGET_TYPES:
        raise PackError(
            "TYPE_NOT_ALLOWED",
            (f"目标对象类型为 {TYPE_NAMES[target.type]}，"
             "仅接受 blob 与 OFS_DELTA（含嵌套 OFS_DELTA）"),
            target.offset,
            {"type": TYPE_NAMES[target.type]})

    # 回溯基对象链：目标 -> ... -> 根。
    back: list[ObjectRecord] = []
    cur = target
    seen: set[int] = set()
    while cur.type == OBJ_OFS_DELTA:
        if cur.offset in seen:
            raise PackError(
                "DELTA_CYCLE", "delta 基对象链存在环", cur.offset)
        seen.add(cur.offset)
        base = by_start.get(cur.base_offset)  # type: ignore[arg-type]
        if base is None:
            raise PackError(
                "BASE_NOT_PRIOR",
                (f"偏移 {cur.offset} 处 delta 的基对象偏移 "
                 f"{cur.base_offset} 不是更早的对象起点"),
                cur.base_offset)
        back.append(cur)
        cur = base

    if cur.type != OBJ_BLOB:
        raise PackError(
            "ROOT_TYPE_NOT_BLOB",
            (f"基对象链根位于偏移 {cur.offset}，类型为 "
             f"{TYPE_NAMES[cur.type]}，仅接受 blob 根"),
            cur.offset,
            {"type": TYPE_NAMES[cur.type]})

    root = cur
    chain = [root] + list(reversed(back))  # 根 -> ... -> 目标

    # 逐层应用：根 blob 内容作为第 1 层的源。
    content = root.inflated
    layers: list[DeltaLayer] = []
    for i, delta_rec in enumerate(reversed(back), start=1):
        content, layer = apply_delta(content, delta_rec.inflated,
                                     delta_rec, i)
        layers.append(layer)

    return VerifyResult(
        target_offset=target_offset,
        object_count=count,
        pack_size=len(buf),
        records=records,
        root=root,
        chain=chain,
        layers=layers,
        content=content,
    )
