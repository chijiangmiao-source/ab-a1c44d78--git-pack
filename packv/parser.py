"""Git Pack v2 解析与 OFS_DELTA 复原（仅 blob / OFS_DELTA 白名单）。

Pack 格式参考：
  头部 12 字节: "PACK" + 版本(4) + 对象数(4)，均为网络字节序；
  对象头为变长 little-endian MSB 续位编码：首字节低 3 位为类型，
  其余位与后续字节各提供 7 位长度；
  OFS_DELTA 的负偏移为 n 字节变长编码（首字节含第 1 位哨兵）；
  对像正文为 zlib (RFC1950) 流，校验要求流结束后不得有尾随字节；
  包尾 20 字节为覆盖整个 pack（含头尾）的 SHA-1。

差分指令：MSB=1 为复制（从源读取），否则为插入（字面字节），
指令流也必须精确耗尽，无尾随字节。
"""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass, field
from typing import Optional

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

# 网页允许粘贴的 Base64 解码后上限：256 KiB。
MAX_PACK_BYTES = 256 * 1024

# 单个对象解压内容 / 每层差分复原结果的上限，防止解压炸弹耗尽内存。
MAX_INFLATED_BYTES = 64 * 1024 * 1024

# 喂给 zlib 的输入块大小；取 8 KiB 使单块最坏解压产出（高熵压缩比
# 极限下约数 MiB）保持有界。
_INFLATE_CHUNK = 8 * 1024

HEADER_LEN = 12
TRAILER_LEN = 20


class VerificationError(Exception):
    """带首个失败字节偏移的校验失败。

    offset 为相对 pack 起始的绝对偏移（无法归因时为 None）；
    若错误位于某对象解压后的正文内（如差分指令），detail_offset
    给出相对该对象解压数据起点的字节偏移。
    """

    def __init__(
        self,
        message: str,
        offset: Optional[int] = None,
        detail_offset: Optional[int] = None,
    ):
        super().__init__(message)
        self.message = message
        self.offset = offset
        self.detail_offset = detail_offset


@dataclass
class CopyStep:
    """一条复制指令的证据。"""

    kind: str = "copy"
    cmd_offset: int = 0          # 指令相对差分数据起点的偏移
    src_offset: int = 0
    length: int = 0
    dst_offset: int = 0          # 复制前目标已写长度
    bytes_hex: str = ""          # 实际复制字节（证据，截断由展示层处理）

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "cmd_offset": self.cmd_offset,
            "src_offset": self.src_offset,
            "length": self.length,
            "dst_offset": self.dst_offset,
            "bytes_hex": self.bytes_hex,
        }


@dataclass
class InsertStep:
    """一条插入指令的证据。"""

    kind: str = "insert"
    cmd_offset: int = 0
    length: int = 0
    dst_offset: int = 0
    bytes_hex: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "cmd_offset": self.cmd_offset,
            "length": self.length,
            "dst_offset": self.dst_offset,
            "bytes_hex": self.bytes_hex,
        }


@dataclass
class ObjectInfo:
    offset: int
    type_code: int
    declared_size: int          # 对象头声明的（解压）长度
    data_start: int             # zlib 流起点
    data_end: int               # zlib 流之后第一个字节
    data: bytes = b""           # 解压后内容（delta 为差分指令）


@dataclass
class DeltaLayer:
    """一层 OFS_DELTA 的复原证据。"""

    delta_offset: int           # 本 delta 对象在 pack 中的偏移
    base_offset: int            # 其声明基对象的偏移
    base_size_declared: int     # 差分头声明的源长度
    result_size_declared: int   # 差分头声明的目标长度
    base_size_actual: int       # 基对象复原后的真实长度
    result_size_actual: int     # 应用差分后的真实长度
    steps: list = field(default_factory=list)  # list[CopyStep | InsertStep]
    result_sha1: str = ""       # 本层产物的规范 SHA-1


def _read_size_header(data: bytes, pos: int) -> tuple[int, int, int]:
    """读取对象变长头。返回 (type_code, size, new_pos)。"""
    if pos >= len(data):
        raise VerificationError("对象头超出 pack 边界", pos)
    first = data[pos]
    type_code = (first >> 4) & 0x7
    size = first & 0x0F
    shift = 4
    pos += 1
    while first & 0x80:
        if pos >= len(data):
            raise VerificationError("不完整的变长对象头（续位截断）", pos)
        b = data[pos]
        size |= (b & 0x7F) << shift
        shift += 7
        pos += 1
        first = b
    return type_code, size, pos


def _read_ofs_delta(data: bytes, pos: int) -> tuple[int, int]:
    """读取 OFS_DELTA 的负偏移编码。返回 (negative_offset, new_pos)。"""
    if pos >= len(data):
        raise VerificationError("OFS_DELTA 偏移编码超出 pack 边界", pos)
    first = data[pos]
    ofs = first & 0x7F
    pos += 1
    while first & 0x80:
        if pos >= len(data):
            raise VerificationError("不完整的 OFS_DELTA 偏移编码", pos)
        b = data[pos]
        ofs = ((ofs + 1) << 7) | (b & 0x7F)
        pos += 1
        first = b
    return ofs, pos


def _inflate_exact(data: bytes, start: int) -> tuple[bytes, int]:
    """从 start 解压单个 zlib 流，返回 (解压内容, 流结束后偏移)。

    通过 max_length 分块限制解压后总长，防止解压炸弹。流后可能合法地
    紧跟下一对象或 20 字节包尾，因此不在此处判定尾随；调用方依靠
    "对象必须连续排布 + 末端必须精确抵达正文边界"发现垃圾字节。
    """
    d = zlib.decompressobj()
    out = bytearray()
    pos = start
    end_offset: Optional[int] = None
    try:
        # 按输入分块喂入（不设输出上限，故 unconsumed_tail 恒为空），
        # 既能限制解压后总长，又能用 unused_data 精确定位流终点。
        while pos < len(data):
            in_len = min(_INFLATE_CHUNK, len(data) - pos)
            piece = d.decompress(data[pos:pos + in_len])
            out.extend(piece)
            if len(out) > MAX_INFLATED_BYTES:
                raise VerificationError(
                    f"解压对象超过 {MAX_INFLATED_BYTES} 字节上限"
                    "（疑似解压炸弹）",
                    start,
                )
            if d.eof:
                end_offset = pos + in_len - len(d.unused_data)
                break
            pos += in_len
        out.extend(d.flush())
    except zlib.error as exc:
        raise VerificationError(f"zlib 流损坏: {exc}", start) from exc
    if not d.eof:
        raise VerificationError("zlib 流在 pack 内提前截断", start)
    return bytes(out), end_offset


def _read_varint_delta(data: bytes, pos: int) -> tuple[int, int]:
    """差分头中的 little-endian MSB 续位 7 位变长整数。"""
    result = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise VerificationError("差分长度字段截断", start)
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7


def parse_pack(pack: bytes) -> tuple[int, list[ObjectInfo]]:
    """解析 pack 头并枚举全部对象（不做 delta 复原）。

    返回 (对象计数, 按出现顺序的 ObjectInfo 列表)。
    """
    if len(pack) < HEADER_LEN + TRAILER_LEN:
        raise VerificationError("pack 短于 头部(12)+尾部(20)=32 字节", 0)
    if pack[:4] != b"PACK":
        raise VerificationError('缺少 "PACK" 签名', 0)
    version = int.from_bytes(pack[4:8], "big")
    if version != 2:
        raise VerificationError(f"不支持的 pack 版本: {version}（仅接受 v2）", 4)
    count = int.from_bytes(pack[8:12], "big")

    body_end = len(pack) - TRAILER_LEN
    objects: list[ObjectInfo] = []
    pos = HEADER_LEN
    for idx in range(count):
        obj_start = pos
        if pos >= body_end:
            raise VerificationError(
                f"对象 #{idx} 起点越过正文边界", obj_start
            )
        type_code, size, after_hdr = _read_size_header(pack, pos)
        if type_code not in TYPE_NAMES:
            raise VerificationError(
                f"非法对象类型码 {type_code}", obj_start
            )
        p = after_hdr
        if type_code == OBJ_OFS_DELTA:
            _, p = _read_ofs_delta(pack, p)
        elif type_code == OBJ_REF_DELTA:
            # 白名单之外，但仍需跳过 20 字节基名以保持枚举准确。
            if p + 20 > body_end:
                raise VerificationError("REF_DELTA 基名截断", p)
            p += 20
        data_start = p
        content, data_end = _inflate_exact(pack, data_start)
        if data_end > body_end:
            raise VerificationError("对象压缩流侵入 20 字节包尾", data_start)
        objects.append(
            ObjectInfo(
                offset=obj_start,
                type_code=type_code,
                declared_size=size,
                data_start=data_start,
                data_end=data_end,
                data=content,
            )
        )
        pos = data_end

    if pos != body_end:
        # 全部声明对象耗尽后仍有残余正文字节（如压缩流后被塞入垃圾）。
        raise VerificationError(
            f"对象计数({count})耗尽后，压缩流与包尾之间仍有 "
            f"{body_end - pos} 个尾随字节",
            pos,
        )

    expected = pack[-TRAILER_LEN:]
    actual = hashlib.sha1(pack[:-TRAILER_LEN]).digest()
    if actual != expected:
        raise VerificationError(
            "包尾 SHA-1 与实际摘要不符（包体可能被篡改或截断）",
            body_end,
        )
    return count, objects


def _apply_delta(
    base: bytes, delta: bytes, delta_obj: ObjectInfo
) -> tuple[DeltaLayer, bytes]:
    """对单层 delta 应用指令并收集复制/插入证据。

    本函数抛出的 VerificationError.offset 均为"解压后差分数据内"的
    字节偏移；调用方负责换算为 pack 绝对偏移。
    """
    pos = 0
    base_size, pos = _read_varint_delta(delta, pos)
    result_size, pos = _read_varint_delta(delta, pos)

    if base_size != len(base):
        raise VerificationError(
            f"差分声明源长度 {base_size} 与实际基长度 {len(base)} 不一致",
            0,
        )
    if result_size > MAX_INFLATED_BYTES:
        raise VerificationError(
            f"差分声明目标长度 {result_size} 超过 {MAX_INFLATED_BYTES} 上限",
            0,
        )

    steps: list = []
    out = bytearray()
    while pos < len(delta):
        cmd_offset = pos
        op = delta[pos]
        pos += 1
        if op & 0x80:
            # 复制指令：随后最多 4 字节偏移 + 4 字节长度，各位对应。
            cp_off = 0
            cp_len = 0
            for i, bit in enumerate((0x01, 0x02, 0x04, 0x08)):
                if op & bit:
                    if pos >= len(delta):
                        raise VerificationError("复制指令的偏移字节截断",
                                                cmd_offset)
                    cp_off |= delta[pos] << (8 * i)
                    pos += 1
            for i, bit in enumerate((0x10, 0x20, 0x40)):
                if op & bit:
                    if pos >= len(delta):
                        raise VerificationError("复制指令的长度字节截断",
                                                cmd_offset)
                    cp_len |= delta[pos] << (8 * i)
                    pos += 1
            if cp_len == 0:
                cp_len = 0x10000
            end = cp_off + cp_len
            if end > len(base):
                raise VerificationError(
                    f"复制越界：源偏移 {cp_off}+长度 {cp_len}"
                    f" 超出基长度 {len(base)}",
                    cmd_offset,
                )
            chunk = bytes(base[cp_off:end])
            steps.append(
                CopyStep(
                    cmd_offset=cmd_offset,
                    src_offset=cp_off,
                    length=cp_len,
                    dst_offset=len(out),
                    bytes_hex=chunk.hex(),
                )
            )
            out.extend(chunk)
        elif op != 0:
            # 插入指令：op 即为字面字节数（1..127）。
            ins_len = op
            if pos + ins_len > len(delta):
                raise VerificationError(
                    f"插入指令声明 {ins_len} 字节但差分数据不足",
                    cmd_offset,
                )
            chunk = delta[pos:pos + ins_len]
            steps.append(
                InsertStep(
                    cmd_offset=cmd_offset,
                    length=ins_len,
                    dst_offset=len(out),
                    bytes_hex=chunk.hex(),
                )
            )
            out.extend(chunk)
            pos += ins_len
        else:
            # op == 0 是保留非法指令。
            raise VerificationError("遇到保留的零号差分指令", cmd_offset)

    if pos != len(delta):
        raise VerificationError("差分指令流存在尾随字节", pos)
    if len(out) != result_size:
        raise VerificationError(
            f"差分声明目标长度 {result_size} 与实际结果长度 {len(out)} 不一致",
            0,
        )
    layer = DeltaLayer(
        delta_offset=delta_obj.offset,
        base_offset=-1,  # 由调用方填写
        base_size_declared=base_size,
        result_size_declared=result_size,
        base_size_actual=len(base),
        result_size_actual=len(out),
        steps=steps,
    )
    return layer, bytes(out)


def _git_object_sha1(type_name: str, content: bytes) -> str:
    header = f"{type_name} {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def verify_pack_object(pack: bytes, target_offset: int) -> dict:
    """验证指定偏移处的对象并复原完整 OFS 基链。

    成功返回结构化结论；失败抛 VerificationError（带首个失败字节偏移）。
    """
    if not isinstance(pack, (bytes, bytearray)):
        raise VerificationError("pack 必须为字节串", 0)
    pack = bytes(pack)
    if len(pack) > MAX_PACK_BYTES:
        raise VerificationError(
            f"pack 超过 {MAX_PACK_BYTES} 字节（256 KiB）上限", 0
        )

    count, objects = parse_pack(pack)
    by_off = {o.offset: o for o in objects}

    if target_offset < 0 or target_offset >= len(pack) - TRAILER_LEN:
        raise VerificationError("目标偏移超出 pack 正文范围", target_offset)
    if target_offset not in by_off:
        raise VerificationError(
            "目标偏移未落在任一对象的起点", target_offset
        )

    target = by_off[target_offset]
    if target.type_code not in (OBJ_BLOB, OBJ_OFS_DELTA):
        raise VerificationError(
            f"目标对象类型 {TYPE_NAMES.get(target.type_code, target.type_code)}"
            " 不在接受范围（仅 blob、ofs_delta）",
            target.offset,
        )

    # 自目标向上沿 OFS 基链收集，再反转为 基->目标 的顺序。
    chain_down: list[ObjectInfo] = []
    cur = target
    seen: set[int] = set()
    while cur.type_code == OBJ_OFS_DELTA:
        neg, _ = _read_ofs_delta(pack, _read_size_header(pack, cur.offset)[2])
        base_off = cur.offset - neg
        if base_off < 0:
            raise VerificationError(
                f"对象 {cur.offset} 的 OFS 基偏移 {base_off} 为负",
                cur.data_start,
            )
        if base_off not in by_off:
            raise VerificationError(
                f"对象 {cur.offset} 声明的基偏移 {base_off} 不是对象起点",
                cur.data_start,
            )
        base_obj = by_off[base_off]
        if base_off >= cur.offset:
            raise VerificationError(
                f"对象 {cur.offset} 的基对象 {base_off} 不在此前位置",
                cur.data_start,
            )
        if base_obj.type_code not in (OBJ_BLOB, OBJ_OFS_DELTA):
            raise VerificationError(
                f"基对象 {base_off} 类型 "
                f"{TYPE_NAMES.get(base_obj.type_code, base_obj.type_code)}"
                " 不在接受范围",
                base_obj.offset,
            )
        if base_off in seen:
            raise VerificationError("OFS 基链出现循环", cur.data_start)
        seen.add(base_off)
        chain_down.append(cur)
        cur = base_obj

    # cur 现在是链根，必须是 blob。
    if cur.type_code != OBJ_BLOB:
        raise VerificationError(
            "基链根对象不是 blob", cur.offset
        )

    layers: list[DeltaLayer] = []
    content = cur.data
    if cur.declared_size != len(content):
        raise VerificationError(
            f"blob 头声明长度 {cur.declared_size} 与解压长度 {len(content)} 不一致",
            cur.offset,
        )

    for delta_obj in reversed(chain_down):
        _, _, after_hdr = _read_size_header(pack, delta_obj.offset)
        _, after_ofs = _read_ofs_delta(pack, after_hdr)
        if after_ofs != delta_obj.data_start:
            # 正常不会发生：枚举时已按相同规则定位；留作结构性防御。
            raise VerificationError(
                "delta 压缩流定位与枚举结果不一致", delta_obj.offset
            )
        if delta_obj.declared_size != len(delta_obj.data):
            raise VerificationError(
                f"delta 头声明长度 {delta_obj.declared_size} "
                f"与解压长度 {len(delta_obj.data)} 不一致",
                delta_obj.offset,
            )
        neg, _ = _read_ofs_delta(pack, after_hdr)
        base_off = delta_obj.offset - neg
        try:
            layer, content = _apply_delta(content, delta_obj.data, delta_obj)
        except VerificationError as exc:
            # 差分内偏移是相对"解压后差分数据"的，无法与压缩字节直接相加；
            # 主偏移报告 delta 对象的 pack 起点，细节偏移保留差分内位置。
            raise VerificationError(
                exc.message,
                delta_obj.offset,
                detail_offset=exc.offset,
            ) from exc
        layer.base_offset = base_off
        layer.result_sha1 = _git_object_sha1("blob", content)
        layers.append(layer)

    final_sha1 = _git_object_sha1("blob", content)
    chain_offsets = [cur.offset] + [d.offset for d in reversed(chain_down)]
    return {
        "ok": True,
        "object_count": count,
        "pack_size": len(pack),
        "pack_sha1": hashlib.sha1(pack[:-TRAILER_LEN]).hexdigest(),
        "target": {
            "offset": target.offset,
            "type": TYPE_NAMES[target.type_code],
            "inflated_length": len(content),
            "sha1": final_sha1,
        },
        "root_blob": {
            "offset": cur.offset,
            "declared_size": cur.declared_size,
            "actual_size": len(cur.data),
        },
        "base_chain_offsets": chain_offsets,
        "final_length": len(content),
        "final_sha1": final_sha1,
        "layers": [_layer_to_dict(l) for l in layers],
    }


def _layer_to_dict(layer: DeltaLayer) -> dict:
    return {
        "delta_offset": layer.delta_offset,
        "base_offset": layer.base_offset,
        "base_size_declared": layer.base_size_declared,
        "base_size_actual": layer.base_size_actual,
        "result_size_declared": layer.result_size_declared,
        "result_size_actual": layer.result_size_actual,
        "result_sha1": layer.result_sha1,
        "steps": [s.to_dict() for s in layer.steps],
    }
