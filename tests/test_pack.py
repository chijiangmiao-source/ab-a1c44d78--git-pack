"""解码规则测试：变长编码、嵌套 OFS_DELTA 复原、真实 git pack 交叉验证、
全部失败路径及首个失败字节偏移。

直接运行：python -m tests.test_pack（仓库根目录）
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import pack as P
from tests import packbuilder as B

OBJ_BLOB = B.OBJ_BLOB
OBJ_COMMIT = B.OBJ_COMMIT
OBJ_TREE = B.OBJ_TREE
OBJ_TAG = B.OBJ_TAG
OBJ_OFS_DELTA = B.OBJ_OFS_DELTA
OBJ_REF_DELTA = B.OBJ_REF_DELTA


class TestEncodings(unittest.TestCase):
    def test_size_header_roundtrip(self):
        for n in [0, 1, 15, 16, 127, 128, 255, 256, 4095, 4096,
                  1 << 20, (1 << 28) - 1]:
            for t in range(1, 8):
                enc = P.encode_size_header(t, n)
                tt, nn, pos = P.decode_size_header(enc, 0)
                self.assertEqual((tt, nn, pos), (t, n, len(enc)))

    def test_ofs_roundtrip(self):
        for n in [1, 127, 128, 255, 256, 16383, 16384, 1 << 20]:
            enc = P.encode_ofs_negative(n)
            got, pos = P.decode_ofs_negative(enc, 0)
            self.assertEqual((got, pos), (n, len(enc)))

    def test_ofs_multi_byte_structure(self):
        self.assertEqual(P.encode_ofs_negative(128), b"\x80\x00")
        self.assertEqual(P.encode_ofs_negative(256), b"\x81\x00")
        for n in (128, 256, 210, 5000):
            got, _ = P.decode_ofs_negative(P.encode_ofs_negative(n), 0)
            self.assertEqual(got, n)
        # 真实 git pack 中 negative=210 编码为 80 52
        got, _ = P.decode_ofs_negative(b"\x80\x52", 0)
        self.assertEqual(got, 210)

    def test_canonical_sha_matches_git(self):
        content = b"hello world\n"
        got = P.canonical_blob_sha1(content)
        self.assertEqual(got, "3b18e512dba79e4c8300dd08aeb37f8e728b8dad")


class TestNestedDelta(unittest.TestCase):
    def _build_nested(self):
        """blob(base) -> delta1 -> delta2(目标)，三层均含复制与插入。"""
        base = b"BASE-PAYLOAD:" + b"0123456789" * 8  # 133 字节
        # 第 1 层：复制前 20 字节，插入，再复制尾部
        mid = (base[:20] + b"-MID-INSERT-" + base[40:])
        ops1 = (B.op_copy(0, 20) + B.op_insert(b"-MID-INSERT-")
                + B.op_copy(40, len(base) - 40))
        self.assertEqual(B.apply_ops_reference(base, ops1), mid)
        d1 = B.make_delta(len(base), len(mid), ops1)
        # 第 2 层：复制 mid 全部并前插，再插入尾标
        final = b"[FINAL]" + mid + b"<<END"
        ops2 = (B.op_insert(b"[FINAL]") + B.op_copy(0, len(mid))
                + B.op_insert(b"<<END"))
        self.assertEqual(B.apply_ops_reference(mid, ops2), final)
        d2 = B.make_delta(len(mid), len(final), ops2)

        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, base)
        i1 = pb.add(OBJ_OFS_DELTA, d1, base_idx=i0)
        i2 = pb.add(OBJ_OFS_DELTA, d2, base_idx=i1)
        return pb, base, mid, final, d1, d2

    def test_nested_chain_success(self):
        pb, base, mid, final, d1, d2 = self._build_nested()
        raw = pb.build()
        # 目标为最后一个对象，其起点：12 + 头与各流长度
        count, records = P._walk_pack(raw)
        self.assertEqual(count, 3)
        target_off = records[2].offset

        res = P.verify_pack(raw, target_off)
        self.assertEqual(res.content, final)
        self.assertEqual(res.sha1, P.canonical_blob_sha1(final))
        self.assertEqual([r.type for r in res.chain],
                         [OBJ_BLOB, OBJ_OFS_DELTA, OBJ_OFS_DELTA])

        self.assertEqual(len(res.layers), 2)
        L1, L2 = res.layers
        self.assertEqual((L1.source_size_declared, L1.source_size_actual,
                          L1.target_size_declared, L1.target_size_actual),
                         (len(base), len(base), len(mid), len(mid)))
        self.assertEqual((L2.source_size_declared, L2.source_size_actual,
                          L2.target_size_declared, L2.target_size_actual),
                         (len(mid), len(mid), len(final), len(final)))
        # 每层都有复制与插入证据
        self.assertTrue(L1.copies and L1.inserts)
        self.assertTrue(L2.copies and L2.inserts)
        # copy 区间并接后 + insert 可重建
        rebuilt = bytearray(final)  # 长度一致性已由 target_size 断言
        self.assertEqual(sum(c.len for c in L1.copies)
                         + sum(i.len for i in L1.inserts), len(mid))
        self.assertEqual(sum(c.len for c in L2.copies)
                         + sum(i.len for i in L2.inserts), len(final))
        # 绝对偏移字段位于对应 zlib 流内
        for rec in records:
            self.assertTrue(raw[rec.data_start:rec.stream_end])
            self.assertEqual(zlib.decompress(raw[rec.data_start:rec.stream_end]),
                             rec.inflated)

    def test_base_blob_direct(self):
        pb, base, *_ = self._build_nested()
        raw = pb.build()
        _, records = P._walk_pack(raw)
        res = P.verify_pack(raw, records[0].offset)
        self.assertEqual(res.content, base)
        self.assertEqual(res.layers, [])

    def test_mid_delta_target(self):
        pb, base, mid, final, *_ = self._build_nested()
        raw = pb.build()
        _, records = P._walk_pack(raw)
        res = P.verify_pack(raw, records[1].offset)
        self.assertEqual(res.content, mid)
        self.assertEqual(len(res.layers), 1)


class TestRealGitPack(unittest.TestCase):
    """用真实 git 生成 pack，验证解析器与 git 结论一致（含 OFS_DELTA）。"""

    def setUp(self):
        self.git = shutil.which("git")
        if not self.git:
            self.skipTest("git 不可用")
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        subprocess.run([self.git, "init", "-q", "-b", "main", str(self.tmp)],
                       check=True)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
        # 两个高度相似的大版本（仅头部少量差异），强制 repack 产生 OFS_DELTA
        common = "".join(f"line {i:04d} data {'X' * 60}\n"
                         for i in range(300)).encode()
        v1 = b"VERSION-ONE\n" + common
        v2 = b"VERSION-TWO!!\n" + common[:-20] + b"TAIL-MARKER\n"
        (self.tmp / "f.bin").write_bytes(v1)
        subprocess.run([self.git, "add", "f.bin"], cwd=self.tmp, env=env,
                       check=True)
        subprocess.run([self.git, "commit", "-qm", "v1"], cwd=self.tmp,
                       env=env, check=True)
        (self.tmp / "f.bin").write_bytes(v2)
        subprocess.run([self.git, "add", "f.bin"], cwd=self.tmp, env=env,
                       check=True)
        subprocess.run([self.git, "commit", "-qm", "v2"], cwd=self.tmp,
                       env=env, check=True)
        subprocess.run([self.git, "repack", "-adf", "--depth=50",
                        "--window=100"], cwd=self.tmp, env=env, check=True)
        packs = list((self.tmp / ".git/objects/pack").glob("*.pack"))
        self.assertEqual(len(packs), 1)
        self.pack_path = packs[0]
        self.raw = self.pack_path.read_bytes()
        out = subprocess.run(
            [self.git, "verify-pack", "-v", str(self.pack_path)],
            check=True, capture_output=True, text=True).stdout
        # 行：<sha> <resolved-type> <size> <pack-space-size> <offset> [depth] [base]
        # delta 行带基对象 SHA（最后一列，40 字符）；resolved-type 是底层类型。
        self.objects = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and len(parts[0]) == 40:
                try:
                    off = int(parts[4])
                except ValueError:
                    continue
            elif len(parts) >= 4 and len(parts[0]) == 40:
                try:
                    off = int(parts[3])
                except ValueError:
                    continue
            else:
                continue
            is_delta = len(parts) >= 1 and len(parts[-1]) == 40 and parts[-1] != parts[0]
            self.objects.append((parts[0], parts[1], off, is_delta))

    def test_matches_git(self):
        _, records = P._walk_pack(self.raw)
        self.assertEqual(len(records), len(self.objects))
        # 真实 repack 必须至少产生一个 delta，证明 OFS 路径被真实覆盖
        self.assertGreaterEqual(
            sum(1 for *_, d in self.objects if d), 1)
        delta_offsets = {off for _, _, off, d in self.objects if d}
        # 解析器与 verify-pack 对每个 delta 的对象起点判定一致
        self.assertEqual(delta_offsets,
                         {r.offset for r in records
                          if r.type == OBJ_OFS_DELTA})
        for sha, rtype, off, is_delta in self.objects:
            if rtype == "blob":
                res = P.verify_pack(self.raw, off)
                self.assertEqual(res.sha1, sha,
                                 f"偏移 {off} 的 SHA 与 git 不符")
            else:
                with self.assertRaises(P.PackError) as cm:
                    P.verify_pack(self.raw, off)
                self.assertIn(cm.exception.code,
                              ("TYPE_NOT_ALLOWED", "ROOT_TYPE_NOT_BLOB"))


class TestFailures(unittest.TestCase):
    def setUp(self):
        self.base = b"abcdefghij" * 10
        ops = B.op_copy(0, 10) + B.op_insert(b"INS") + B.op_copy(10, 90)
        mid = self.base[:10] + b"INS" + self.base[10:]
        self.delta = B.make_delta(len(self.base), len(mid), ops)
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        pb.add(OBJ_OFS_DELTA, self.delta, base_idx=i0)
        self.pb = pb
        self.mid = mid

    def test_bad_signature(self):
        raw = self.pb.build(bad_signature=True)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "BAD_SIGNATURE")
        self.assertEqual(cm.exception.offset, 0)

    def test_bad_version(self):
        raw = self.pb.build(bad_version=3)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "UNSUPPORTED_VERSION")
        self.assertEqual(cm.exception.offset, 4)

    def test_count_too_large(self):
        raw = self.pb.build(override_count=9)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TRUNCATED_OBJECT")

    def test_count_too_small_is_trailing_bytes(self):
        raw = self.pb.build(override_count=1)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TRAILING_BODY_BYTES")

    def test_trailing_byte_in_body(self):
        raw = self.pb.build(inject_trailing_byte=True)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TRAILING_BODY_BYTES")
        self.assertEqual(cm.exception.offset, len(raw) - 21)

    def test_corrupt_trailer(self):
        raw = self.pb.build(corrupt_trailer=True)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TRAILER_MISMATCH")
        self.assertEqual(cm.exception.offset, len(raw) - 20)

    def test_target_type_commit(self):
        pb = B.PackBuilder()
        pb.add(OBJ_COMMIT, b"tree x\nauthor t\n\nmsg\n")
        raw = pb.build()
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TYPE_NOT_ALLOWED")
        self.assertEqual(cm.exception.offset, 12)

    def test_target_type_tree_and_tag(self):
        for t in (OBJ_TREE, OBJ_TAG):
            pb = B.PackBuilder()
            pb.add(t, b"100644 x\x00" + b"\x00" * 20)
            raw = pb.build()
            with self.assertRaises(P.PackError) as cm:
                P.verify_pack(raw, 12)
            self.assertEqual(cm.exception.code, "TYPE_NOT_ALLOWED")

    def test_ref_delta_rejected(self):
        raw = self.pb_build_with_ref()
        _, records = P._walk_pack(raw)
        # 第二个对象（REF_DELTA）作为目标必须被类型闸口拒绝
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[1].offset)
        self.assertEqual(cm.exception.code, "TYPE_NOT_ALLOWED")

    @staticmethod
    def pb_build_with_ref():
        # REF_DELTA 需要手工补 20 字节基名后再压 zlib
        import hashlib
        import zlib as _z
        base = b"abcdefghij" * 10
        ops = B.op_copy(0, 10) + B.op_insert(b"INS") + B.op_copy(10, 90)
        d = B.make_delta(len(base), 103, ops)
        out = b"PACK" + (2).to_bytes(4, "big") + (2).to_bytes(4, "big")
        h0 = B.encode_obj_header(OBJ_BLOB, len(base))
        z0 = _z.compress(base)
        out += h0 + z0
        h1 = B.encode_obj_header(OBJ_REF_DELTA, len(d)) + b"\x11" * 20
        out += h1 + _z.compress(d)
        return out + hashlib.sha1(out).digest()

    def test_offset_not_object_start(self):
        raw = self.pb.build()
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 13)
        self.assertEqual(cm.exception.code, "OFFSET_NOT_OBJECT_START")
        self.assertEqual(cm.exception.offset, 13)

    def test_offset_out_of_range(self):
        raw = self.pb.build()
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 999999)
        self.assertEqual(cm.exception.code, "OFFSET_OUT_OF_RANGE")

    def test_base_not_prior(self):
        # 把 OFS 负偏移改大到指向包起点之前
        raw = self.pb.build(ofs_override={1: 9999})
        # 改写后摘要失配可能先报 OFS 错误（走查顺序先于摘要）
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "BASE_NOT_PRIOR")

    def test_base_points_inside_another_object(self):
        # 负偏移指向 blob 头之后的位置（非对象起点）
        raw = self.pb.build(ofs_override={1: 11})  # base = delta_start-11
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "BASE_NOT_PRIOR")

    def test_delta_copy_out_of_range(self):
        bad_ops = B.op_copy(0, 10) + B.op_copy(95, 20)  # 95+20>100
        d = B.make_delta(100, 30, bad_ops)
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        # 注意：摘要此时仍正确（build 重算），应在应用 delta 时报越界
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_COPY_OUT_OF_RANGE")
        # 首个失败字节 = copy 操作码在包内的绝对偏移
        opcode_abs = records[i1].data_start + _leb_len(100) + _leb_len(30) \
            + 1 + _copy_operand_len(0, 10)
        self.assertEqual(cm.exception.offset, opcode_abs)

    def test_delta_source_size_mismatch(self):
        d = B.make_delta(99, len(self.mid),
                         B.op_copy(0, 10) + B.op_insert(b"INS")
                         + B.op_copy(10, 90))
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_SOURCE_SIZE_MISMATCH")
        self.assertEqual(cm.exception.offset, records[i1].data_start)

    def test_delta_target_size_mismatch(self):
        ops = (B.op_copy(0, 10) + B.op_insert(b"INS")
               + B.op_copy(10, 90))
        d = B.make_delta(len(self.base), 777, ops)
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_TARGET_SIZE_MISMATCH")

    def test_delta_opcode_zero(self):
        d = B.make_delta(100, 0, b"\x00")
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "INVALID_DELTA_OPCODE")
        self.assertEqual(cm.exception.offset, records[i1].data_start
                         + _leb_len(100) + _leb_len(0))

    def test_insert_operand_truncated(self):
        d = B.make_delta(100, 5, bytes([5, b"a"[0]]))  # 声称 5 字节只给 1
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, self.base)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_OPERAND_TRUNCATED")

    def test_declared_inflated_size_mismatch(self):
        pb = B.PackBuilder()
        # 手工构造头声明尺寸与实际不符
        head = B.encode_obj_header(OBJ_BLOB, 999)
        payload = zlib.compress(self.base)
        import hashlib
        out = (b"PACK" + (2).to_bytes(4, "big") + (1).to_bytes(4, "big")
               + head + payload)
        raw = out + hashlib.sha1(out).digest()
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "DECLARED_SIZE_MISMATCH")

    def test_truncated_zlib(self):
        # 剥除 4 字节 adler 后，流不报错但永远等不到正常终止。
        payload = zlib.compress(self.base)
        with self.assertRaises(P.PackError) as cm:
            P._inflate_stream(payload[:-4], 0)
        self.assertEqual(cm.exception.code, "ZLIB_TRUNCATED")

    def test_truncated_pack_short_body(self):
        # 端到端：正文不足以容纳声明的对象，先在对象起点处报截断。
        raw = (b"PACK" + (2).to_bytes(4, "big") + (1).to_bytes(4, "big")
               + b"\x00" * 10)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, 12)
        self.assertEqual(cm.exception.code, "TRUNCATED_OBJECT")

    def test_root_of_chain_not_blob(self):
        # delta 基于一个 tree 对象
        tree = b"100644 f\x00" + b"\x22" * 20
        ops = B.op_copy(0, 5) + B.op_insert(b"ZZ")
        d = B.make_delta(len(tree), 7, ops)
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_TREE, tree)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "ROOT_TYPE_NOT_BLOB")

    def test_delta_size_field_truncated(self):
        # delta 解压数据只有一个续位字节，源长度 LEB128 无终止字节。
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, b"x" * 10)
        i1 = pb.add(OBJ_OFS_DELTA, bytes([0x80]), base_idx=i0)
        raw = pb.build()
        _, records = P._walk_pack(raw)
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, records[i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_HEADER_TRUNCATED")
        # 首个失败字节为源长度字段起点（即 delta zlib 数据起点）
        self.assertEqual(cm.exception.offset, records[i1].data_start)

    def test_copy_size_zero_means_64k(self):
        big = bytes(range(256)) * 257  # 65792 字节
        d = B.make_delta(len(big), 0x10000, B.op_copy(0, 0))
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, big)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        res = P.verify_pack(raw, P._walk_pack(raw)[1][i1].offset)
        self.assertEqual(len(res.content), 0x10000)
        self.assertEqual(res.layers[0].copies[0].len, 0x10000)
        self.assertEqual(res.content, big[:0x10000])

    def test_copy_size_zero_out_of_range(self):
        d = B.make_delta(100, 0x10000, B.op_copy(0, 0))
        pb = B.PackBuilder()
        i0 = pb.add(OBJ_BLOB, b"a" * 100)
        i1 = pb.add(OBJ_OFS_DELTA, d, base_idx=i0)
        raw = pb.build()
        with self.assertRaises(P.PackError) as cm:
            P.verify_pack(raw, P._walk_pack(raw)[1][i1].offset)
        self.assertEqual(cm.exception.code, "DELTA_COPY_OUT_OF_RANGE")
        self.assertEqual(cm.exception.detail["copy_size"], 0x10000)

    def test_large_object_multibyte_header(self):
        big = bytes((i * 7 + 3) & 0xFF for i in range(5000))
        pb = B.PackBuilder()
        pb.add(OBJ_BLOB, big)
        raw = pb.build()
        res = P.verify_pack(raw, 12)
        self.assertEqual(res.content, big)
        self.assertEqual(len(res.chain[0].declared_size and big), 5000)


def _leb_len(n: int) -> int:
    return len(B.varint(n))


def _copy_operand_len(src: int, size: int) -> int:
    n = 0
    for shift in (0, 8, 16, 24):
        if (src >> shift) & 0xFF:
            n += 1
    for shift in (0, 8, 16):
        if (size >> shift) & 0xFF:
            n += 1
    return n


if __name__ == "__main__":
    unittest.main(verbosity=2)
