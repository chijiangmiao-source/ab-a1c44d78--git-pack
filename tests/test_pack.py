"""packv 解码规则测试。

不依赖 pytest，直接 `python3 -m unittest` 即可运行。
测试数据通过两种方式构造：
  1. 手工按字节拼装，精确制造畸形结构（尾随字节、越界复制等）；
  2. 调用本机 git index-pack 生成真实 pack（若 git 可用）做交叉校验。
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

from packv import (
    MAX_PACK_BYTES,
    OBJ_BLOB,
    OBJ_OFS_DELTA,
    VerificationError,
    parse_pack,
    verify_pack_object,
)
from tests.fixtures import (
    build_nested_pack,
    copy_op,
    enc_obj_header,
    enc_ofs,
    finish_pack,
    insert_op,
    make_delta,
)


# ---------- 测试专用构造工具 ----------

def zobj(type_code: int, content: bytes, prefix: bytes = b"") -> bytes:
    return bytes(enc_obj_header(type_code, len(content))) + prefix + zlib.compress(content)


def build_simple_pack() -> tuple[bytes, int, int]:
    """blob + OFS_DELTA，返回 (pack, blob_off, delta_off)。"""
    base = b"hello world, base content!!"
    # 复制前 6 字节 "hello "，插入 "earth"，再从逗号处续复制。
    target = b"hello " + b"earth" + base[11:]
    ops = copy_op(0, 6) + insert_op(b"earth") + copy_op(11, len(base) - 11)
    delta = make_delta(len(base), ops, len(target))
    blob_part = zobj(OBJ_BLOB, base)
    blob_off = 12
    neg = len(blob_part)
    delta_part = bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta))) + enc_ofs(neg) + zlib.compress(delta)
    delta_off = 12 + len(blob_part)
    pack = finish_pack(blob_part + delta_part, 2)
    return pack, blob_off, delta_off


# ---------- 测试 ----------

class HeaderTests(unittest.TestCase):
    def test_good_pack_blob(self):
        base = b"abcdef" * 10
        body = zobj(OBJ_BLOB, base)
        pack = finish_pack(body, 1)
        count, objs = parse_pack(pack)
        self.assertEqual(count, 1)
        self.assertEqual(objs[0].offset, 12)
        self.assertEqual(objs[0].declared_size, len(base))
        self.assertEqual(objs[0].data, base)

    def test_bad_signature(self):
        pack = b"XACK" + b"\x00" * 28
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertEqual(cm.exception.offset, 0)

    def test_bad_version(self):
        body = b""
        pack = b"PACK" + struct.pack(">II", 3, 0)
        pack += hashlib.sha1(pack).digest()
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertEqual(cm.exception.offset, 4)

    def test_count_mismatch_residual(self):
        base = b"x"
        body = zobj(OBJ_BLOB, base)
        pack = finish_pack(body, 0)  # 计数 0 但实际有对象 → 残余字节
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertEqual(cm.exception.offset, 12)

    def test_count_too_large(self):
        pack = finish_pack(b"", 1)
        with self.assertRaises(VerificationError):
            parse_pack(pack)

    def test_bad_trailer_sha_reports_body_end(self):
        base = b"abcdef"
        pack = finish_pack(zobj(OBJ_BLOB, base), 1, bad_sha=True)
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertEqual(cm.exception.offset, len(pack) - 20)

    def test_trailing_bytes_after_zlib(self):
        # 最后一个对象的 zlib 流结束后、包尾之前被塞入垃圾字节。
        base = b"abc"
        hdr = bytes(enc_obj_header(OBJ_BLOB, len(base)))
        z = zlib.compress(base)
        junk = b"\x99\x88\x77"
        body = hdr + z + junk
        pack = finish_pack(body, 1)
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertIn("尾随字节", cm.exception.message)
        # 失败偏移恰为 zlib 流结束位置（即首个垃圾字节）。
        self.assertEqual(cm.exception.offset, 12 + len(hdr) + len(z))

    def test_garbage_between_objects(self):
        # 两个对象之间塞入垃圾：枚举到下一个对象头时在垃圾字节处失败。
        base = b"abc"
        hdr = bytes(enc_obj_header(OBJ_BLOB, len(base)))
        z = zlib.compress(base)
        junk_pos = 12 + len(hdr) + len(z)
        body = hdr + z + b"\x80" + zobj(OBJ_BLOB, b"d")
        pack = finish_pack(body, 2)
        with self.assertRaises(VerificationError) as cm:
            parse_pack(pack)
        self.assertEqual(cm.exception.offset, junk_pos)


class OfsEncodingTests(unittest.TestCase):
    def test_ofs_small(self):
        self.assertEqual(enc_ofs(1), b"\x01")
        self.assertEqual(enc_ofs(127), b"\x7f")

    def test_ofs_multibyte(self):
        # 128 -> 首字节 0x80 | 0, 次字节 0x00? 按 Git 规则：
        self.assertEqual(enc_ofs(128), b"\x80\x00")
        # 用解析器交叉验证 enc_ofs。
        from packv.parser import _read_ofs_delta
        for n in (1, 2, 127, 128, 129, 255, 256, 16383, 16384, 65535, 1 << 20):
            buf = enc_ofs(n)
            got, used = _read_ofs_delta(buf, 0)
            self.assertEqual(got, n, n)
            self.assertEqual(used, len(buf))


class DeltaChainTests(unittest.TestCase):
    def test_simple_ofs_delta(self):
        pack, blob_off, delta_off = build_simple_pack()
        target = b"hello earth, base content!!"
        r = verify_pack_object(pack, delta_off)
        self.assertTrue(r["ok"])
        self.assertEqual(r["target"]["type"], "ofs_delta")
        self.assertEqual(r["final_length"], len(target))
        self.assertEqual(r["base_chain_offsets"], [blob_off, delta_off])
        want = hashlib.sha1(
            f"blob {len(target)}\0".encode() + target).hexdigest()
        self.assertEqual(r["final_sha1"], want)
        # 每层证据包含复制与插入。
        kinds = [s["kind"] for s in r["layers"][0]["steps"]]
        self.assertEqual(kinds, ["copy", "insert", "copy"])

    def test_target_blob_directly(self):
        pack, blob_off, _ = build_simple_pack()
        r = verify_pack_object(pack, blob_off)
        self.assertTrue(r["ok"])
        self.assertEqual(r["target"]["type"], "blob")
        self.assertEqual(r["layers"], [])

    def test_nested_ofs_delta(self):
        fx = build_nested_pack()
        pack = fx["pack"]
        blob_off, off1, off2 = fx["blob_off"], fx["delta1_off"], fx["delta2_off"]
        v1, v2 = fx["v1"], fx["v2"]

        r = verify_pack_object(pack, off2)
        self.assertTrue(r["ok"])
        self.assertEqual(r["base_chain_offsets"], [blob_off, off1, off2])
        self.assertEqual(r["final_length"], len(v2))
        self.assertEqual(
            r["final_sha1"],
            hashlib.sha1(f"blob {len(v2)}\0".encode() + v2).hexdigest(),
        )
        # 两层各自的 SHA-1
        self.assertEqual(
            r["layers"][0]["result_sha1"],
            hashlib.sha1(b"blob 48\0" + v1).hexdigest(),
        )

    def test_copy_out_of_bounds(self):
        base = b"0123456789"
        ops = copy_op(8, 10)  # 8+10 > 10
        delta = make_delta(len(base), ops, 18)
        body = zobj(OBJ_BLOB, base)
        hdr = bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
        dpart = hdr + enc_ofs(len(body)) + zlib.compress(delta)
        pack = finish_pack(body + dpart, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(body))
        self.assertIn("复制越界", cm.exception.message)

    def test_declared_base_size_mismatch(self):
        base = b"0123456789"
        ops = copy_op(0, 5) + insert_op(b"xxxxx")
        delta = make_delta(9, ops, 10)  # 声明源 9，实际 10
        body = zobj(OBJ_BLOB, base)
        dpart = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
                 + enc_ofs(len(body)) + zlib.compress(delta))
        pack = finish_pack(body + dpart, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(body))
        self.assertIn("源长度", cm.exception.message)

    def test_declared_result_size_mismatch(self):
        base = b"0123456789"
        ops = copy_op(0, 5) + insert_op(b"xxxxx")
        result = base[:5] + b"xxxxx"
        delta = make_delta(len(base), ops, len(result) + 1)  # 谎报目标长度
        body = zobj(OBJ_BLOB, base)
        dpart = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
                 + enc_ofs(len(body)) + zlib.compress(delta))
        pack = finish_pack(body + dpart, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(body))
        self.assertIn("目标长度", cm.exception.message)

    def test_reserved_zero_opcode(self):
        base = b"0123456789"
        delta = make_delta(len(base), b"\x00", 0)
        body = zobj(OBJ_BLOB, base)
        dpart = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
                 + enc_ofs(len(body)) + zlib.compress(delta))
        pack = finish_pack(body + dpart, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(body))
        self.assertIn("零号", cm.exception.message)


class TargetValidationTests(unittest.TestCase):
    def setUp(self):
        self.pack, self.blob_off, self.delta_off = build_simple_pack()

    def test_offset_mid_object(self):
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(self.pack, self.blob_off + 1)
        self.assertEqual(cm.exception.offset, self.blob_off + 1)
        self.assertIn("未落在", cm.exception.message)

    def test_offset_inside_trailer(self):
        with self.assertRaises(VerificationError):
            verify_pack_object(self.pack, len(self.pack) - 1)

    def test_unsupported_target_type(self):
        # 手工构造一个 commit 对象（类型 1）。
        content = b"tree 0000000000000000000000000000000000000000\n\nmsg\n"
        pack = finish_pack(zobj(1, content), 1)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertIn("commit", cm.exception.message)
        self.assertEqual(cm.exception.offset, 12)

    def test_forward_base_rejected(self):
        # delta 在前，声称的基偏移在它之后 → 拒绝。
        base = b"abc"
        ops = copy_op(0, 3)
        delta = make_delta(3, ops, 3)
        zdelta = zlib.compress(delta)
        hdr = bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
        # 负偏移编码为 1（指向自身）或者构造指向"之后"：不可能，因为
        # offset - negative 只会更早。改为基偏移指向非对象起点。
        dpart = hdr + enc_ofs(5) + zdelta  # 12+5 一般不是对象起点
        body = dpart + zobj(OBJ_BLOB, base)
        pack = finish_pack(body, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertTrue(
            "不是对象起点" in cm.exception.message
            or "不在此前位置" in cm.exception.message
        )

    def test_size_limit(self):
        with self.assertRaises(VerificationError):
            verify_pack_object(b"\x00" * (MAX_PACK_BYTES + 1), 0)


class WhitelistTests(unittest.TestCase):
    def test_ref_delta_target_rejected(self):
        # REF_DELTA（类型 7）对象：20 字节基名 + zlib 数据。
        content = b"whatever"
        body = (bytes(enc_obj_header(7, len(content)))
                + b"\x00" * 20 + zlib.compress(content))
        pack = finish_pack(body, 1)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertIn("ref_delta", cm.exception.message)

    def test_tree_base_rejected(self):
        # OFS_DELTA 以 tree（类型 2）为基 —— 拒绝。
        tree_content = b"100644 a\x00" + b"\x00" * 20
        ops = copy_op(0, 1)
        # 差分声明源长度与 tree 等长，使拒绝发生在类型检查阶段。
        delta = make_delta(len(tree_content), ops, len(tree_content))
        p_tree = zobj(2, tree_content)
        p_delta = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
                   + enc_ofs(len(p_tree)) + zlib.compress(delta))
        pack = finish_pack(p_tree + p_delta, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(p_tree))
        self.assertIn("tree", cm.exception.message)

    def test_self_or_inner_offset_base_rejected(self):
        # 负偏移 1：基偏移落在 delta 对象内部，不是对象起点。
        base = b"abc"
        delta = make_delta(3, copy_op(0, 3), 3)
        hdr = bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
        dpart = hdr + enc_ofs(1) + zlib.compress(delta)
        pack = finish_pack(dpart + zobj(OBJ_BLOB, base), 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertIn("不是对象起点", cm.exception.message)

    def test_zero_negative_offset_self_reference_rejected(self):
        # 直接塞入编码 0x00（负偏移为 0，基指向自身）。
        base = b"abc"
        delta = make_delta(3, copy_op(0, 3), 3)
        hdr = bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta)))
        dpart = hdr + b"\x00" + zlib.compress(delta)
        pack = finish_pack(dpart + zobj(OBJ_BLOB, base), 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertIn("此前位置", cm.exception.message)

    def test_blob_header_size_mismatch_rejected(self):
        # 对象头谎报长度（与 zlib 实际解压长度不符）。
        real = b"abcdefghij"
        hdr = bytes(enc_obj_header(OBJ_BLOB, len(real) + 5))
        pack = finish_pack(hdr + zlib.compress(real), 1)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12)
        self.assertIn("声明长度", cm.exception.message)

    def test_delta_header_size_mismatch_rejected(self):
        base = b"0123456789"
        delta = make_delta(len(base), copy_op(0, 10), 10)
        p_base = zobj(OBJ_BLOB, base)
        # 头部谎报 delta 解压长度 +3。
        p_delta = (bytes(enc_obj_header(OBJ_OFS_DELTA, len(delta) + 3))
                   + enc_ofs(len(p_base)) + zlib.compress(delta))
        pack = finish_pack(p_base + p_delta, 2)
        with self.assertRaises(VerificationError) as cm:
            verify_pack_object(pack, 12 + len(p_base))
        self.assertIn("delta 头声明长度", cm.exception.message)


class CorruptZlibTests(unittest.TestCase):
    def test_broken_zlib(self):
        hdr = bytes(enc_obj_header(OBJ_BLOB, 10))
        body = hdr + b"\x78\x9c\xff\xff\xff\xff"
        with self.assertRaises(VerificationError):
            parse_pack(finish_pack(body, 1))

    def test_inflate_spanning_chunks_keeps_exact_end(self):
        # 不可压缩（高熵）数据，压缩后 > 64 KiB，强制解压分多块消费；
        # 若流终点偏移算错，残余字节检查或包尾 SHA-1 检查就会失败。
        rng = random.Random(20261002)
        blob = bytes(rng.getrandbits(8) for _ in range(100 * 1024))
        raw = zlib.compress(blob, 6)
        self.assertGreater(len(raw), 64 * 1024)
        hdr = bytes(enc_obj_header(OBJ_BLOB, len(blob)))
        pack = finish_pack(hdr + raw, 1)
        count, objs = parse_pack(pack)
        self.assertEqual(count, 1)
        self.assertEqual(objs[0].data, blob)
        self.assertEqual(objs[0].data_end, 12 + len(hdr) + len(raw))
        # 同一对象再走完整验证路径
        r = verify_pack_object(pack, 12)
        self.assertTrue(r["ok"])
        self.assertEqual(r["final_length"], len(blob))


@unittest.skipUnless(shutil.which("git"), "需要 git CLI 做交叉校验")
class RealGitPackTests(unittest.TestCase):
    """用真实 git 生成含 OFS_DELTA 的薄/厚 pack，与 git cat-file 结果比对。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        subprocess.run(["git", "init", "-q", self.tmp], check=True)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")

        def add(blob: bytes) -> str:
            p = os.path.join(self.tmp, "f.bin")
            with open(p, "wb") as fh:
                fh.write(blob)
            subprocess.run(["git", "add", "f.bin"], cwd=self.tmp,
                           check=True, env=env)
            subprocess.run(["git", "commit", "-qm", "c"], cwd=self.tmp,
                           check=True, env=env)
            out = subprocess.run(
                ["git", "rev-parse", "HEAD:f.bin"], cwd=self.tmp,
                capture_output=True, text=True, check=True, env=env)
            return out.stdout.strip()

        # 两个相似大 blob，第二次提交 git 通常以 delta 存储。
        b1 = (b"prefix-" + bytes(range(256)) * 8 + b"-suffix")
        b2 = (b"prefix-" + bytes(range(256)) * 8 + b"-suffix-CHANGED-TAIL-PADDING")
        self.sha1 = add(b1)
        self.sha2 = add(b2)
        self.versions = {self.sha1: b1, self.sha2: b2}

        # 用 rev-list 生成 pack。
        out = subprocess.run(
            ["git", "rev-list", "--objects", "HEAD"], cwd=self.tmp,
            capture_output=True, check=True).stdout
        objs = [ln.split()[0] for ln in out.decode().splitlines()]
        pack_out = subprocess.run(
            ["git", "pack-objects", "--delta-base-offset", "--stdout"],
            cwd=self.tmp,
            input=("\n".join(objs) + "\n").encode(),
            capture_output=True, check=True).stdout
        self.pack = pack_out

    def test_parse_real_pack_and_compare(self):
        count, objs = parse_pack(self.pack)
        self.assertGreaterEqual(count, 3)
        # 枚举的对象类型都合法。
        for o in objs:
            self.assertIn(o.type_code, (1, 2, 3, 4, 6, 7))
        # 找一个 OFS_DELTA 目标，要求其最终 sha1 与 b2 匹配；若该 pack
        # 未做 delta（全是 base），则至少校验 blob 直取。
        delta_objs = [o for o in objs if o.type_code == OBJ_OFS_DELTA]
        if not delta_objs:
            self.skipTest("git 未在本包生成 OFS_DELTA")
        # git 自行决定哪一版作为 delta 基（可能新对象在前），因此
        # 任一 delta 目标只要复原出 b1 或 b2 即通过。
        matched = 0
        for d in delta_objs:
            try:
                r = verify_pack_object(self.pack, d.offset)
            except VerificationError:
                continue
            if r["final_sha1"] in self.versions:
                content = self.versions[r["final_sha1"]]
                self.assertEqual(r["final_length"], len(content))
                want_hex = hashlib.sha1(
                    f"blob {len(content)}\0".encode() + content).hexdigest()
                self.assertEqual(want_hex, r["final_sha1"])
                matched += 1
        self.assertGreaterEqual(matched, 1, "未在真实 git pack 中复原出 blob delta")


if __name__ == "__main__":
    unittest.main(verbosity=2)
