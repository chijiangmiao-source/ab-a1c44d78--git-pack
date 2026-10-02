"""packv: 受限的 Git Pack v2 验证器。

仅支持 blob、OFS_DELTA 以及以它们为基的嵌套 OFS_DELTA。
所有偏移均为相对 pack 文件起始的绝对字节偏移。
"""

from .parser import (
    OBJ_BLOB,
    OBJ_OFS_DELTA,
    OBJ_COMMIT,
    OBJ_TREE,
    OBJ_TAG,
    OBJ_REF_DELTA,
    TYPE_NAMES,
    MAX_PACK_BYTES,
    VerificationError,
    verify_pack_object,
    parse_pack,
)

__all__ = [
    "OBJ_BLOB",
    "OBJ_OFS_DELTA",
    "OBJ_COMMIT",
    "OBJ_TREE",
    "OBJ_TAG",
    "OBJ_REF_DELTA",
    "TYPE_NAMES",
    "MAX_PACK_BYTES",
    "VerificationError",
    "verify_pack_object",
    "parse_pack",
]
