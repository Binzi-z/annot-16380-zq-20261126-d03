"""规范序列化与哈希。

整批离线复查要求“独立可验证”，因此凡是会被签封或哈希保护的结构，
都必须用唯一确定的字节表示。这里用 JSON：键排序、无多余空白、
UTF-8、拒绝 NaN/Infinity、整数只允许十进制且不出现浮点。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    """输入无法被规范编码。"""


def canonical_bytes(obj: Any) -> bytes:
    """返回对象唯一的规范字节串。

    规则：
      * JSON，键按码点排序；
      * 分隔符为 (",", ":")，无多余空白；
      * ensure_ascii=False，使用 UTF-8；
      * allow_nan=False，禁止 NaN / Infinity；
      * 只接受 JSON 原生类型（dict/list/str/int/bool/None），
        float 一律拒绝，避免 0.0 与 -0.0 等歧义。
    """
    _reject_non_canonical(obj)
    try:
        text = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:  # pragma: no cover - 防御
        raise CanonicalError(f"无法规范编码: {exc}") from exc
    return text.encode("utf-8")


def _reject_non_canonical(obj: Any) -> None:
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, bool):
            continue
        if isinstance(cur, float):
            raise CanonicalError("规范结构禁止浮点（请改用整数或有理数表示）")
        if isinstance(cur, (str, int)) or cur is None:
            continue
        if isinstance(cur, dict):
            for k, v in cur.items():
                if not isinstance(k, str):
                    raise CanonicalError("字典键必须是字符串")
                stack.append(v)
            continue
        if isinstance(cur, (list, tuple)):
            stack.extend(cur)
            continue
        raise CanonicalError(f"不支持的规范类型: {type(cur).__name__}")


def canonical_sha256(obj: Any) -> str:
    """对象规范字节串的 SHA-256 十六进制小写摘要。"""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tagged_sha256(tag: str, obj: Any) -> str:
    """带域分隔标签的 SHA-256，避免不同用途的结构哈希撞在同一空间。"""
    h = hashlib.sha256()
    h.update(tag.encode("utf-8"))
    h.update(b"\x00")
    h.update(canonical_bytes(obj))
    return h.hexdigest()
