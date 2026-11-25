"""合成密码层（标准库，测试夹具）。

真实系统里签封应当是非对称签名；离线复查只关心**状态机与证据**的正确性，
因此这里用 HMAC-SHA256 作为确定性、可离线重算的签名替身，并显式标注：

    * 所有密钥都是合成夹具（由标签派生），不具备任何机密性保证；
    * 验签器持有同一份“公开材料”（密钥登记表）即可独立重算；
    * 安全属性（不可伪造）不属于本复查目标，**状态/授权/证据**才是。

关键语义（对应题面）：

    签封须限定 受托人(trustee) + 资源(resource) + 授权代(generation)。
    同一根来源的两份见证不能合并成有效许可 —— 独立性以“根的谱系原点”判定，
    而非仅看 root_id 字符串。代理换根(proxy re-root)会生成新的 root_id，
    但其谱系原点不变；因此换根前后由同一谱系签出的两份见证仍然同源，不能凑成许可。
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

from .canonical import tagged_sha256


def fixture_key(label: str) -> bytes:
    """由标签派生的确定性合成密钥（仅测试用）。"""
    return sha256(b"dutyid-fixture-key\x00" + label.encode("utf-8")).digest()


def key_id_of(key: bytes) -> str:
    return sha256(b"dutyid-key-id\x00" + key).hexdigest()


def seal_mac(key: bytes, payload: Mapping) -> str:
    """对签封载荷计算 HMAC-SHA256（十六进制小写）。

    先对载荷做规范序列化并加域标签 "seal/v1"，再以控制器密钥作 HMAC。
    """
    msg = b"seal/v1\x00" + _canon(payload)
    return hmac.new(key, msg, sha256).hexdigest()


def verify_seal_mac(key: bytes, payload: Mapping, mac: str) -> bool:
    expected = seal_mac(key, payload)
    return hmac.compare_digest(expected, mac)


def _canon(obj) -> bytes:
    from .canonical import canonical_bytes

    return canonical_bytes(obj)


# --------------------------------------------------------------------------- #
# 根与密钥登记表
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Root:
    """一个“根来源”。parent 存在表示它源于某次代理换根。"""

    root_id: str
    parent: str | None = None


class KeyRegistry:
    """密钥登记表：key_id -> (controller_id, root_id, key_bytes)。

    视作 PKI/CA 夹具。验签器使用它把 key_id 解析回“谁、哪个根”，
    **不信任签封里自报的 root_id**。
    """

    def __init__(self) -> None:
        self._keys: dict[str, tuple[str, str, bytes]] = {}
        self._roots: dict[str, Root] = {}

    # -- 根 -- #
    def add_root(self, root_id: str, parent: str | None = None) -> Root:
        if parent is not None and parent not in self._roots:
            raise KeyError(f"父根不存在: {parent}")
        r = Root(root_id, parent)
        self._roots[root_id] = r
        return r

    def has_root(self, root_id: str) -> bool:
        return root_id in self._roots

    def root(self, root_id: str) -> Root:
        return self._roots[root_id]

    def lineage_origin(self, root_id: str) -> str:
        """沿 parent 链上溯到谱系原点。环/断裂都会报错。"""
        seen: set[str] = set()
        cur = root_id
        while True:
            if cur in seen:
                raise ValueError(f"根的谱系存在环: {root_id}")
            seen.add(cur)
            r = self._roots.get(cur)
            if r is None:
                raise KeyError(f"未知根: {cur}")
            if r.parent is None:
                return cur
            cur = r.parent

    # -- 控制人密钥 -- #
    def add_controller_key(
        self, controller_id: str, root_id: str, key_label: str
    ) -> str:
        """登记一把控制器密钥，返回 key_id。"""
        if root_id not in self._roots:
            raise KeyError(f"未知根: {root_id}")
        key = fixture_key(key_label)
        kid = key_id_of(key)
        if kid in self._keys:
            raise ValueError(f"key_id 冲突: {kid}")
        self._keys[kid] = (controller_id, root_id, key)
        return kid

    def resolve(self, key_id: str) -> tuple[str, str, bytes]:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"未登记的密钥: {key_id}") from exc

    def controller_of(self, key_id: str) -> str:
        return self.resolve(key_id)[0]

    def root_of(self, key_id: str) -> str:
        return self.resolve(key_id)[1]

    def origin_of(self, key_id: str) -> str:
        return self.lineage_origin(self.root_of(key_id))

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._keys


# --------------------------------------------------------------------------- #
# 签封载荷与计算
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SealPayload:
    """签封要绑定的全部字段（规范哈希的输入）。

    trustee/resource/generation 三者缺一不可 —— 这就是题面的“限定”。
    """

    permit_no: str
    generation: int
    trustee: str
    resource: str
    key_id: str
    nonce: str

    def to_dict(self) -> dict:
        return {
            "permit_no": self.permit_no,
            "generation": self.generation,
            "trustee": self.trustee,
            "resource": self.resource,
            "key_id": self.key_id,
            "nonce": self.nonce,
        }

    def digest(self) -> str:
        """签封载荷的规范摘要，用作最小证据里对该见证的引用。"""
        return tagged_sha256("seal-payload/v1", self.to_dict())
