"""数据模型：事件、签封、清单与不可变记录。

设计要点
--------
* 事件（Event）是追加式哈希链日志的单元，用于并发排序与恢复重放。
* 签封（Seal）与锁（Lock）既作为事件出现，也会各自**落盘为独立文件**；
  恢复必须能从这些独立文件 + 清单（Manifest）重建，而不是盲信日志。
* 授权判定被写成显式规则（RULES），验签器据此独立重算，不依赖引擎内部状态。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from .canonical import tagged_sha256
from .crypto import SealPayload

# --------------------------------------------------------------------------- #
# 枚举
# --------------------------------------------------------------------------- #


class EventType(str, enum.Enum):
    APPLY = "apply"
    LOCK = "lock"
    SEAL = "seal"
    ISSUE = "issue"
    REVOKE = "revoke"
    REROOT = "reroot"
    REJECTED = "rejected"   # 非法操作被拒（如旧代重投），只入日志不落实体


class PermitStatus(str, enum.Enum):
    PENDING = "pending"      # 已申请，未锁定
    LOCKED = "locked"        # 已锁定授权代，等签封
    VALID = "valid"          # 双根独立签封齐备，且未撤销
    REVOKED = "revoked"      # 已撤销
    REJECTED = "rejected"    # 因冲突/非法操作被拒


# 授权规则编号（验签器与证据都引用它们）
R_LOCK = "R1-lock-binds-generation"
R_INDEPENDENT_SEALS = "R2-two-independent-root-seals"
R_GENERATION_MATCH = "R3-seal-generation-matches-lock"
R_NOT_REVOKED = "R4-not-revoked"
R_MANIFEST_AGREES = "R5-manifest-agrees-with-artifacts"
R_UNIQUE_ACTIVE_GEN = "R6-unique-active-generation"


# --------------------------------------------------------------------------- #
# 事件
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Event:
    """哈希链日志中的一条事件。seq 从 0 开始单调递增。"""

    seq: int
    etype: str
    payload: dict
    prev_hash: str
    hash: str = ""

    def body(self) -> dict:
        return {
            "seq": self.seq,
            "etype": self.etype,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return tagged_sha256("event/v1", self.body())

    def sealed(self) -> "Event":
        return Event(self.seq, self.etype, self.payload, self.prev_hash, self.compute_hash())

    def to_dict(self) -> dict:
        return {**self.body(), "hash": self.hash}

    @staticmethod
    def from_dict(d: dict) -> "Event":
        return Event(int(d["seq"]), d["etype"], d["payload"], d["prev_hash"], d["hash"])


# --------------------------------------------------------------------------- #
# 签封与锁（落盘实体）
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Seal:
    """一个控制人的签封。mac 由控制器密钥对 SealPayload 计算。"""

    payload: SealPayload
    mac: str
    created_seq: int          # 写入日志时的事件序号（恢复时用于排序/撤销判定）

    @property
    def trustee(self) -> str:
        return self.payload.trustee

    @property
    def resource(self) -> str:
        return self.payload.resource

    @property
    def generation(self) -> int:
        return self.payload.generation

    @property
    def permit_no(self) -> str:
        return self.payload.permit_no

    def identity_tuple(self) -> tuple[str, str, str, int]:
        """签封绑定的四元组：受托人、资源、授权代、许可号。"""
        return (self.permit_no, self.trustee, self.resource, self.generation)

    def to_dict(self) -> dict:
        return {
            "payload": self.payload.to_dict(),
            "mac": self.mac,
            "created_seq": self.created_seq,
            "digest": self.payload.digest(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Seal":
        p = d["payload"]
        return Seal(
            SealPayload(
                permit_no=p["permit_no"],
                generation=int(p["generation"]),
                trustee=p["trustee"],
                resource=p["resource"],
                key_id=p["key_id"],
                nonce=p["nonce"],
            ),
            d["mac"],
            int(d["created_seq"]),
        )


@dataclass(frozen=True)
class Lock:
    """资源授权锁：把一个许可号钉在特定授权代、受托人、资源上。"""

    permit_no: str
    generation: int
    trustee: str
    resource: str
    created_seq: int

    def to_dict(self) -> dict:
        return {
            "permit_no": self.permit_no,
            "generation": self.generation,
            "trustee": self.trustee,
            "resource": self.resource,
            "created_seq": self.created_seq,
        }

    @staticmethod
    def from_dict(d: dict) -> "Lock":
        return Lock(
            d["permit_no"],
            int(d["generation"]),
            d["trustee"],
            d["resource"],
            int(d["created_seq"]),
        )


@dataclass(frozen=True)
class Revoke:
    """撤销：针对某个身份（trustee）在某个授权代上生效。"""

    target: str
    generation: int | None   # None 表示撤销该身份全部代
    created_seq: int

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "generation": self.generation,
            "created_seq": self.created_seq,
        }

    @staticmethod
    def from_dict(d: dict) -> "Revoke":
        g = d["generation"]
        return Revoke(d["target"], None if g is None else int(g), int(d["created_seq"]))


@dataclass(frozen=True)
class ReRoot:
    """代理换根：由 old_root 派生 new_root，谱系原点不变。"""

    old_root: str
    new_root: str
    created_seq: int

    def to_dict(self) -> dict:
        return {
            "old_root": self.old_root,
            "new_root": self.new_root,
            "created_seq": self.created_seq,
        }

    @staticmethod
    def from_dict(d: dict) -> "ReRoot":
        return ReRoot(d["old_root"], d["new_root"], int(d["created_seq"]))


# --------------------------------------------------------------------------- #
# 清单
# --------------------------------------------------------------------------- #


@dataclass
class ManifestEntry:
    """清单中的一条许可记录：作者声称的当前授权代与状态。"""

    permit_no: str
    active_generation: int
    status: str
    trustee: str
    resource: str
    seal_digests: list[str] = field(default_factory=list)  # 引用哪些签封

    def to_dict(self) -> dict:
        return {
            "permit_no": self.permit_no,
            "active_generation": self.active_generation,
            "status": self.status,
            "trustee": self.trustee,
            "resource": self.resource,
            "seal_digests": sorted(self.seal_digests),
        }

    @staticmethod
    def from_dict(d: dict) -> "ManifestEntry":
        return ManifestEntry(
            d["permit_no"],
            int(d["active_generation"]),
            d["status"],
            d["trustee"],
            d["resource"],
            list(d.get("seal_digests", [])),
        )


@dataclass
class Manifest:
    """清单：许可号 -> 条目，附加一个自摘要用于完整性自检。"""

    entries: dict[str, ManifestEntry] = field(default_factory=dict)

    def digest(self) -> str:
        return tagged_sha256(
            "manifest/v1",
            {k: v.to_dict() for k, v in sorted(self.entries.items())},
        )

    def to_dict(self) -> dict:
        return {
            "entries": {k: v.to_dict() for k, v in sorted(self.entries.items())},
            "digest": self.digest(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Manifest":
        m = Manifest({k: ManifestEntry.from_dict(v) for k, v in d["entries"].items()})
        return m


# --------------------------------------------------------------------------- #
# 事实引用（证据用）
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FactRef:
    """对一条落盘事实的引用。kind 与 digest 足以让验签器独立定位并重算。"""

    kind: str          # "lock" | "seal" | "revoke" | "manifest" | "reroot"
    digest: str        # 该事实规范摘要
    label: str         # 人类可读的短标签（不参与验证）

    def to_dict(self) -> dict:
        return {"kind": self.kind, "digest": self.digest, "label": self.label}


def fact_digest(kind: str, obj: Any) -> str:
    return tagged_sha256(f"fact/{kind}/v1", obj)
