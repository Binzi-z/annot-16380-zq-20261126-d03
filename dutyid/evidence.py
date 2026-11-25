"""最小冲突证据：以“极小的落盘事实子集”表达冲突，而不是宽松的子句集。

为什么用事实子集
----------------
“最小冲突”在约束语境里指：一个**极小的事实子集**，它本身即违反安全规则，
且删去其中任意一条事实后就不再违反（可满足/仅不完整）。这正是独立复核
需要的性质，也便于离线逐条比对：

    revoked        {锁 L, 撤销 R}            —— 删任一条都不再构成“已撤销”
    same_origin    {锁 L, 签封 S1, S2}        —— 删任一签封就只剩 1 份，不构成冲突
                   （“same_origin” 涵盖两种不独立：同一根谱系原点，或同一控制人；
                     判定统一交给 rules.independent_pair）
    regression     {较晚低代锁 L_low, 较早高代锁 L_high} —— 删任一条不再是回退

证据自包含：携带每条事实的**原始内容**与其规范摘要。独立验签器据此：
  1) 重算每条事实的摘要，确认与声称一致；
  2) 重放 violate() 确认子集确实违规；
  3) 逐条删除后重放，确认不再违规 —— 从而证明**极小性**。
证据对象自身再算一个规范摘要，便于离线交叉比对。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import tagged_sha256
from .crypto import KeyRegistry
from .model import Lock, Revoke, Seal, fact_digest
from .rules import seal_mac_ok

K_REVOKED = "revoked"
K_SAME_ORIGIN = "same_origin"
K_REGRESSION = "generation_regression"


# --------------------------------------------------------------------------- #
# 事实记录（自包含）
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FactRecord:
    kind: str          # "lock" | "seal" | "revoke"
    digest: str
    body: dict         # {"lock": {...}} / {"seal": {...}} / {"revoke": {...}}
    label: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "digest": self.digest, "body": self.body, "label": self.label}

    @staticmethod
    def from_dict(d: dict) -> "FactRecord":
        return FactRecord(d["kind"], d["digest"], d["body"], d.get("label", ""))


def lock_fact(lock: Lock, label: str = "") -> FactRecord:
    body = {"lock": lock.to_dict()}
    d = fact_digest("lock", lock.to_dict())
    return FactRecord("lock", d, body, label or f"lock {lock.permit_no} g{lock.generation}")


def seal_fact(seal: Seal, label: str = "") -> FactRecord:
    obj = seal.payload.to_dict() | {"mac": seal.mac}
    body = {"seal": seal.to_dict()}
    d = fact_digest("seal", obj)
    return FactRecord(
        "seal", d, body,
        label or f"seal {seal.permit_no} g{seal.generation} {seal.payload.key_id[:8]}",
    )


def revoke_fact(rev: Revoke, label: str = "") -> FactRecord:
    body = {"revoke": rev.to_dict()}
    d = fact_digest("revoke", rev.to_dict())
    g = "all" if rev.generation is None else str(rev.generation)
    return FactRecord("revoke", d, body, label or f"revoke {rev.target} g{g}")


# --------------------------------------------------------------------------- #
# 事实还原与重算
# --------------------------------------------------------------------------- #
@dataclass
class RestoredFacts:
    locks: list[Lock] = field(default_factory=list)
    seals: list[Seal] = field(default_factory=list)
    revokes: list[Revoke] = field(default_factory=list)


def restore(records: list[FactRecord]) -> RestoredFacts:
    rf = RestoredFacts()
    for r in records:
        if r.kind == "lock":
            obj = r.body["lock"]
            if fact_digest("lock", obj) != r.digest:
                raise ValueError(f"锁事实摘要不符: {r.digest[:12]}")
            rf.locks.append(Lock.from_dict(obj))
        elif r.kind == "seal":
            s = Seal.from_dict(r.body["seal"])
            if fact_digest("seal", s.payload.to_dict() | {"mac": s.mac}) != r.digest:
                raise ValueError(f"签封事实摘要不符: {r.digest[:12]}")
            rf.seals.append(s)
        elif r.kind == "revoke":
            obj = r.body["revoke"]
            if fact_digest("revoke", obj) != r.digest:
                raise ValueError(f"撤销事实摘要不符: {r.digest[:12]}")
            rf.revokes.append(Revoke.from_dict(obj))
        else:
            raise ValueError(f"未知事实种类: {r.kind!r}")
    return rf


# --------------------------------------------------------------------------- #
# 违规判定（只依赖传入事实子集）
# --------------------------------------------------------------------------- #
def _valid_seal(reg: KeyRegistry, s: Seal) -> bool:
    return seal_mac_ok(reg, s)




def _matching_seals(rf: RestoredFacts, reg: KeyRegistry,
                    permit_no: str, gen: int, trustee: str, resource: str) -> list[Seal]:
    return [
        s for s in rf.seals
        if s.permit_no == permit_no and s.generation == gen
        and s.trustee == trustee and s.resource == resource and _valid_seal(reg, s)
    ]


def violates(kind: str, rf: RestoredFacts, reg: KeyRegistry) -> bool:
    """给定事实子集，是否违反该种类规则。"""
    from .rules import independent_pair  # 局部导入，单一事实源

    if kind == K_REVOKED:
        for l in rf.locks:
            for r in rf.revokes:
                if r.target == l.trustee and (r.generation is None or r.generation == l.generation):
                    return True
        return False
    if kind == K_SAME_ORIGIN:
        # 违规 = 有 ≥2 份匹配签封，却凑不出“不同控制人且不同原点”的一对
        for l in rf.locks:
            ms = _matching_seals(rf, reg, l.permit_no, l.generation, l.trustee, l.resource)
            if len(ms) >= 2 and independent_pair(reg, ms) is None:
                return True
        return False
    if kind == K_REGRESSION:
        by_permit: dict[str, list[Lock]] = {}
        for l in rf.locks:
            by_permit.setdefault(l.permit_no, []).append(l)
        for locks in by_permit.values():
            locks = sorted(locks, key=lambda x: x.created_seq)
            seen_max = -1
            for l in locks:
                if l.generation < seen_max:
                    return True
                seen_max = max(seen_max, l.generation)
        return False
    raise ValueError(f"未知冲突种类: {kind!r}")


def minimize_facts(kind: str, records: list[FactRecord], reg: KeyRegistry) -> list[FactRecord]:
    """逐条删除，求极小违规事实子集。"""
    current = list(records)
    if not violates(kind, restore(current), reg):
        raise ValueError("全集不违规，无法构造冲突证据")
    i = 0
    while i < len(current):
        trial = current[:i] + current[i + 1:]
        if trial and violates(kind, restore(trial), reg):
            current = trial
        else:
            i += 1
    return current


# --------------------------------------------------------------------------- #
# 证据对象
# --------------------------------------------------------------------------- #
@dataclass
class ConflictEvidence:
    permit_no: str
    active_generation: int
    trustee: str
    resource: str
    conflict_kind: str
    rule: str
    facts: list[FactRecord]

    def to_dict(self) -> dict:
        return {
            "kind": "conflict-evidence/v1",
            "permit_no": self.permit_no,
            "active_generation": self.active_generation,
            "trustee": self.trustee,
            "resource": self.resource,
            "conflict_kind": self.conflict_kind,
            "rule": self.rule,
            "facts": [f.to_dict() for f in self.facts],
        }

    def digest(self) -> str:
        return tagged_sha256("conflict-evidence/v1", self.to_dict())

    @staticmethod
    def from_dict(d: dict) -> "ConflictEvidence":
        return ConflictEvidence(
            d["permit_no"], int(d["active_generation"]), d["trustee"], d["resource"],
            d["conflict_kind"], d["rule"], [FactRecord.from_dict(x) for x in d["facts"]],
        )

    def fact_digests(self) -> list[str]:
        return [f.digest for f in self.facts]
