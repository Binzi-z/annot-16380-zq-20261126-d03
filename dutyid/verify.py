"""独立验签器。

刻意只依赖 canonical / crypto / rules / evidence 的**纯函数**（不导入 engine），
从而对“引擎是否自洽”保持独立。职责：

  * 从磁盘重读事件链并校验哈希链；
  * 从磁盘重读独立签封/锁/撤销文件，逐个重算 MAC 与规范摘要；
  * 用 rules.evaluate_permit 独立重算授权集合；
  * 把清单与实际重算交叉核对；
  * 独立复核最小冲突证据：重算每条事实摘要、重放 violates、
    并逐条删除确认不再违规（极小性）。

区分两类结论：
  * ok / problems —— **结构完整性**（链、MAC、摘要、被引文件缺失）。这是
    “数据是否可信”的底线，正常应为 ok。
  * findings —— **语义分歧**（清单自称与重建不符等）。这是工具**应检测到**
    的真实问题，不能静默通过。一个合法的危险场景恰恰期望 findings 非空。

验签器不信任：签封自报的 root_id、清单自报 status、引擎内存状态、
证据里自报的“冲突种类”。一切以重算为准。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import KeyRegistry, SealPayload
from .evidence import ConflictEvidence, restore, violates
from .rules import (
    S_VALID,
    Facts,
    evaluate_permit,
    seal_mac_ok,
)
from .store import Store


@dataclass
class VerifyReport:
    ok: bool = True
    problems: list[str] = field(default_factory=list)      # 结构完整性
    findings: list[str] = field(default_factory=list)      # 语义分歧（应被检测）
    valid: set[str] = field(default_factory=set)
    decisions: dict = field(default_factory=dict)
    evidence_results: dict = field(default_factory=dict)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.problems.append(msg)

    def find(self, msg: str) -> None:
        self.findings.append(msg)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "problems": self.problems,
            "findings": self.findings,
            "valid": sorted(self.valid),
            "decisions": {
                k: {"status": v.status, "valid": v.valid, "rule": v.rule}
                for k, v in sorted(self.decisions.items())
            },
            "evidence_results": self.evidence_results,
        }


def verify_store(store: Store, registry: KeyRegistry) -> VerifyReport:
    rep = VerifyReport()

    # 1) 事件链
    try:
        events = list(store.iter_events())
    except Exception as exc:  # noqa: BLE001
        rep.fail(f"事件链校验失败: {exc}")
        return rep
    if not events:
        rep.fail("事件链为空")
        return rep

    # 2) 独立事实文件：重算摘要与 MAC
    try:
        locks = store.read_locks()
        seals = store.read_seals()
        revokes = store.read_revokes()
        reroots = store.read_reroots()
        manifest = store.read_manifest()
    except Exception as exc:  # noqa: BLE001
        rep.fail(f"事实文件读取/校验失败: {exc}")
        return rep

    for s in seals:
        if not seal_mac_ok(registry, s):
            rep.fail(f"签封 MAC 校验失败: {s.payload.digest()[:12]}")
        try:
            registry.resolve(s.payload.key_id)
        except KeyError:
            rep.fail(f"签封引用未登记密钥: {s.payload.key_id[:12]}")

    facts = Facts(locks=locks, seals=seals, revokes=revokes, reroots=reroots,
                  manifest=manifest)

    # 3) 独立重算授权集合
    for permit_no in sorted({l.permit_no for l in locks}):
        d = evaluate_permit(permit_no, facts, registry)
        rep.decisions[permit_no] = d
        if d.valid:
            rep.valid.add(permit_no)

    # 4) 清单 vs 重算（语义分歧 -> findings；被引文件缺失 -> problems）
    if manifest is not None:
        for permit_no, entry in manifest.entries.items():
            claimed_valid = entry.status == S_VALID
            actual_valid = permit_no in rep.valid
            if claimed_valid != actual_valid:
                rep.find(
                    f"清单声称 {permit_no}={entry.status} 与重算不符"
                    f"（重算 {'valid' if actual_valid else 'invalid'}）"
                )
            # 活动代分歧：清单钉的代应与重建的活动代一致（防止陈旧快照蒙混）
            dec = rep.decisions.get(permit_no)
            if dec is not None and dec.active_generation is not None:
                if entry.active_generation != dec.active_generation:
                    rep.find(
                        f"清单声称 {permit_no} 活动代={entry.active_generation} "
                        f"与重算活动代={dec.active_generation} 不符（清单陈旧）"
                    )
            for dg in entry.seal_digests:
                if not store.seal_path_by_digest(dg).exists():
                    rep.fail(f"清单引用缺失签封: {permit_no} <- {dg[:12]}")

    # 5) 事件与事实一致性：每个 seal 事件都应有对应落盘签封
    seal_digests_on_disk = {s.payload.digest() for s in seals}
    for ev in events:
        if ev.etype == "seal":
            d = ev.payload.get("payload", {})
            sp = SealPayload(
                d["permit_no"], int(d["generation"]), d["trustee"],
                d["resource"], d["key_id"], d["nonce"],
            )
            if sp.digest() not in seal_digests_on_disk:
                rep.fail(f"seal 事件缺少落盘签封: {sp.digest()[:12]}")

    return rep


# --------------------------------------------------------------------------- #
# 独立复核冲突证据
# --------------------------------------------------------------------------- #
def verify_evidence(
    evidence: ConflictEvidence, registry: KeyRegistry
) -> VerifyReport:
    """复核证据：事实自洽、确实违规、且极小。"""
    rep = VerifyReport()

    # 1) 事实摘要重算
    try:
        restored = restore(evidence.facts)
    except Exception as exc:  # noqa: BLE001
        rep.fail(f"证据事实还原/摘要校验失败: {exc}")
        return rep

    # 2) 确实违规
    if not violates(evidence.conflict_kind, restored, registry):
        rep.fail(f"证据子集不违反规则 {evidence.rule}（{evidence.conflict_kind}）")
        return rep

    # 3) 极小性：删除任一事实后不再违规
    for i in range(len(evidence.facts)):
        trial = evidence.facts[:i] + evidence.facts[i + 1:]
        if not trial:
            continue
        if violates(evidence.conflict_kind, restore(trial), registry):
            rep.fail(
                f"证据非极小：删除事实 "
                f"{evidence.facts[i].label or evidence.facts[i].digest[:12]} 后仍违规"
            )

    rep.evidence_results = {
        "conflict_kind": evidence.conflict_kind,
        "rule": evidence.rule,
        "facts": [f.label or f.digest[:12] for f in evidence.facts],
        "minimal": rep.ok,
        "digest": evidence.digest(),
    }
    return rep
