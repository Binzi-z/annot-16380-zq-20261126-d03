"""状态机引擎：申请、锁、签封、签发、撤销、代理换根；以及恢复重建。

线程模型
--------
* 所有**变更**操作在实例级 threading.Lock 下串行化，保证落盘顺序有全序；
* 引擎不假设调用方单线程：场景模块用两个真实线程 + 屏障控制“谁先提交”，
  引擎只负责把已获准的这次提交原子地落盘（文件 fsync + 事件 append）。

恢复
----
`recover()` 只依据**实际落盘**的事实：
  1) 先校验事件哈希链完整；
  2) 读取独立的锁/签封/撤销/换根文件与清单；
  3) 用 rules.evaluate_permit 逐个重建授权集合；
  4) 用清单交叉核对（R5），不一致即作为冲突上报并生成证据。
绝不盲信内存状态或清单作者自报。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .crypto import KeyRegistry, SealPayload, seal_mac
from .evidence import (
    K_REGRESSION,
    K_REVOKED,
    K_SAME_ORIGIN,
    ConflictEvidence,
    FactRecord,
    lock_fact,
    minimize_facts,
    revoke_fact,
    seal_fact,
)
from .model import (
    EventType,
    Lock,
    Manifest,
    ManifestEntry,
    R_INDEPENDENT_SEALS,
    R_NOT_REVOKED,
    R_UNIQUE_ACTIVE_GEN,
    Revoke,
    ReRoot,
    Seal,
)
from .rules import (
    Facts,
    RuleDecision,
    S_CONFLICT,
    S_REGRESSION,
    S_REVOKED,
    S_VALID,
    evaluate_permit,
)
from .store import Store


class EngineError(RuntimeError):
    """非法操作。"""


@dataclass
class Ack:
    """签发确认回执（可能遗失 —— 场景会模拟）。"""

    permit_no: str
    generation: int
    status: str
    manifest_digest: str
    seal_digests: list[str]

    def to_dict(self) -> dict:
        return {
            "permit_no": self.permit_no,
            "generation": self.generation,
            "status": self.status,
            "manifest_digest": self.manifest_digest,
            "seal_digests": sorted(self.seal_digests),
        }


@dataclass
class RecoveredState:
    """恢复结果：授权集合 + 判定 + 每许可的决定性对象。"""

    decisions: dict[str, RuleDecision] = field(default_factory=dict)
    valid: set[str] = field(default_factory=set)
    conflicts: dict[str, ConflictEvidence] = field(default_factory=dict)
    facts: Facts = field(default_factory=Facts)
    manifest_ok: bool = True
    chain_ok: bool = True
    notes: list[str] = field(default_factory=list)

    def authorization_set(self) -> set[str]:
        return set(self.valid)


class Engine:
    def __init__(self, store: Store, registry: KeyRegistry) -> None:
        self.store = store
        self.registry = registry
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # 基本操作（每个都在引擎锁下原子提交）
    # ------------------------------------------------------------------ #
    def apply(self, permit_no: str, trustee: str, resource: str) -> dict:
        with self._lock:
            payload = {
                "permit_no": permit_no,
                "trustee": trustee,
                "resource": resource,
            }
            ev = self.store.append_event(EventType.APPLY.value, payload)
            return {"event_seq": ev.seq, "permit_no": permit_no}

    def lock(self, permit_no: str, generation: int, trustee: str, resource: str) -> Lock:
        with self._lock:
            # 主动防线：拒绝代回退（活动代必须严格递增）。恢复侧仍会独立检出，
            # 但这里在写入前就挡住，避免污染落盘状态。
            facts = self._read_facts()
            current, _ = self._active_lock(facts.locks, permit_no)
            if current is not None and generation <= current.generation:
                raise EngineError(
                    f"锁定代回退被拒：请求 gen={generation} 未大于当前 gen={current.generation}"
                )
            lock = self.store.append_event_built(
                EventType.LOCK.value,
                lambda seq: Lock(permit_no, generation, trustee, resource, seq).to_dict(),
            )
            lock_obj = Lock(permit_no, generation, trustee, resource, lock.seq)
            self.store.write_lock(lock_obj)
            return lock_obj

    def submit_seal(
        self, permit_no: str, controller: str, key_id: str, nonce: str
    ) -> Seal | None:
        """控制人签封。授权代/受托人/资源取自当前活动锁；旧代重投会被拒。

        返回 None 表示这是对已生效代的**重复重投**（幂等，不改状态）。
        抛出 EngineError 表示非法（如旧代重投、缺锁、密钥归属不符）。
        """
        with self._lock:
            facts = self._read_facts()
            lock, _ = self._active_lock(facts.locks, permit_no)
            if lock is None:
                raise EngineError(f"许可 {permit_no} 尚未锁定，无法签封")
            if not self.registry_has_key_for_controller(key_id, controller):
                raise EngineError(f"密钥 {key_id} 不属于控制人 {controller}")
            return self._seal_locked(lock, controller, key_id, nonce)

    def submit_stale_seal(
        self, permit_no: str, controller: str, key_id: str, nonce: str,
        generation: int,
    ) -> None:
        """显式提交一个**指定代**的签封（用于模拟旧代同号重投）。

        若该代 != 当前活动代，则拒绝并记录一条 REJECTED，不写签封文件。
        这是一道主动防线：重投者自称的旧代无法覆盖已生效的新代。
        """
        with self._lock:
            facts = self._read_facts()
            lock, _ = self._active_lock(facts.locks, permit_no)
            if lock is None:
                raise EngineError(f"许可 {permit_no} 尚未锁定")
            if generation != lock.generation:
                self.store.append_event(
                    EventType.REJECTED.value,
                    {
                        "permit_no": permit_no,
                        "reason": "stale_generation",
                        "claimed_generation": generation,
                        "active_generation": lock.generation,
                        "controller": controller,
                        "key_id": key_id,
                        "nonce": nonce,
                    },
                )
                raise EngineError(
                    f"旧代重投被拒：claimed gen={generation} != active gen={lock.generation}"
                )
            # 同代重投：幂等，重走正常签封
            self._seal_locked(lock, controller, key_id, nonce)

    def _seal_locked(self, lock: Lock, controller: str, key_id: str, nonce: str) -> Seal:
        _, _, key = self.registry.resolve(key_id)

        def build(seq: int) -> dict:
            p = SealPayload(
                permit_no=lock.permit_no,
                generation=lock.generation,
                trustee=lock.trustee,
                resource=lock.resource,
                key_id=key_id,
                nonce=nonce,
            )
            return Seal(p, seal_mac(key, p.to_dict()), seq).to_dict()

        ev = self.store.append_event_built(EventType.SEAL.value, build)
        seal = Seal.from_dict(ev.payload)
        self.store.write_seal(seal)
        return seal

    def issue(self, permit_no: str) -> Ack:
        """尝试签发：要求双根独立签封齐备且未被撤销。成功则更新清单。"""
        with self._lock:
            facts = self._read_facts()
            decision = evaluate_permit(permit_no, facts, self.registry)
            if not decision.valid:
                raise EngineError(
                    f"许可 {permit_no} 不可签发: {decision.status} ({'; '.join(decision.reasons)})"
                )
            manifest = facts.manifest or Manifest()
            assert decision.pair is not None and decision.lock is not None
            d1 = decision.pair[0].payload.digest()
            d2 = decision.pair[1].payload.digest()
            manifest.entries[permit_no] = ManifestEntry(
                permit_no=permit_no,
                active_generation=decision.active_generation or 0,
                status=S_VALID,
                trustee=decision.trustee or "",
                resource=decision.resource or "",
                seal_digests=[d1, d2],
            )
            self.store.append_event(
                EventType.ISSUE.value,
                {
                    "permit_no": permit_no,
                    "generation": decision.active_generation,
                    "seal_digests": sorted([d1, d2]),
                    "manifest_digest": manifest.digest(),
                },
            )
            self.store.write_manifest(manifest)
            return Ack(
                permit_no=permit_no,
                generation=decision.active_generation or 0,
                status=S_VALID,
                manifest_digest=manifest.digest(),
                seal_digests=[d1, d2],
            )

    def revoke(self, target: str, generation: int | None = None) -> Revoke:
        with self._lock:
            ev = self.store.append_event_built(
                EventType.REVOKE.value,
                lambda seq: Revoke(target, generation, seq).to_dict(),
            )
            rev = Revoke(target, generation, ev.seq)
            self.store.write_revoke(rev)
            # 清单状态即时降级（若存在且在撤销范围内）
            facts = self._read_facts()
            manifest = facts.manifest
            if manifest is not None:
                changed = False
                for entry in manifest.entries.values():
                    if entry.trustee != target:
                        continue
                    if generation is not None and entry.active_generation != generation:
                        continue
                    if entry.status == S_VALID:
                        entry.status = S_REVOKED
                        changed = True
                if changed:
                    self.store.write_manifest(manifest)
            return rev

    def reroot(self, old_root: str, new_root: str) -> ReRoot:
        """代理换根：登记新根，其父为 old_root；谱系原点保持不变。"""
        with self._lock:
            if not self.registry.has_root(old_root):
                raise EngineError(f"未知根: {old_root}")
            try:
                self.registry.add_root(new_root, parent=old_root)
            except KeyError as exc:
                raise EngineError(str(exc)) from exc
            ev = self.store.append_event_built(
                EventType.REROOT.value,
                lambda seq: ReRoot(old_root, new_root, seq).to_dict(),
            )
            rr = ReRoot(old_root, new_root, ev.seq)
            self.store.write_reroot(rr)
            return rr

    # ------------------------------------------------------------------ #
    # 读取事实
    # ------------------------------------------------------------------ #
    def _read_facts(self) -> Facts:
        return Facts(
            locks=self.store.read_locks(),
            seals=self.store.read_seals(),
            revokes=self.store.read_revokes(),
            reroots=self.store.read_reroots(),
            manifest=self.store.read_manifest(),
        )

    def _active_lock(self, locks: list[Lock], permit_no: str) -> tuple[Lock | None, bool]:
        from .rules import active_lock

        return active_lock(locks, permit_no)

    def registry_has_key_for_controller(self, key_id: str, controller: str) -> bool:
        try:
            return self.registry.controller_of(key_id) == controller
        except KeyError:
            return False

    # ------------------------------------------------------------------ #
    # 恢复
    # ------------------------------------------------------------------ #
    def recover(self) -> RecoveredState:
        with self._lock:
            state = RecoveredState()
            # 1) 哈希链完整性（iter_events 遇断裂即抛 StoreCorruption）
            try:
                seqs = [ev.seq for ev in self.store.iter_events()]
                state.chain_ok = True
                state.notes.append(f"事件链完整，共 {len(seqs)} 条")
            except Exception as exc:  # noqa: BLE001 —— 恢复要把损坏作为结论
                state.chain_ok = False
                state.notes.append(f"事件链损坏: {exc}")
                raise

            facts = self._read_facts()
            state.facts = facts

            # 2) 逐许可重建授权集合
            for permit_no in sorted({l.permit_no for l in facts.locks}):
                decision = evaluate_permit(permit_no, facts, self.registry)
                state.decisions[permit_no] = decision
                if decision.valid:
                    state.valid.add(permit_no)
                else:
                    ev = self._evidence_for(decision)
                    if ev is not None:
                        state.conflicts[permit_no] = ev

            # 3) 清单交叉核对（R5）
            if facts.manifest is not None:
                for permit_no, entry in facts.manifest.entries.items():
                    rebuilt_valid = permit_no in state.valid
                    claimed_valid = entry.status == S_VALID
                    if rebuilt_valid != claimed_valid:
                        state.manifest_ok = False
                        state.notes.append(
                            f"清单与重建不一致: {permit_no} 清单={entry.status} "
                            f"重建={'valid' if rebuilt_valid else 'invalid'}"
                        )
                    # 清单引用的签封必须真实落盘
                    for d in entry.seal_digests:
                        try:
                            self.store.seal_path_by_digest(d).read_text("utf-8")
                        except OSError:
                            state.manifest_ok = False
                            state.notes.append(f"清单引用缺失签封: {permit_no} <- {d}")
            return state

    # ------------------------------------------------------------------ #
    # 证据（极小违规事实子集）
    # ------------------------------------------------------------------ #
    def _evidence_for(self, decision: RuleDecision) -> ConflictEvidence | None:
        lock = decision.lock
        if lock is None:
            return None
        gen = decision.active_generation
        assert gen is not None

        if decision.status == S_REVOKED and decision.revoke is not None:
            cand = [lock_fact(lock), revoke_fact(decision.revoke)]
            return self._make_evidence(
                decision, K_REVOKED, R_NOT_REVOKED, cand
            )
        if decision.status == S_CONFLICT and decision.same_origin:
            cand = [lock_fact(lock)] + [seal_fact(s) for s in decision.same_origin]
            return self._make_evidence(
                decision, K_SAME_ORIGIN, R_INDEPENDENT_SEALS, cand
            )
        if decision.status == S_REGRESSION:
            mine = [l for l in self.store.read_locks() if l.permit_no == decision.permit_no]
            cand = [lock_fact(l) for l in mine]
            return self._make_evidence(
                decision, K_REGRESSION, R_UNIQUE_ACTIVE_GEN, cand
            )
        # incomplete 等不构成“冲突”，只是尚未完成；不产证据
        return None

    def _make_evidence(
        self, decision: RuleDecision, kind: str, rule: str, candidates: list[FactRecord]
    ) -> ConflictEvidence | None:
        try:
            minimal = minimize_facts(kind, candidates, self.registry)
        except ValueError:
            # 候选并不违规（例如撤销被更晚重锁抵消）——不构造证据
            return None
        return ConflictEvidence(
            permit_no=decision.permit_no,
            active_generation=decision.active_generation or 0,
            trustee=decision.trustee or "",
            resource=decision.resource or "",
            conflict_kind=kind,
            rule=rule,
            facts=minimal,
        )
