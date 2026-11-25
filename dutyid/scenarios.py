"""并发场景：两个真实线程 + 屏障，复现题面的两种危险交错。

场景 A —— 撤销先写入
    管理员在两个控制人签封之间撤回身份；两线程在“即将提交”处设屏障，
    并用事件闸保证**撤销先落盘**，签封/签发线程随后才提交。
    引擎在签发时重读事实，故撤销必胜：签发被拒。
    恢复不得把该许可纳入授权集合，并给出 {锁, 撤销} 的 2 条事实最小证据。

场景 B —— 合法签发已落盘、回执遗失，再叠加旧代同号重投 + 代理换根
    先在第 1 代用两根 A、B 各自签封，合法签发并落盘（清单记 valid）；
    随后“确认回执丢失”，调用方未持有 ack，但磁盘已生效。
    之后代理换根：新根 B2 挂在 A 之下（B2 的谱系原点 = A），c2 的密钥迁移到 B2。
    轮换到第 2 代后，c1(原点A) 与 c2(原点A) 两份签封**同源**，不能合并。
    同时外部进程把第 1 代旧签封“同号重投”到磁盘。
    恢复须：只依据落盘签封与清单重建；旧代签封被忽略；第 2 代判为同源冲突；
    清单自称 valid 与重建不符作为**语义分歧**被检出；并给出
    {第 2 代锁, 签封c1, 签封c2} 的 3 条事实最小证据（删任一条即不复冲突）。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .crypto import KeyRegistry, SealPayload, fixture_key, key_id_of, seal_mac
from .engine import Engine, EngineError, RecoveredState
from .evidence import K_REVOKED, K_SAME_ORIGIN
from .model import Seal
from .rules import S_CONFLICT, S_REVOKED
from .store import Store
from .verify import VerifyReport, verify_evidence, verify_store


# --------------------------------------------------------------------------- #
# 夹具
# --------------------------------------------------------------------------- #
def base_registry() -> KeyRegistry:
    """两个独立根 A、B，各一名控制人 c1、c2。"""
    reg = KeyRegistry()
    reg.add_root("A")
    reg.add_root("B")
    reg.add_controller_key("c1", "A", "c1-key-v1")
    reg.add_controller_key("c2", "B", "c2-key-v1")
    return reg


def kid(key_label: str) -> str:
    return key_id_of(fixture_key(key_label))


@dataclass
class ScenarioResult:
    name: str
    description: str
    recovered: RecoveredState
    verify: VerifyReport
    evidence_verify: dict[str, VerifyReport] = field(default_factory=dict)
    trace: list[str] = field(default_factory=list)
    threads_used: int = 0
    barriers_used: int = 0
    expectations: list[tuple[str, bool]] = field(default_factory=list)

    @property
    def expectations_ok(self) -> bool:
        return all(passed for _, passed in self.expectations)

    @property
    def ok(self) -> bool:
        ev_ok = all(r.ok for r in self.evidence_verify.values())
        return self.verify.ok and ev_ok and self.expectations_ok


# --------------------------------------------------------------------------- #
# 场景 A：撤销先写入（两线程 + 屏障）
# --------------------------------------------------------------------------- #
def scenario_revoke_first(workdir: str) -> ScenarioResult:
    store = Store(workdir)
    reg = base_registry()
    eng = Engine(store, reg)
    trace: list[str] = []

    permit = "DUTY-A"
    trustee = "张伟"
    resource = "值班室-东区"

    eng.apply(permit, trustee, resource)
    eng.lock(permit, 1, trustee, resource)
    trace.append("已锁定 gen=1（受托人=张伟，资源=值班室-东区）")

    arrive = threading.Barrier(2)          # 两线程在“即将提交”处会合
    revoke_done = threading.Event()        # 强制撤销先落盘
    result: dict[str, object] = {}
    tls = threading.Lock()

    def admin_thread() -> None:
        arrive.wait()
        with tls:
            eng.revoke(trustee, generation=1)
            trace.append("线程R：撤销已 fsync 落盘（gen=1）")
        revoke_done.set()

    def issuer_thread() -> None:
        arrive.wait()
        revoke_done.wait()                  # 撤销落盘后才允许提交
        with tls:
            try:
                s1 = eng.submit_seal(permit, "c1", kid("c1-key-v1"), "A-c1")
                s2 = eng.submit_seal(permit, "c2", kid("c2-key-v1"), "A-c2")
                trace.append("线程I：两份独立签封已落盘（本可构成有效许可）")
                ack = eng.issue(permit)
                result["ack"] = ack
                trace.append(f"线程I：签发竟然成功 {ack}（不应发生）")
            except EngineError as exc:
                result["error"] = str(exc)
                trace.append(f"线程I：签发被拒 — {exc}")

    t_r = threading.Thread(target=admin_thread, name="admin-revoke")
    t_i = threading.Thread(target=issuer_thread, name="issuer")
    t_r.start(); t_i.start()
    t_r.join(); t_i.join()

    recovered = eng.recover()
    vrep = verify_store(Store(workdir), reg)

    ev_verify: dict[str, VerifyReport] = {}
    ev = recovered.conflicts.get(permit)
    if ev is not None:
        trace.append(
            f"恢复：{permit} 判定={recovered.decisions[permit].status}；"
            f"证据={ev.conflict_kind}，事实数={len(ev.facts)}"
        )
        ev_verify[permit] = verify_evidence(ev, reg)
    else:
        trace.append(f"严重：恢复未产出 {permit} 的冲突证据")

    decision = recovered.decisions.get(permit)
    expectations = [
        ("签发被撤销拒绝", "error" in result and "ack" not in result),
        ("恢复后许可不在授权集合", permit not in recovered.valid),
        ("判定为已撤销", decision is not None and decision.status == S_REVOKED),
        ("证据种类=revoked", ev is not None and ev.conflict_kind == K_REVOKED),
        ("证据恰为 2 条事实", ev is not None and len(ev.facts) == 2),
        ("结构完整性 ok", vrep.ok),
        ("无陈旧清单分歧", vrep.findings == []),
    ]

    return ScenarioResult(
        name="A-撤销先写入",
        description="管理员在签封之间先 fsync 撤销；撤销必胜，签发不得生效",
        recovered=recovered, verify=vrep, evidence_verify=ev_verify,
        trace=trace, threads_used=2, barriers_used=1, expectations=expectations,
    )


# --------------------------------------------------------------------------- #
# 场景 B：回执遗失 + 代理换根致同源 + 旧代同号重投（两线程 + 屏障）
# --------------------------------------------------------------------------- #
def scenario_lost_ack_replay(workdir: str) -> ScenarioResult:
    store = Store(workdir)
    reg = base_registry()
    eng = Engine(store, reg)
    trace: list[str] = []

    permit = "DUTY-B"
    trustee = "李娜"
    resource = "值班室-西区"

    eng.apply(permit, trustee, resource)
    eng.lock(permit, 1, trustee, resource)
    # 第 1 代：A、B 两根独立签封 -> 合法签发
    s1 = eng.submit_seal(permit, "c1", kid("c1-key-v1"), "B1-c1")
    s2 = eng.submit_seal(permit, "c2", kid("c2-key-v1"), "B1-c2")
    ack = eng.issue(permit)
    trace.append(
        f"gen=1 合法签发并落盘；清单 digest={ack.manifest_digest[:12]}；"
        "但确认回执在返回途中遗失（调用方不持有 ack）"
    )
    del ack  # 回执遗失

    arrive = threading.Barrier(2)
    rotated = threading.Event()
    errs: list[str] = []
    tls = threading.Lock()

    def rotate_thread() -> None:
        arrive.wait()
        with tls:
            # 代理换根：新根 B2 挂在 A 之下；c2 的密钥迁移到 B2 —— 谱系原点变为 A
            eng.reroot("A", "B2")
            reg.add_controller_key("c2", "B2", "c2-key-v2")
            trace.append("线程ROTATE：代理换根 B2←A，c2 密钥迁至 B2（原点=A）")
            # 轮换到第 2 代
            eng.lock(permit, 2, trustee, resource)
            trace.append("线程ROTATE：轮换至 gen=2")
            # 第 2 代由 c1(原点A) 与 c2(原点A) 各签一份 —— 同源
            eng.submit_seal(permit, "c1", kid("c1-key-v1"), "B2-c1")
            eng.submit_seal(permit, "c2", kid("c2-key-v2"), "B2-c2")
            trace.append("线程ROTATE：gen=2 两份签封均来自谱系原点 A（同源）")
        rotated.set()

    def replay_thread() -> None:
        arrive.wait()
        rotated.wait()   # 待新代生效后，再“旧代同号重投”
        with tls:
            # 1) 走引擎的显式旧代重投接口：应被拒并留痕
            try:
                eng.submit_stale_seal(
                    permit, "c2", kid("c2-key-v1"), "replay-c2", generation=1
                )
                errs.append("引擎过早接受了旧代重投")
            except EngineError as exc:
                trace.append(f"线程REPLAY：引擎拒绝旧代重投 — {exc}")
            # 2) 外部进程绕过引擎，把第 1 代签封“同号重投”到磁盘
            _inject_seal_file(workdir, permit, "c1", kid("c1-key-v1"),
                               trustee, resource, generation=1, nonce="replay-c1-g1")
            _inject_seal_file(workdir, permit, "c2", kid("c2-key-v1"),
                               trustee, resource, generation=1, nonce="replay-c2-g1")
            trace.append("线程REPLAY：第 1 代旧签封已同号重投到磁盘（应被恢复忽略）")

    t_rot = threading.Thread(target=rotate_thread, name="rotate-reroot")
    t_rep = threading.Thread(target=replay_thread, name="replay")
    t_rot.start(); t_rep.start()
    t_rot.join(); t_rep.join()
    if errs:
        trace.append("；".join(errs))

    recovered = eng.recover()
    vrep = verify_store(Store(workdir), reg)

    ev_verify: dict[str, VerifyReport] = {}
    ev = recovered.conflicts.get(permit)
    decision = recovered.decisions.get(permit)
    if ev is not None:
        trace.append(
            f"恢复：{permit} 判定={decision.status if decision else '?'}"
            f"（活动代={decision.active_generation if decision else '?'}）；"
            f"证据={ev.conflict_kind}，事实数={len(ev.facts)}"
        )
        ev_verify[permit] = verify_evidence(ev, reg)
    else:
        trace.append(f"严重：恢复未产出 {permit} 的冲突证据")

    # 统计：磁盘上存在的第 1 代签封（含重投）数量
    all_seals = Store(workdir).read_seals()
    g1_seals = [s for s in all_seals if s.permit_no == permit and s.generation == 1]
    trace.append(f"磁盘上第 1 代签封共 {len(g1_seals)} 份（含 2 份重投），恢复均已按旧代忽略")

    expectations = [
        ("换根后原点合并为 A", reg.origin_of(kid("c2-key-v2")) == "A"),
        ("恢复后许可不在授权集合", permit not in recovered.valid),
        ("判定为同源冲突", decision is not None and decision.status == S_CONFLICT),
        ("证据种类=same_origin", ev is not None and ev.conflict_kind == K_SAME_ORIGIN),
        ("证据恰为 3 条事实", ev is not None and len(ev.facts) == 3),
        ("旧代重投被引擎拒绝", any("拒绝旧代重投" in t for t in trace)),
        ("检出陈旧清单分歧", len(vrep.findings) >= 1),
        ("结构完整性 ok", vrep.ok),
    ]

    return ScenarioResult(
        name="B-回执遗失+换根同源+旧代重投",
        description="合法签发已落盘但回执遗失；代理换根令第2代同源；旧代同号重投被忽略",
        recovered=recovered, verify=vrep, evidence_verify=ev_verify,
        trace=trace, threads_used=2, barriers_used=1, expectations=expectations,
    )


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _inject_seal_file(workdir: str, permit: str, controller: str, key_id: str,
                      trustee: str, resource: str, generation: int, nonce: str) -> Seal:
    """绕过引擎，直接构造并落盘一份签封（模拟外部进程同号重投）。"""
    p = SealPayload(
        permit_no=permit, generation=generation, trustee=trustee,
        resource=resource, key_id=key_id, nonce=nonce,
    )
    real_key = _fixture_key_for_kid(key_id)
    seal = Seal(p, seal_mac(real_key, p.to_dict()), created_seq=10_000)
    Store(workdir).write_seal(seal)
    return seal


def _fixture_key_for_kid(key_id: str) -> bytes:
    """在已知合成标签里找匹配 key_id 的密钥。"""
    for label in ("c1-key-v1", "c2-key-v1", "c2-key-v2", "c1-key-v2"):
        k = fixture_key(label)
        if key_id_of(k) == key_id:
            return k
    raise KeyError(f"未知合成 key_id: {key_id}")
