"""小图穷举：签发、撤销、代理换根的短交错。

思路
----
把“一个许可从锁定到撤销”的操作集缩小成 7 个抽象动作，按**状态图**做有界
广度优先遍历（默认深度 5），从而穷尽所有短交错，而不是只测手写用例。

每个可达的抽象状态都会被**映射回真实模型对象**（Lock/Seal/Revoke + 真实
KeyRegistry 谱系），再调用生产用的 rules.evaluate_permit 独立求值。随后的安全
不变量断言，检验的是真实判定逻辑在所有短交错下是否守住：

  I1 撤销支配：若当前代被撤销（含全代撤销），重建后的授权集合不得含它；
  I2 独立性：某代被判有效，当且仅当至少存在来自 **2 个不同根谱系原点** 的
     有效签封；同一原点两份签封绝不能凑成有效；
  I3 代理换根不改写历史：换根只影响此后签封的原点，已落盘签封的判定不变；
  I4 旧代重投无效：把旧代签封重投到状态里，当前代的判定不受影响；
  I5 单活动代：授权集合最多只含“当前活动代”。

一旦违反，报告最短到达路径（动作序列）作为反例。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .crypto import KeyRegistry, SealPayload, fixture_key, key_id_of, seal_mac
from .model import Lock, Revoke, Seal
from .rules import Facts, S_VALID, evaluate_permit, independent_pair

# ---------------------------------------------------------------------------
# 抽象动作
# ---------------------------------------------------------------------------
OP_SEAL1 = "seal_c1"
OP_SEAL2 = "seal_c2"
OP_REVOKE_GEN = "revoke_gen"
OP_REVOKE_ALL = "revoke_all"
OP_REROOT = "reroot"
OP_ISSUE = "issue"
OP_BUMP = "bump_gen"
OP_REPLAY = "replay_old"

ALPHABET = [
    OP_SEAL1, OP_SEAL2, OP_REVOKE_GEN, OP_REVOKE_ALL,
    OP_REROOT, OP_ISSUE, OP_BUMP, OP_REPLAY,
]

PERMIT = "DUTY-M"
TRUSTEE = "王强"
RESOURCE = "调度室"

SEAL_NONCE = 1_000_000  # 保证重投/N 次签封的 nonce 唯一


@dataclass(frozen=True)
class AbstractState:
    gen: int
    rerooted: bool
    revoke_all: bool
    revoked_gens: frozenset[int]
    # seals: 每条 = (controller, gen, rerooted_at_seal, nonce)
    seals: frozenset[tuple[str, int, bool, int]]
    next_nonce: int = 0

    def signature(self) -> tuple:
        return (
            self.gen, self.rerooted, self.revoke_all,
            tuple(sorted(self.revoked_gens)), tuple(sorted(self.seals)),
        )


def initial_state() -> AbstractState:
    return AbstractState(
        gen=1, rerooted=False, revoke_all=False,
        revoked_gens=frozenset(), seals=frozenset(), next_nonce=0,
    )


def step(s: AbstractState, op: str) -> AbstractState | None:
    """执行一个抽象动作；非法则返回 None。"""
    if op == OP_SEAL1:
        return _add_seal(s, "c1")
    if op == OP_SEAL2:
        return _add_seal(s, "c2")
    if op == OP_REVOKE_GEN:
        if s.gen in s.revoked_gens:
            return None
        return AbstractState(s.gen, s.rerooted, s.revoke_all,
                             s.revoked_gens | {s.gen}, s.seals, s.next_nonce)
    if op == OP_REVOKE_ALL:
        if s.revoke_all:
            return None
        return AbstractState(s.gen, s.rerooted, True, s.revoked_gens, s.seals, s.next_nonce)
    if op == OP_REROOT:
        if s.rerooted:
            return None
        return AbstractState(s.gen, True, s.revoke_all, s.revoked_gens, s.seals, s.next_nonce)
    if op == OP_ISSUE:
        # 抽象层不改变事实；签发是否成功由求值决定，这里作为“观察点”
        return s
    if op == OP_BUMP:
        if s.gen >= 3:   # 小图：最多到第 3 代
            return None
        return AbstractState(s.gen + 1, s.rerooted, s.revoke_all,
                             s.revoked_gens, s.seals, s.next_nonce)
    if op == OP_REPLAY:
        # 重投上一代的某份旧签封（若存在旧代）
        if s.gen <= 1:
            return None
        old = s.gen - 1
        return AbstractState(s.gen, s.rerooted, s.revoke_all, s.revoked_gens,
                             s.seals | {("c1", old, s.rerooted, -1)}, s.next_nonce)
    raise ValueError(op)


def _add_seal(s: AbstractState, controller: str) -> AbstractState:
    n = s.next_nonce
    return AbstractState(
        s.gen, s.rerooted, s.revoke_all, s.revoked_gens,
        s.seals | {(controller, s.gen, s.rerooted, n)}, n + 1,
    )


# ---------------------------------------------------------------------------
# 抽象状态 -> 真实模型
# ---------------------------------------------------------------------------
def build_registry(rerooted: bool) -> KeyRegistry:
    """构造注册表。注意：换根**不删除历史**——旧根 B 与旧密钥仍然存在。

    * 未换根：根 A、B；c1 -> A(c1-key-v1)，c2 -> B(c2-key-v1)。
    * 已换根：额外加入新根 B2（父为 A）；c2 的 v2 密钥挂在 B2 下（原点=A）。
      但 c2-key-v1 仍留在 B 下 —— 换根前落的签封必须继续按原点 B 解释。
    """
    reg = KeyRegistry()
    reg.add_root("A")
    reg.add_root("B")
    reg.add_controller_key("c1", "A", "c1-key-v1")
    reg.add_controller_key("c2", "B", "c2-key-v1")   # 历史密钥始终存在
    if rerooted:
        reg.add_root("B2", parent="A")
        reg.add_controller_key("c2", "B2", "c2-key-v2")
    return reg


def _key_for(controller: str, rerooted_at_seal: bool) -> str:
    if controller == "c1":
        return key_id_of(fixture_key("c1-key-v1"))
    if rerooted_at_seal:
        return key_id_of(fixture_key("c2-key-v2"))
    return key_id_of(fixture_key("c2-key-v1"))


def to_facts(s: AbstractState) -> tuple[Facts, KeyRegistry]:
    reg = build_registry(s.rerooted)
    locks = [Lock(PERMIT, g, TRUSTEE, RESOURCE, created_seq=g) for g in range(1, s.gen + 1)]
    seals: list[Seal] = []
    for controller, g, rr, nonce in sorted(s.seals):
        kid = _key_for(controller, rr)
        p = SealPayload(PERMIT, g, TRUSTEE, RESOURCE, kid, f"n{nonce}")
        try:
            _, _, key = reg.resolve(kid)
        except KeyError:
            continue
        seals.append(Seal(p, seal_mac(key, p.to_dict()), created_seq=g))
    revokes = [Revoke(TRUSTEE, g, created_seq=g) for g in sorted(s.revoked_gens)]
    if s.revoke_all:
        revokes.append(Revoke(TRUSTEE, None, created_seq=0))
    return Facts(locks=locks, seals=seals, revokes=revokes), reg


# ---------------------------------------------------------------------------
# 不变量
# ---------------------------------------------------------------------------
@dataclass
class Violation:
    invariant: str
    path: list[str]
    detail: str


def check_state(s: AbstractState, path: list[str]) -> list[Violation]:
    facts, reg = to_facts(s)
    decision = evaluate_permit(PERMIT, facts, reg)
    out: list[Violation] = []

    g = s.gen
    revoked = s.revoke_all or (g in s.revoked_gens)

    # I1 撤销支配
    if revoked and decision.valid:
        out.append(Violation("I1-revoke-dominance", list(path),
                             f"当前代 {g} 已被撤销，却仍被判有效"))

    # I2 独立性（双向）：有效 <=> 存在“不同控制人且不同原点”的一对，且未被撤销
    matching = [se for se in facts.seals
                if se.generation == g and not revoked]
    pair = independent_pair(reg, matching)
    origins = set()
    for se in matching:
        try:
            origins.add(reg.origin_of(se.payload.key_id))
        except (KeyError, ValueError):
            pass
    should_be_valid = (not revoked) and (pair is not None)
    if decision.valid != should_be_valid:
        out.append(Violation(
            "I2-independence", list(path),
            f"判定 valid={decision.valid} 但独立对={pair is not None} "
            f"（签封数={len(matching)}，原点数={len(origins)}），期望 {should_be_valid}",
        ))
    # 同源（或同一控制人）多份绝不能凑成有效
    if len(matching) >= 2 and pair is None and decision.valid:
        out.append(Violation("I2-independence", list(path),
                             "见证不独立的多份签封被判有效（见证被合并）"))

    # I5 单活动代
    if decision.valid and decision.active_generation != g:
        out.append(Violation("I5-single-active-generation", list(path),
                             f"有效代 {decision.active_generation} != 当前代 {g}"))

    return out


def check_reroot_history_independence(
    s: AbstractState, path: list[str]
) -> list[Violation]:
    """I3：代理换根不得改写历史签封的谱系原点。

    换根前落盘的 c2 签封使用 c2-key-v1（原点 B），换根后必须**仍**解释为
    原点 B；否则一次换根就会悄悄把旧见证“并入”新根，破坏独立性判定。
    这里直接比对：无论状态是否已换根，同一历史密钥的谱系原点必须恒定。
    """
    out: list[Violation] = []
    kid_v1 = key_id_of(fixture_key("c2-key-v1"))
    origin_now = build_registry(s.rerooted).origin_of(kid_v1)
    origin_none = build_registry(False).origin_of(kid_v1)
    if origin_now != origin_none:
        out.append(Violation(
            "I3-reroot-immutable-history", list(path),
            f"换根改变了历史密钥原点：{origin_none} -> {origin_now}",
        ))
    return out


# ---------------------------------------------------------------------------
# 有界状态图遍历
# ---------------------------------------------------------------------------
@dataclass
class ModelCheckResult:
    max_depth: int
    states: int
    transitions: int
    violations: list[Violation] = field(default_factory=list)
    named: dict[str, list[str]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.violations


def explore(max_depth: int = 5) -> ModelCheckResult:
    start = initial_state()
    seen: dict[tuple, int] = {start.signature(): 0}
    parent: dict[tuple, tuple[tuple, str] | None] = {start.signature(): None}
    q: deque[AbstractState] = deque([start])
    violations: list[Violation] = []
    transitions = 0

    def path_to(sig: tuple) -> list[str]:
        ops: list[str] = []
        cur = sig
        while parent[cur] is not None:
            prev, op = parent[cur]  # type: ignore[misc]
            ops.append(op)
            cur = prev
        return list(reversed(ops))

    while q:
        s = q.popleft()
        depth = seen[s.signature()]
        violations.extend(check_state(s, path_to(s.signature())))
        violations.extend(check_reroot_history_independence(s, path_to(s.signature())))
        if depth >= max_depth:
            continue
        for op in ALPHABET:
            ns = step(s, op)
            if ns is None:
                continue
            transitions += 1
            sig = ns.signature()
            if sig in seen:
                continue
            seen[sig] = depth + 1
            parent[sig] = (s.signature(), op)
            q.append(ns)

    named = {
        "撤销先于第二签封": [OP_SEAL1, OP_REVOKE_GEN, OP_SEAL2, OP_ISSUE],
        "签发后撤销": [OP_SEAL1, OP_SEAL2, OP_ISSUE, OP_REVOKE_GEN],
        "换根致同源": [OP_SEAL1, OP_REROOT, OP_REVOKE_GEN, OP_BUMP, OP_SEAL1, OP_SEAL2],
        "旧代重投": [OP_SEAL1, OP_SEAL2, OP_BUMP, OP_REPLAY, OP_SEAL1, OP_SEAL2],
    }
    # 验证命名场景也在覆盖内（深路径单独回放，仅用于展示判定）
    for name, ops in named.items():
        st = initial_state()
        okpath = True
        for op in ops:
            st = step(st, op)
            if st is None:
                okpath = False
                break
        if okpath:
            violations.extend(check_state(st, ops))

    return ModelCheckResult(
        max_depth=max_depth,
        states=len(seen),
        transitions=transitions,
        violations=violations,
        named=named,
    )
