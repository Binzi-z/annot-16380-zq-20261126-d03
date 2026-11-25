"""纯授权规则（无 I/O，单一事实源）。

引擎、穷举模型检查器、独立验签器都调用这里，保证“判定逻辑只有一份”。
所有函数只依赖传入的事实集合与密钥登记表，不触碰磁盘、不读全局状态。

关键规则（与 model.R_* 对应）：

  R1  锁把许可钉在一个授权代上，并绑定受托人/资源；
  R2  需要两份来自**不同根谱系原点**的签封；同源两份不能合并；
  R3  参与授权的签封，其授权代必须等于当前活动代（且受托人/资源一致）；
  R4  存在覆盖当前代（或全代）的撤销，则授权无效；
  R5  清单必须与实际签封产物一致（由恢复流程核对）；
  R6  每个许可同一时刻只有一个活动代，且新锁的代必须严格递增。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import KeyRegistry, verify_seal_mac
from .model import (
    R_GENERATION_MATCH,
    R_INDEPENDENT_SEALS,
    R_LOCK,
    R_NOT_REVOKED,
    R_UNIQUE_ACTIVE_GEN,
    Lock,
    Manifest,
    Revoke,
    ReRoot,
    Seal,
)

# 判定状态
S_VALID = "valid"
S_REVOKED = "revoked"
S_CONFLICT = "conflicting"
S_INCOMPLETE = "incomplete"
S_NO_LOCK = "no_lock"
S_REGRESSION = "generation_regression"


@dataclass
class Facts:
    """一次判定所依据的全部落盘事实快照。"""

    locks: list[Lock] = field(default_factory=list)
    seals: list[Seal] = field(default_factory=list)
    revokes: list[Revoke] = field(default_factory=list)
    reroots: list[ReRoot] = field(default_factory=list)
    manifest: Manifest | None = None


@dataclass
class RuleDecision:
    """一个许可的判定结果，附带决定性对象（供证据构造）。"""

    permit_no: str
    status: str
    valid: bool
    rule: str | None
    active_generation: int | None = None
    trustee: str | None = None
    resource: str | None = None
    lock: Lock | None = None
    pair: tuple[Seal, Seal] | None = None
    same_origin: tuple[Seal, ...] = ()
    revoke: Revoke | None = None
    stale_seals: tuple[Seal, ...] = ()
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# 基础谓词
# --------------------------------------------------------------------------- #
def seal_mac_ok(registry: KeyRegistry, seal: Seal) -> bool:
    try:
        _, _, key = registry.resolve(seal.payload.key_id)
    except KeyError:
        return False
    return verify_seal_mac(key, seal.payload.to_dict(), seal.mac)


def is_revoked(revokes: list[Revoke], trustee: str, generation: int) -> Revoke | None:
    """返回覆盖 (trustee, generation) 的撤销（若有）。全代撤销覆盖任意代。"""
    for rev in revokes:
        if rev.target != trustee:
            continue
        if rev.generation is None or rev.generation == generation:
            return rev
    return None


def active_lock(locks: list[Lock], permit_no: str) -> tuple[Lock | None, bool]:
    """返回 (活动锁, 是否发生代回退)。

    活动锁 = created_seq 最大的锁（最后写入）。若其代不是历史最大代，
    说明出现了代回退（R6 违规）。
    """
    mine = [l for l in locks if l.permit_no == permit_no]
    if not mine:
        return None, False
    mine_sorted = sorted(mine, key=lambda l: l.created_seq)
    last = mine_sorted[-1]
    max_gen = max(l.generation for l in mine)
    regression = last.generation < max_gen
    # 也检查创建序上代是否单调不减
    seen_max = -1
    for l in mine_sorted:
        if l.generation < seen_max:
            regression = True
            break
        seen_max = max(seen_max, l.generation)
    return last, regression


def group_by_origin(
    registry: KeyRegistry, seals: list[Seal]
) -> dict[str, list[Seal]]:
    out: dict[str, list[Seal]] = {}
    for s in seals:
        try:
            origin = registry.origin_of(s.payload.key_id)
        except (KeyError, ValueError):
            continue
        out.setdefault(origin, []).append(s)
    return out


def independent_pair(
    registry: KeyRegistry, seals: list[Seal]
) -> tuple[Seal, Seal] | None:
    """在给定签封里找一对**见证独立**的签封，找不到返回 None。

    独立 = 控制人不同 **且** 根谱系原点不同。两条缺一不可：
      * 控制人不同 —— 对应“两个控制人分别签封”；
      * 原点不同   —— 对应“同一根来源的两份见证不能合并成有效许可”。

    仅凭原点不同是不够的：同一控制人的两把密钥若挂在两个原点下，
    仍是同一个人签的，不构成双人见证。因此这里同时约束二者。

    返回的一对按 (摘要, 摘要) 字典序最小化，保证判定确定性。
    """
    n = len(seals)
    best: tuple[Seal, Seal] | None = None
    for i in range(n):
        si = seals[i]
        try:
            ci = registry.controller_of(si.payload.key_id)
            oi = registry.origin_of(si.payload.key_id)
        except (KeyError, ValueError):
            continue
        for j in range(i + 1, n):
            sj = seals[j]
            try:
                cj = registry.controller_of(sj.payload.key_id)
                oj = registry.origin_of(sj.payload.key_id)
            except (KeyError, ValueError):
                continue
            if ci != cj and oi != oj:
                a, b = sorted((si, sj), key=lambda s: s.payload.digest())
                if best is None or (a.payload.digest(), b.payload.digest()) < (
                    best[0].payload.digest(), best[1].payload.digest()
                ):
                    best = (a, b)
    return best


# --------------------------------------------------------------------------- #
# 主判定
# --------------------------------------------------------------------------- #
def evaluate_permit(
    permit_no: str, facts: Facts, registry: KeyRegistry
) -> RuleDecision:
    lock, regression = active_lock(facts.locks, permit_no)
    if lock is None:
        return RuleDecision(
            permit_no, S_NO_LOCK, False, R_LOCK,
            reasons=["没有该许可的锁"],
        )
    gen = lock.generation
    trustee = lock.trustee
    resource = lock.resource

    if regression:
        return RuleDecision(
            permit_no, S_REGRESSION, False, R_UNIQUE_ACTIVE_GEN,
            active_generation=gen, trustee=trustee, resource=resource, lock=lock,
            reasons=["授权代出现回退，违反单活动代约束"],
        )

    # 撤销优先：管理员撤回身份后，任何签封都不能使其有效
    rev = is_revoked(facts.revokes, trustee, gen)
    if rev is not None:
        return RuleDecision(
            permit_no, S_REVOKED, False, R_NOT_REVOKED,
            active_generation=gen, trustee=trustee, resource=resource,
            lock=lock, revoke=rev,
            reasons=[f"存在覆盖 ({trustee}, gen={gen}) 的撤销"],
        )

    # 拆分签封：活动代的匹配签封 / 旧代签封
    stale: list[Seal] = []
    matched: list[Seal] = []
    invalid_mac: list[Seal] = []
    for s in facts.seals:
        if s.permit_no != permit_no:
            continue
        if s.generation != gen:
            stale.append(s)
            continue
        if s.trustee != trustee or s.resource != resource:
            continue
        if not seal_mac_ok(registry, s):
            invalid_mac.append(s)
            continue
        matched.append(s)

    by_origin = group_by_origin(registry, matched)
    origins = sorted(by_origin)
    pair = independent_pair(registry, matched)

    if pair is not None:
        # 两个不同控制人、且来自不同根谱系原点的签封齐备
        return RuleDecision(
            permit_no, S_VALID, True, None,
            active_generation=gen, trustee=trustee, resource=resource,
            lock=lock, pair=pair, stale_seals=tuple(stale),
            reasons=["两位不同控制人、不同根谱系原点的签封齐备"],
        )

    if len(matched) >= 2:
        # 有两份以上签封却凑不出“不同控制人且不同原点”的一对，即见证不独立
        same = tuple(sorted(matched, key=lambda s: s.payload.digest()))
        if len(origins) == 1:
            why = "两份以上签封来自同一根谱系原点，见证不独立"
        else:
            why = "签封虽跨原点，但没有两位不同控制人，见证不独立"
        return RuleDecision(
            permit_no, S_CONFLICT, False, R_INDEPENDENT_SEALS,
            active_generation=gen, trustee=trustee, resource=resource,
            lock=lock, same_origin=same, stale_seals=tuple(stale),
            reasons=[why],
        )

    reasons = []
    if not matched:
        reasons.append("尚无匹配的双根签封")
    if invalid_mac:
        reasons.append(f"{len(invalid_mac)} 份签封 MAC 校验失败")
    return RuleDecision(
        permit_no, S_INCOMPLETE, False, R_GENERATION_MATCH,
        active_generation=gen, trustee=trustee, resource=resource,
        lock=lock, stale_seals=tuple(stale), reasons=reasons or ["签封不完整"],
    )


def permits_in(facts: Facts) -> set[str]:
    return {l.permit_no for l in facts.locks}
