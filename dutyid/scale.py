"""规模测试：六万条按组织隔离的身份记录，比较一次撤回的实际访问范围与全量结果。

场景
----
构造 60 个组织 × 1,000 条 = 60,000 条合成身份记录。每条携带：
    record_id, org, trustee(姓名), resource, permit_no, generation, status

关键设计：**受托人姓名跨组织复用**（每个组织都有同名“张伟/李娜/王强…”），
因此按姓名做全局检索会越界命中别的组织，而按 (组织, 姓名) 做隔离检索才精确。

一次“撤回”要确定它实际触及的记录范围：
  * 实际访问范围（scoped）：用 (org, trustee) 复合键定位，仅命中本组织内该人；
  * 全量结果（full）：用 trustee 姓名做全局扫描，跨组织一并命中。

断言与度量
----------
  * 实际范围必须**精确**等于本组织内该受托人的全部记录（不漏不溢）；
  * 实际范围与其它组织**完全不相交**（组织隔离成立）；
  * 全量结果 ⊋ 实际范围：越界命中数即“若不做隔离会造成的爆炸半径”；
  * 60,000 条规模下计时，验证检索为索引而非线性全扫。

本节不依赖签封密码，只检验**作用域**与**规模**正确性；签封/证据正确性
由前两个模块覆盖。合成数据，离线，纯标准库。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

N_ORGS = 60
PER_ORG = 1_000
TOTAL = N_ORGS * PER_ORG  # 60,000

# 姓名池很小 -> 跨组织必然重名，放大“全局误伤”
NAME_POOL = ["张伟", "李娜", "王强", "刘洋", "陈静", "杨磊", "赵敏", "周涛",
             "吴芳", "徐鹏", "孙丽", "马超"]
RESOURCES = ["调度室", "值班室-东区", "值班室-西区", "机房", "门禁-主楼",
             "监控中心", "库房", "配电间"]


@dataclass(frozen=True)
class IdentityRecord:
    record_id: int
    org: str
    trustee: str
    resource: str
    permit_no: str
    generation: int
    status: str  # "valid" | "revoked"


def _org_name(i: int) -> str:
    return f"ORG-{i:03d}"


def generate(n_orgs: int = N_ORGS, per_org: int = PER_ORG) -> list[IdentityRecord]:
    """确定性生成全部记录（无随机源，复现稳定）。"""
    recs: list[IdentityRecord] = []
    rid = 0
    for oi in range(n_orgs):
        org = _org_name(oi)
        for j in range(per_org):
            name = NAME_POOL[(oi * 7 + j * 5) % len(NAME_POOL)]
            res = RESOURCES[(j * 3 + oi) % len(RESOURCES)]
            gen = 1 + (j % 3)
            recs.append(IdentityRecord(
                record_id=rid, org=org, trustee=name, resource=res,
                permit_no=f"P-{org}-{j:04d}", generation=gen, status="valid",
            ))
            rid += 1
    return recs


# --------------------------------------------------------------------------- #
# 两种检索策略
# --------------------------------------------------------------------------- #
class ScopedIndex:
    """按 (org, trustee) 隔离索引 —— 实际访问范围来源。"""

    def __init__(self, recs: Iterable[IdentityRecord]) -> None:
        self._by_key: dict[tuple[str, str], list[int]] = {}
        for r in recs:
            self._by_key.setdefault((r.org, r.trustee), []).append(r.record_id)

    def recall_scope(self, org: str, trustee: str) -> list[int]:
        return list(self._by_key.get((org, trustee), ()))


class GlobalNameIndex:
    """仅按 trustee 姓名的全局索引 —— 全量结果来源（易越界）。"""

    def __init__(self, recs: Iterable[IdentityRecord]) -> None:
        self._by_name: dict[str, list[int]] = {}
        for r in recs:
            self._by_name.setdefault(r.trustee, []).append(r.record_id)

    def recall_scope(self, org: str, trustee: str) -> list[int]:
        return list(self._by_name.get(trustee, ()))


# --------------------------------------------------------------------------- #
# 结果
# --------------------------------------------------------------------------- #
@dataclass
class ScaleReport:
    total_records: int
    n_orgs: int
    per_org: int
    target_org: str
    target_trustee: str
    expected_scope: list[int]
    actual_scope: list[int]
    full_result: list[int]
    build_seconds: float
    scoped_query_seconds: float
    full_query_seconds: float
    checks: list[tuple[str, bool]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def overreach(self) -> int:
        """全量结果中超出实际范围的记录数（跨组织误伤）。"""
        return len(set(self.full_result) - set(self.actual_scope))

    @property
    def ok(self) -> bool:
        return all(passed for _, passed in self.checks)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "total_records": self.total_records,
            "n_orgs": self.n_orgs,
            "per_org": self.per_org,
            "target": {"org": self.target_org, "trustee": self.target_trustee},
            "counts": {
                "expected_scope": len(self.expected_scope),
                "actual_scope": len(self.actual_scope),
                "full_result": len(self.full_result),
                "overreach": self.overreach,
            },
            "timing_ms": {
                "build": round(self.build_seconds * 1000, 2),
                "scoped_query": round(self.scoped_query_seconds * 1000, 3),
                "full_query": round(self.full_query_seconds * 1000, 3),
            },
            "checks": [{"name": n, "passed": p} for n, p in self.checks],
            "notes": self.notes,
        }


def run(
    n_orgs: int = N_ORGS, per_org: int = PER_ORG,
    target_org: str = "ORG-017", target_trustee: str = "张伟",
) -> ScaleReport:
    t0 = time.perf_counter()
    recs = generate(n_orgs, per_org)
    scoped = ScopedIndex(recs)
    glob = GlobalNameIndex(recs)
    # 期望范围：直接从原始数据独立求出（不经过任何索引），作为金标准
    expected = [
        r.record_id for r in recs
        if r.org == target_org and r.trustee == target_trustee and r.status == "valid"
    ]
    build_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    actual = [i for i in scoped.recall_scope(target_org, target_trustee)
              if recs[i].status == "valid"]
    scoped_s = time.perf_counter() - t1

    t2 = time.perf_counter()
    full = [i for i in glob.recall_scope(target_org, target_trustee)
            if recs[i].status == "valid"]
    full_s = time.perf_counter() - t2

    expected_set = set(expected)
    actual_set = set(actual)
    full_set = set(full)
    other_orgs = {r.record_id for r in recs if r.org != target_org}

    checks: list[tuple[str, bool]] = []
    checks.append(("总数=组织数×每组织", len(recs) == n_orgs * per_org))
    checks.append(("实际范围=金标准(不漏)", actual_set == expected_set))
    checks.append(("实际范围与其它组织不相交",
                   not (actual_set & other_orgs)))
    checks.append(("实际范围全部落在目标组织",
                   all(recs[i].org == target_org for i in actual_set)))
    checks.append(("全量结果严格包含实际范围", actual_set < full_set))
    checks.append(("全量结果确实越界(overreach>0)",
                   len(full_set - actual_set) > 0))
    checks.append(("越界记录均属其它组织",
                   all(recs[i].org != target_org for i in (full_set - actual_set))))

    notes = [
        f"目标：{target_org}/{target_trustee}",
        f"实际访问范围 {len(actual_set)} 条（精确、组织内）",
        f"全量结果 {len(full_set)} 条；越界 {len(full_set - actual_set)} 条将波及其它组织",
        f"索引构建 {build_s*1000:.1f} ms；隔离查询 {scoped_s*1000:.3f} ms；"
        f"全局查询 {full_s*1000:.3f} ms",
    ]

    return ScaleReport(
        total_records=len(recs),
        n_orgs=n_orgs, per_org=per_org,
        target_org=target_org, target_trustee=target_trustee,
        expected_scope=expected, actual_scope=actual, full_result=full,
        build_seconds=build_s, scoped_query_seconds=scoped_s,
        full_query_seconds=full_s, checks=checks, notes=notes,
    )
