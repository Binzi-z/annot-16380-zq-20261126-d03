"""端到端与单元测试（仅标准库 unittest）。

运行：
    python -m unittest discover -s tests -v
或：
    python tests/test_dutyid.py
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from dutyid import modelcheck, scale, scenarios
from dutyid.canonical import canonical_bytes, canonical_sha256, CanonicalError
from dutyid.crypto import KeyRegistry, SealPayload, fixture_key, key_id_of, seal_mac
from dutyid.engine import Engine, EngineError
from dutyid.evidence import (
    K_REVOKED,
    K_SAME_ORIGIN,
    minimize_facts,
    restore,
    violates,
)
from dutyid.model import fact_digest, Lock, Revoke, Seal
from dutyid.rules import S_CONFLICT, S_REVOKED, S_VALID, evaluate_permit, Facts
from dutyid.store import Store, StoreCorruption
from dutyid.verify import verify_evidence, verify_store


class TestCanonical(unittest.TestCase):
    def test_deterministic(self):
        a = {"b": 1, "a": [2, 3]}
        self.assertEqual(canonical_bytes(a), canonical_bytes({"a": [2, 3], "b": 1}))

    def test_reject_float(self):
        with self.assertRaises(CanonicalError):
            canonical_bytes({"x": 1.5})

    def test_reject_nonstring_key(self):
        with self.assertRaises(CanonicalError):
            canonical_bytes({1: "x"})

    def test_sha_stable(self):
        self.assertEqual(canonical_sha256({"a": 1}), canonical_sha256({"a": 1}))


class TestCrypto(unittest.TestCase):
    def test_origin_lineage(self):
        reg = KeyRegistry()
        reg.add_root("A")
        reg.add_root("B2", parent="A")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c2", "B2", "k2")
        self.assertEqual(reg.origin_of(key_id_of(fixture_key("k1"))), "A")
        self.assertEqual(reg.origin_of(key_id_of(fixture_key("k2"))), "A")

    def test_mac_binds_fields(self):
        k = fixture_key("k")
        p1 = SealPayload("P", 1, "T", "R", "kid", "n")
        p2 = SealPayload("P", 2, "T", "R", "kid", "n")
        self.assertNotEqual(seal_mac(k, p1.to_dict()), seal_mac(k, p2.to_dict()))


class TestRules(unittest.TestCase):
    def _reg(self):
        reg = KeyRegistry()
        reg.add_root("A"); reg.add_root("B")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c2", "B", "k2")
        return reg

    def _seal(self, reg, permit, gen, t, r, kid_label, nonce):
        kid = key_id_of(fixture_key(kid_label))
        _, _, key = reg.resolve(kid)
        p = SealPayload(permit, gen, t, r, kid, nonce)
        return Seal(p, seal_mac(key, p.to_dict()), 1)

    def test_two_independent_valid(self):
        reg = self._reg()
        lock = Lock("P", 1, "T", "R", 1)
        s1 = self._seal(reg, "P", 1, "T", "R", "k1", "n1")
        s2 = self._seal(reg, "P", 1, "T", "R", "k2", "n2")
        d = evaluate_permit("P", Facts(locks=[lock], seals=[s1, s2]), reg)
        self.assertTrue(d.valid)
        self.assertEqual(d.status, S_VALID)

    def test_same_origin_not_valid(self):
        reg = KeyRegistry()
        reg.add_root("A")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c2", "A", "k2")
        lock = Lock("P", 1, "T", "R", 1)
        s1 = self._seal(reg, "P", 1, "T", "R", "k1", "n1")
        s2 = self._seal(reg, "P", 1, "T", "R", "k2", "n2")
        d = evaluate_permit("P", Facts(locks=[lock], seals=[s1, s2]), reg)
        self.assertFalse(d.valid)
        self.assertEqual(d.status, S_CONFLICT)

    def test_revoked_dominates(self):
        reg = self._reg()
        lock = Lock("P", 1, "T", "R", 1)
        s1 = self._seal(reg, "P", 1, "T", "R", "k1", "n1")
        s2 = self._seal(reg, "P", 1, "T", "R", "k2", "n2")
        rev = Revoke("T", 1, 5)
        d = evaluate_permit("P", Facts(locks=[lock], seals=[s1, s2], revokes=[rev]), reg)
        self.assertFalse(d.valid)
        self.assertEqual(d.status, S_REVOKED)

    def test_revoke_all_generations(self):
        reg = self._reg()
        lock = Lock("P", 2, "T", "R", 2)
        rev = Revoke("T", None, 5)
        d = evaluate_permit("P", Facts(locks=[lock], revokes=[rev]), reg)
        self.assertEqual(d.status, S_REVOKED)

    def test_stale_gen_seal_ignored(self):
        reg = self._reg()
        lock2 = Lock("P", 2, "T", "R", 2)
        s1 = self._seal(reg, "P", 1, "T", "R", "k1", "n1")  # 旧代
        s2 = self._seal(reg, "P", 1, "T", "R", "k2", "n2")  # 旧代
        d = evaluate_permit("P", Facts(locks=[lock2], seals=[s1, s2]), reg)
        self.assertFalse(d.valid)


class TestStore(unittest.TestCase):
    def test_chain_integrity_detects_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(td)
            store.append_event("apply", {"permit_no": "P"})
            store.append_event("lock", {"permit_no": "P", "generation": 1})
            p = Path(td) / Store.EVENTS
            lines = p.read_text("utf-8").splitlines()
            obj = json.loads(lines[0])
            obj["payload"]["permit_no"] = "EVIL"
            lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False)
            p.write_text("\n".join(lines) + "\n", "utf-8")
            with self.assertRaises(StoreCorruption):
                list(store.iter_events())


class TestEvidence(unittest.TestCase):
    def _reg(self):
        reg = KeyRegistry()
        reg.add_root("A"); reg.add_root("B")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c2", "B", "k2")
        return reg

    def test_minimize_revoked(self):
        reg = self._reg()
        from dutyid.evidence import lock_fact, revoke_fact, FactRecord
        lock = Lock("P", 1, "T", "R", 1)
        rev = Revoke("T", 1, 5)
        cand = [lock_fact(lock), revoke_fact(rev)]
        minimal = minimize_facts(K_REVOKED, cand, reg)
        self.assertEqual(len(minimal), 2)
        self.assertTrue(violates(K_REVOKED, restore(minimal), reg))


class TestScenarios(unittest.TestCase):
    def test_scenario_revoke_first(self):
        with tempfile.TemporaryDirectory() as td:
            r = scenarios.scenario_revoke_first(os.path.join(td, "A"))
            self.assertTrue(r.ok, msg=f"{r.trace}\n{r.verify.problems}")
            self.assertNotIn("DUTY-A", r.recovered.valid)
            ev = r.recovered.conflicts["DUTY-A"]
            self.assertEqual(ev.conflict_kind, K_REVOKED)
            self.assertEqual(len(ev.facts), 2)

    def test_scenario_lost_ack_replay(self):
        with tempfile.TemporaryDirectory() as td:
            r = scenarios.scenario_lost_ack_replay(os.path.join(td, "B"))
            self.assertTrue(r.ok, msg=f"{r.trace}\n{r.verify.problems}")
            self.assertNotIn("DUTY-B", r.recovered.valid)
            ev = r.recovered.conflicts["DUTY-B"]
            self.assertEqual(ev.conflict_kind, K_SAME_ORIGIN)
            self.assertEqual(len(ev.facts), 3)
            # 旧代签封不应改变第 2 代判定
            self.assertEqual(r.recovered.decisions["DUTY-B"].active_generation, 2)
            # 陈旧清单：既应检出 valid/invalid 分歧，也应检出活动代分歧
            self.assertTrue(any("与重算不符" in f for f in r.verify.findings))
            self.assertTrue(any("活动代" in f for f in r.verify.findings))


class TestModelCheck(unittest.TestCase):
    def test_no_violations(self):
        mc = modelcheck.explore(max_depth=6)
        self.assertTrue(mc.ok, msg=[f"{v.invariant}:{v.detail}@{v.path}" for v in mc.violations])
        self.assertGreater(mc.states, 20)

    def test_growth_is_bounded(self):
        """深度增加应收敛到有限状态（小图），而不是爆炸。"""
        a = modelcheck.explore(max_depth=4)
        b = modelcheck.explore(max_depth=6)
        self.assertLessEqual(a.states, b.states)
        self.assertLess(b.states, 20_000, "小图状态数应远小于两万")


class TestScale(unittest.TestCase):
    def test_60k_isolation(self):
        r = scale.run()
        self.assertEqual(r.total_records, 60_000)
        self.assertTrue(r.ok, msg=[n for n, p in r.checks if not p])
        self.assertGreater(r.overreach, 0)
        self.assertEqual(set(r.actual_scope), set(r.expected_scope))


class TestAdversarial(unittest.TestCase):
    """针对关键安全属性的对抗性测试。"""

    def _two_controllers_two_roots(self):
        reg = KeyRegistry()
        reg.add_root("A"); reg.add_root("B")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c2", "B", "k2")
        return reg

    def _seal(self, reg, permit, gen, t, r, kid_label, nonce):
        kid = key_id_of(fixture_key(kid_label))
        _, _, key = reg.resolve(kid)
        p = SealPayload(permit, gen, t, r, kid, nonce)
        return Seal(p, seal_mac(key, p.to_dict()), 1)

    def test_same_controller_two_origins_not_independent(self):
        """同一控制人的两把密钥分别挂在 A、B 两原点 —— 仍是同一人，不能凑成有效。"""
        reg = KeyRegistry()
        reg.add_root("A"); reg.add_root("B")
        reg.add_controller_key("c1", "A", "k1")
        reg.add_controller_key("c1", "B", "k2")   # 同一控制人 c1，两把密钥
        lock = Lock("P", 1, "T", "R", 1)
        s1 = self._seal(reg, "P", 1, "T", "R", "k1", "n1")
        s2 = self._seal(reg, "P", 1, "T", "R", "k2", "n2")
        d = evaluate_permit("P", Facts(locks=[lock], seals=[s1, s2]), reg)
        self.assertFalse(d.valid, "同一控制人跨原点不应构成双人见证")
        self.assertEqual(d.status, S_CONFLICT)

    def test_lock_regression_prevented_and_detected(self):
        with tempfile.TemporaryDirectory() as td:
            reg = self._two_controllers_two_roots()
            eng = Engine(Store(td), reg)
            eng.apply("P", "T", "R")
            eng.lock("P", 2, "T", "R")
            with self.assertRaises(EngineError):
                eng.lock("P", 1, "T", "R")   # 回退被拒
            # 直接篡改磁盘注入一个低代锁（模拟外部/损坏），恢复应检出回退
            store = Store(td)
            store.write_lock(Lock("P", 1, "T", "R", 999))
            rec = eng.recover()
            self.assertEqual(rec.decisions["P"].status, "generation_regression")
            self.assertIn("P", rec.conflicts)

    def test_seal_tamper_detected(self):
        with tempfile.TemporaryDirectory() as td:
            reg = self._two_controllers_two_roots()
            eng = Engine(Store(td), reg)
            eng.apply("P", "T", "R")
            eng.lock("P", 1, "T", "R")
            s = eng.submit_seal("P", "c1", key_id_of(fixture_key("k1")), "n1")
            # 篡改磁盘上的签封（改 MAC），恢复时 MAC 校验应失败 -> 签封不参与授权
            path = Store(td).seal_path_by_digest(s.payload.digest())
            obj = json.loads(path.read_text("utf-8"))
            obj["mac"] = "00" * 32
            path.write_text(json.dumps(obj, ensure_ascii=False), "utf-8")
            rep = verify_store(Store(td), reg)
            self.assertFalse(rep.ok)
            self.assertTrue(any("MAC" in p for p in rep.problems))

    def test_evidence_minimal_ignores_decoys(self):
        """在撤销证据旁放无关签封/旧代签封，极小化应把它们排除。"""
        with tempfile.TemporaryDirectory() as td:
            reg = self._two_controllers_two_roots()
            eng = Engine(Store(td), reg)
            eng.apply("P", "T", "R")
            eng.lock("P", 1, "T", "R")
            eng.submit_seal("P", "c1", key_id_of(fixture_key("k1")), "n1")
            eng.submit_seal("P", "c2", key_id_of(fixture_key("k2")), "n2")
            eng.revoke("T", generation=1)
            rec = eng.recover()
            ev = rec.conflicts["P"]
            # 尽管磁盘有两份签封，撤销证据仍只应含 {锁, 撤销} 两条
            self.assertEqual(ev.conflict_kind, K_REVOKED)
            self.assertEqual(len(ev.facts), 2)
            self.assertEqual({f.kind for f in ev.facts}, {"lock", "revoke"})


class TestCli(unittest.TestCase):
    """端到端：驱动 __main__ 生成完整报告（在 unittest 许可下运行）。"""

    def test_full_report(self):
        from dutyid.__main__ import build_report
        with tempfile.TemporaryDirectory() as td:
            report = build_report(Path(td))
        self.assertIn("scenario_A_revoke_first", report["sections"])
        self.assertIn("scenario_B_lost_ack_replay", report["sections"])
        self.assertIn("exhaustive_interleavings", report["sections"])
        self.assertIn("scale_60k_org_isolation", report["sections"])
        # 全部小节通过
        for name, sec in report["sections"].items():
            self.assertTrue(sec.get("ok", False), msg=f"小节失败: {name} -> {sec}")
        # 场景 A 证据为 revoked/2 条
        secA = report["sections"]["scenario_A_revoke_first"]
        evA = secA["evidence"]["DUTY-A"]["evidence_results"]
        self.assertEqual(evA["conflict_kind"], "revoked")
        self.assertTrue(evA["minimal"])
        # 场景 B 证据为 same_origin/极小
        secB = report["sections"]["scenario_B_lost_ack_replay"]
        evB = secB["evidence"]["DUTY-B"]["evidence_results"]
        self.assertEqual(evB["conflict_kind"], "same_origin")
        self.assertTrue(evB["minimal"])
        # 规模：越界>0 且实际=精确
        c = report["sections"]["scale_60k_org_isolation"]["counts"]
        self.assertEqual(c["actual_scope"], c["expected_scope"])
        self.assertGreater(c["overreach"], 0)
        # 报告可 JSON 序列化
        json.dumps(report, ensure_ascii=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
