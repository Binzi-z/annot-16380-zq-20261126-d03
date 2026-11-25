"""通过 unittest 许可通道驱动 CLI，落地到 artifacts/ 与 report.{json,txt}。

运行：python -m unittest discover -s tests -v

注意：build_report 需要一个**干净**的工作目录（不自动清除旧状态）。
这里每次运行前先清空 artifacts/，避免与上次残留状态相互污染。
"""

import json
import shutil
import unittest
from pathlib import Path

from dutyid.__main__ import build_report, _summary


class TestEmitReport(unittest.TestCase):
    def test_emit(self):
        art = Path("artifacts")
        if art.exists():
            shutil.rmtree(art)
        report = build_report(art)
        Path("report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), "utf-8"
        )
        text = _summary(report).replace("✓", "[PASS]").replace("✗", "[FAIL]")
        Path("report.txt").write_text(text, "utf-8")
        print("\n" + text.encode("ascii", "replace").decode("ascii"))
        self.assertTrue(report["ok"], msg=report["sections"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
