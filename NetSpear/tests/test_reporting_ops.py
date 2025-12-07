import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from reporting import ReportGenerator


class TestReportingOperations(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.report_root = Path(self.temp_dir.name) / "Reports"
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.generator = ReportGenerator(base_dir=self.report_root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _touch(self, path: Path, mtime: float):
        path.write_text("dummy")
        os.utime(path, (mtime, mtime))

    def test_archive_moves_old_reports_only(self):
        old_file = self.report_root / "old.html"
        recent_file = self.report_root / "recent.html"
        now = time.time()
        self._touch(old_file, now - (10 * 86400))  # 10 days old
        self._touch(recent_file, now)

        moved = self.generator.archive_old_reports(days_old=7)

        archived_file = self.generator.archive_dir / old_file.name
        self.assertEqual(moved, 1)
        self.assertTrue(archived_file.exists())
        self.assertTrue(recent_file.exists(), "Recent file should not be archived")

    def test_clear_reports_respects_grace_and_removes_old(self):
        old_file = self.report_root / "old.json"
        recent_file = self.report_root / "recent.json"
        now = time.time()
        self._touch(old_file, now - 100)
        self._touch(recent_file, now)

        removed = self.generator.clear_all_reports()

        self.assertEqual(removed, 1)
        self.assertFalse(old_file.exists())
        self.assertTrue(recent_file.exists(), "Recent file should survive the grace window")


if __name__ == "__main__":
    unittest.main()
