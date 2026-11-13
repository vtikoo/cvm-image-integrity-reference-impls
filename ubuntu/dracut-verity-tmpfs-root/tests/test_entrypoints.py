#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RECIPE = Path(__file__).resolve().parents[1]


class ShellEntrypointTests(unittest.TestCase):
    def test_deployment_and_cleanup_forward_paths_and_propagate_failures(self):
        for script, action, arguments in (
            ("deploy.sh", "deploy", ["--run-directory", "/private/run with spaces", "--plan"]),
            ("cleanup.sh", "cleanup", ["--run-directory", "/private/run with spaces", "--remove-run"]),
        ):
            for status in (0, 17):
                with self.subTest(script=script, status=status), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    python = root / "python3"
                    python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$FORWARDED"\n'
                                      'exit "$PYTHON_STATUS"\n')
                    python.chmod(0o755)
                    forwarded = root / "forwarded"
                    env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"],
                               FORWARDED=str(forwarded), PYTHON_STATUS=str(status))
                    result = subprocess.run(["bash", str(RECIPE / script), *arguments],
                                            cwd=directory, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(forwarded.read_text().splitlines(),
                                     [str(RECIPE / "scripts/deploy.py"), action, *arguments])

    def run_package_update(self, *, locked=False, permanent=False, expire=False):
        source = (RECIPE / "scripts/deployment-builder.sh").read_text()
        function = "update_package_indexes() {" + source.split(
            "update_package_indexes() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt = root / "apt-get"
            apt.write_text(
                '#!/bin/sh\n'
                'count=0\n'
                'if test -f "$work/count"; then count=$(cat "$work/count"); fi\n'
                'count=$((count + 1))\nprintf "%s" "$count" > "$work/count"\n'
                'if test "$PERMANENT" = 1; then echo "E: Repository unavailable" >&2; exit 100; fi\n'
                'if test "$LOCKED" = 1 || test "$count" = 1; then\n'
                '  echo "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 123" >&2\n'
                '  exit 100\n'
                'fi\n'
            )
            apt.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], work=str(root),
                       LOCKED=str(int(locked)), PERMANENT=str(int(permanent)))
            sleep = 'sleep() { SECONDS=$((SECONDS + 301)); }\n' if expire else 'sleep() { :; }\n'
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + function + sleep
                                     + "update_package_indexes\n"],
                                    env=env, capture_output=True, text=True)
            return result, int((root / "count").read_text())

    def test_builder_waits_for_package_index_lock(self):
        result, calls = self.run_package_update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, 2)
        self.assertIn("Waiting for the builder package-index lock", result.stderr)

    def test_builder_reports_non_lock_update_failure_without_retry(self):
        result, calls = self.run_package_update(permanent=True)
        self.assertEqual(result.returncode, 100)
        self.assertEqual(calls, 1)
        self.assertIn("Repository unavailable", result.stderr)

    def test_builder_lock_wait_is_bounded(self):
        result, calls = self.run_package_update(locked=True, expire=True)
        self.assertEqual(result.returncode, 100)
        self.assertEqual(calls, 2)
        self.assertIn("Could not get lock", result.stderr)


if __name__ == "__main__":
    unittest.main()
