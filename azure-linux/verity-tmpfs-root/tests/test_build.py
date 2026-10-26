"""Build-controller tests; no IC build, Docker daemon or Azure calls."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKOUT = ROOT.parents[1]
PINS = json.loads((ROOT / "inputs.json").read_text())


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="azl-build-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.base = self.directory / "base.qcow2"
        self.base.write_bytes(b"unbooted base fixture")
        self.public = self.directory / "public.pub"
        self.public.write_text("ssh-ed25519 AAAATEST disposable-test\n")
        self.run = self.directory / "run"
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        for name in ("git", "go", "docker"):
            wrapper = self.bin / name
            wrapper.write_text(
                f'#!/bin/bash\nexec python3 "{__file__}" --tool {name} "$@"\n'
            )
            wrapper.chmod(0o700)
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            BUILD_TEST_RUN=str(self.run),
            BUILD_TEST_CALLS=str(self.directory / "calls.jsonl"),
            BUILD_TEST_MODE="",
        )

    def build(self, *, run=None, mode=""):
        return subprocess.run(
            ["bash", str(ROOT / "build-image.sh"), str(self.base), str(self.public),
             str(run or self.run)],
            env=dict(self.env, BUILD_TEST_MODE=mode),
            text=True, capture_output=True, timeout=30,
        )

    def calls(self):
        path = self.directory / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_build_uses_pins_readonly_base_and_compiled_executable(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("BUILD_REFERENCE_IMAGE_OK", result.stdout)
        calls = self.calls()
        self.assertIn(["docker", "pull", PINS["dependencyContainer"]], calls)
        self.assertTrue(any(PINS["imageCustomizerCommit"] in call for call in calls))
        build = next(call for call in calls if "/repro/imagecustomizer" in call)
        self.assertIn(f"{self.base}:/input/base.qcow2:ro", build)
        self.assertEqual(build[build.index("--package-snapshot-time") + 1],
                         PINS["packageSnapshotTime"])
        self.assertEqual((self.run / "operator.pub").read_text(), self.public.read_text())
        self.assertEqual(self.base.read_bytes(), b"unbooted base fixture")
        self.assertTrue((self.run / "evidence/image.sha256").is_file())

    def test_private_key_is_rejected_before_tool_execution(self):
        self.public.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("never private", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_existing_and_repository_run_directories_are_rejected(self):
        self.run.mkdir()
        for run in (self.run, ROOT / "not-created-by-test", CHECKOUT / "not-created-by-test"):
            with self.subTest(run=run):
                self.assertNotEqual(self.build(run=run).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_wrong_compiler_is_rejected_before_network_operations(self):
        result = self.build(mode="wrong-go")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] in ("git", "docker") for call in self.calls()))

    def test_wrong_source_revision_is_rejected(self):
        result = self.build(mode="wrong-revision")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "docker" for call in self.calls()))

    def test_image_build_and_inspection_failures_cannot_report_success(self):
        for mode in ("build-failed", "missing-inspection-marker"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                run = pathlib.Path(temporary) / "run"
                self.env["BUILD_TEST_RUN"] = str(run)
                result = self.build(run=run, mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("BUILD_REFERENCE_IMAGE_OK", result.stdout)


def tool(name, arguments):
    run = pathlib.Path(os.environ["BUILD_TEST_RUN"])
    mode = os.environ["BUILD_TEST_MODE"]
    with open(os.environ["BUILD_TEST_CALLS"], "a") as stream:
        stream.write(json.dumps([name, *arguments]) + "\n")
    if name == "git":
        if arguments[0] == "clone":
            pathlib.Path(arguments[-1]).mkdir()
        elif arguments[-2:] == ["rev-parse", "HEAD"]:
            print("bad-revision" if mode == "wrong-revision" else PINS["imageCustomizerCommit"])
    elif name == "go":
        if arguments == ["version"]:
            print("go version wrong linux/amd64" if mode == "wrong-go"
                  else f'go version {PINS["goVersion"]} linux/amd64')
        else:
            pathlib.Path(arguments[arguments.index("-o") + 1]).write_bytes(b"compiled IC fixture")
    elif arguments[0] == "image":
        print("[]")
    elif arguments[0] == "run":
        if "/repro/imagecustomizer" in arguments:
            if mode == "build-failed":
                return 1
            (run / "root-volatile.raw").write_bytes(b"raw image fixture")
        elif mode != "missing-inspection-marker":
            print("ARTIFACT_INSPECTION_OK")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--tool":
        raise SystemExit(tool(sys.argv[2], sys.argv[3:]))
    unittest.main()
