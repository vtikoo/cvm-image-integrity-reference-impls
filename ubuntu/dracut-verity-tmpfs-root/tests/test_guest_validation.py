#!/usr/bin/env python3
"""Cloud-init acceptance must distinguish reported warnings from fatal errors."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "verify_guest", Path(__file__).resolve().parents[1] / "verify-guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class CloudInitTests(unittest.TestCase):
    def check(self, code=0, **changes):
        status = {"status": "done", "errors": [], "recoverable_errors": {}}
        status.update(changes)
        result = subprocess.CompletedProcess([], code, json.dumps(status), "")
        output = io.StringIO()
        with patch.object(guest.subprocess, "run", return_value=result), contextlib.redirect_stderr(output):
            accepted = guest.cloud_init_status()
        return accepted, output.getvalue()

    def test_accepts_completed_clean_status(self):
        status, output = self.check()
        self.assertEqual(status["status"], "done")
        self.assertEqual(output, "")

    def test_accepts_and_reports_recoverable_imds_warning(self):
        warnings = {"WARNING": ["Provisioning media unavailable; using IMDS"]}
        status, output = self.check(2, recoverable_errors=warnings)
        self.assertEqual(status["recoverable_errors"], warnings)
        self.assertIn("CVM_CLOUD_INIT_RECOVERABLE_WARNINGS", output)
        self.assertIn("using IMDS", output)

    def test_rejects_fatal_incomplete_and_malformed_status(self):
        for code, changes in (
            (1, {}), (3, {}), (0, {"status": "running"}),
            (2, {"errors": ["fatal"]}),
            (2, {"init": {"errors": ["fatal stage"]}}),
            (0, {"recoverable_errors": None}),
            (0, {"errors": None}),
        ):
            with self.subTest(code=code, changes=changes), self.assertRaises(RuntimeError):
                self.check(code, **changes)


class CollectorTests(unittest.TestCase):
    def test_checks_installed_collector_against_independent_build_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "usr/local/bin/azure-guest-attest"
            wrapper = root / "usr/local/bin/cvm-attest"
            record = root / "etc/cvm-verity/attestation-sdk.json"
            binary.parent.mkdir(parents=True)
            record.parent.mkdir(parents=True)
            binary.write_bytes(b"native collector fixture")
            wrapper.write_bytes(b"expanded PCR wrapper fixture")
            sdk = {"revision": "fixture", "patch": {"sha256": "patch fixture"},
                   "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
            record.write_text(json.dumps(sdk))
            expected = {"attestationSdk": dict(
                sdk, wrapperSha256=hashlib.sha256(wrapper.read_bytes()).hexdigest())}
            self.assertEqual(guest.verify_attestation_collector(expected, root),
                             expected["attestationSdk"])
            for target in (binary, wrapper, record):
                original = target.read_bytes()
                target.write_bytes(b"{}" if target == record else b"old collector or changed wrapper")
                with self.subTest(target=target), self.assertRaises(RuntimeError):
                    guest.verify_attestation_collector(expected, root)
                target.write_bytes(original)


class VerityMountTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "rootHash": "ab" * 32,
            "dataPartUuid": "10000000-0000-0000-0000-000000000001",
            "hashPartUuid": "10000000-0000-0000-0000-000000000002",
        }
        self.table = ("0 67108864 verity 1 8:2 8:3 4096 4096 8388608 1 sha256 "
                      + self.expected["rootHash"] + " cd").split()
        numbers = {"8:2": (8, 2), "8:3": (8, 3), "8:4": (8, 4),
                   "/dev/disk/by-partuuid/" + self.expected["dataPartUuid"]: (8, 2),
                   "/dev/disk/by-partuuid/" + self.expected["hashPartUuid"]: (8, 3)}
        self.devices = patch.object(guest, "device_number", side_effect=numbers.__getitem__)
        self.devices.start()
        self.addCleanup(self.devices.stop)

    def test_confirms_live_mount_without_scanning_disk_content(self):
        def policy(args, **kwargs):
            self.assertEqual(args, ["/usr/local/libexec/cvm-check-root", "/"])
            self.assertTrue(kwargs["check"])
            return subprocess.CompletedProcess(args, 0)

        with patch.object(guest, "run", return_value=" ".join(self.table)) as query, \
                patch.object(guest.subprocess, "run", side_effect=policy) as command:
            guest.verify_verity_mount(self.expected)
        query.assert_called_once_with("dmsetup", "table", "root")
        command.assert_called_once()

    def test_rejects_wrong_mapper_hash_or_devices_and_failed_mount_policy(self):
        for index, value in ((2, "linear"), (10, "sha512"), (11, "ff" * 32),
                             (4, "8:4"), (5, "8:4")):
            table = self.table.copy()
            table[index] = value
            with self.subTest(index=index), patch.object(guest, "run", return_value=" ".join(table)), \
                    patch.object(guest.subprocess, "run"), self.assertRaises(RuntimeError):
                guest.verify_verity_mount(self.expected)
        with patch.object(guest.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, ["/usr/local/libexec/cvm-check-root", "/"])), \
                self.assertRaises(subprocess.CalledProcessError):
            guest.verify_verity_mount(self.expected)


if __name__ == "__main__":
    unittest.main()
