"""Linux controller tests. Every Azure call goes to the local strict CLI double."""
import base64
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
PLAN = ["--subscription-id", SUBSCRIPTION, "--resource-group", "test-cvm-rg", "--prefix", "test-cvm"]


class BashControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cvm-bash-test-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = pathlib.Path(self.temporary.name)
        self.run = self.fixture / "run"
        self.run.mkdir()
        (self.run / "evidence").mkdir()
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        wrappers = {
            "az": f'#!/bin/bash\nexec python3 "{ROOT / "tests/mock_az.py"}" "$@"\n',
            "sleep": "#!/bin/bash\nexit 0\n",
        }
        for name, body in wrappers.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ["PATH"],
                        TEST_RUN=str(self.run), TEST_FIXTURE=str(self.fixture), MOCK_MODE="")
        self.config = json.loads(self.bash(["deploy.sh", *PLAN, "--plan"]).stdout)
        (self.run / "config.json").write_text(json.dumps(self.config))
        (self.fixture / "public.pub").write_text("ssh-ed25519 AAAATEST test\n")

    def bash(self, args, *, check=True, env=None):
        result = subprocess.run(["bash", str(ROOT / args[0]), *args[1:]], env=env or self.env,
                                text=True, capture_output=True, timeout=90)
        if check and result.returncode:
            self.fail(f"{args[0]} failed:\n{result.stdout}\n{result.stderr}")
        return result

    def function(self, command, *, mode="", check=True, prefix=""):
        env = dict(self.env, MOCK_MODE=mode)
        script = (f'set -euo pipefail; source "{ROOT}/scripts/bash/common.sh"; '
                  f'source "{ROOT}/scripts/bash/azure.sh"; RUN_DIR="$TEST_RUN"; load_config; '
                  f'{prefix}\n{command}')
        result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=20)
        if check and result.returncode:
            self.fail(f"Function failed:\n{result.stdout}\n{result.stderr}")
        return result

    def calls(self):
        path = self.fixture / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def certificate(self):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=Disposable controller test/", "-keyout", str(self.fixture / "test.key.pem"),
                        "-out", str(self.fixture / "public.pem")], check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-in", str(self.fixture / "public.pem"), "-outform", "DER",
                        "-out", str(self.fixture / "public.der")], check=True, capture_output=True)

    def managed_script(self):
        (self.fixture / "guest.sh").write_text("#!/bin/bash\necho TEST_PASSED\n")
        return 'managed_guest "$TEST_FIXTURE/guest.sh" test TEST_PASSED'

    def full_deployment(self, mode=""):
        self.certificate()
        run = self.fixture / "deployment"
        env = dict(self.env, TEST_RUN=str(run), MOCK_MODE=mode)
        result = self.bash(["deploy.sh", *PLAN, "--ssh-public-key", str(self.fixture / "public.pub"),
                            "--run-directory", str(run)], env=env, check=False)
        return result, run

    def test_plan_has_safe_names_and_no_azure_calls(self):
        other = json.loads(self.bash(["deploy.sh", *PLAN, "--plan"]).stdout)
        self.assertNotEqual(self.config["storageAccount"], other["storageAccount"])
        self.assertLessEqual(len(self.config["storageAccount"]), 24)
        self.assertEqual(self.config["maximumVms"], 2)
        self.assertEqual(self.calls(), [])

    def test_local_source_requires_an_existing_block_device(self):
        image = self.fixture / "not-a-block-device.raw"
        image.write_bytes(b"not a disk")
        for path, message in ((image, "Source must be a block device"),
                              (self.fixture / "missing.raw", "Source disk does not exist")):
            with self.subTest(path=path):
                result = self.bash(["scripts/Build-Image.sh"], check=False,
                                   env=dict(self.env, POC_SOURCE_DISK=str(path)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_local_kernel_input_requires_an_existing_directory(self):
        file = self.fixture / "not-a-directory"
        file.write_text("not a kernel tree")
        for path, message in ((file, "Kernel input root must be a directory"),
                              (self.fixture / "missing-root", "Kernel input root does not exist")):
            with self.subTest(path=path):
                result = self.bash(["scripts/custom-uki/Rebuild-SignedUki.sh", "stock", "key", "cert", "out", "kernel"],
                                   check=False, env=dict(self.env, POC_KERNEL_ROOT=str(path)))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_plan_matches_powershell_configuration(self):
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(ROOT / "Deploy.ps1"),
                                 "-SubscriptionId", SUBSCRIPTION, "-ResourceGroup", "test-cvm-rg",
                                 "-Prefix", "test-cvm", "-SshPublicKey", "unused.pub", "-Plan"],
                                check=True, capture_output=True, text=True)
        powershell = json.loads(result.stdout)
        actual = dict(self.config)
        for key in ("runId", "storageAccount"):
            powershell.pop(key)
            actual.pop(key)
        self.assertEqual(actual, powershell)

    def test_invalid_inputs_rejected_before_azure(self):
        for flag, value in (("--prefix", "../bad"), ("--subscription-id", "bad"),
                            ("--resource-group", "../../bad"), ("--vm-size", "Standard_D4s_v5"),
                            ("--location", "../bad")):
            with self.subTest(flag=flag):
                self.assertNotEqual(self.bash(["deploy.sh", *PLAN, flag, value, "--plan"], check=False).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_existing_or_repository_run_directory_rejected(self):
        for directory in (self.run, ROOT / "not-created-by-test",
                          ROOT.parents[1] / "not-created-by-test"):
            with self.subTest(directory=directory):
                result = self.bash(["deploy.sh", *PLAN, "--ssh-public-key", str(self.fixture / "public.pub"),
                                    "--run-directory", str(directory)], check=False)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_pending_exit_zero_and_marker_are_not_success(self):
        self.function(self.managed_script())
        state = json.loads((self.fixture / "state.json").read_text())
        self.assertEqual(state["commands"]["poc-test"]["polls"], 2)

    def test_managed_terminal_state_exit_and_marker_are_all_required(self):
        for mode in ("failed", "exit-code", "missing-marker"):
            with self.subTest(mode=mode):
                self.assertNotEqual(self.function(self.managed_script(), mode=mode, check=False).returncode, 0)

    def test_pending_startup_deadline_is_bounded(self):
        prefix = """
date() {
    if [[ ! -f "$TEST_FIXTURE/clock" ]]; then echo 0 > "$TEST_FIXTURE/clock"; fi
    local count
    count=$(< "$TEST_FIXTURE/clock")
    echo $((count+601)) > "$TEST_FIXTURE/clock"
    echo $((count+601))
}
"""
        result = self.function(self.managed_script(), mode="pending", prefix=prefix, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deadline", result.stderr)

    def test_private_material_rejected_before_managed_submission(self):
        (self.fixture / "guest.sh").write_text("-----BEGIN PRIVATE KEY-----\n")
        result = self.function('managed_guest "$TEST_FIXTURE/guest.sh" test TEST_PASSED', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_multichunk_artifact_round_trip(self):
        data = os.urandom(12000)
        (self.fixture / "artifact.bin").write_bytes(data)
        self.function('read_artifact /var/tmp/test-artifact "$TEST_FIXTURE/output.bin"')
        self.assertEqual((self.fixture / "output.bin").read_bytes(), data)
        self.assertGreater(len([call for call in self.calls() if "--method" in call and "put" in call]), 1)

    def test_artifact_hash_and_cross_chunk_consistency_required(self):
        (self.fixture / "artifact.bin").write_bytes(os.urandom(12000))
        for mode in ("tamper", "changed-chunk"):
            with self.subTest(mode=mode):
                result = self.function('read_artifact /var/tmp/test-artifact "$TEST_FIXTURE/output.bin"',
                                       mode=mode, check=False)
                self.assertNotEqual(result.returncode, 0)
                expected = "SHA256 verification" if mode == "tamper" else "changed during retrieval"
                self.assertIn(expected, result.stderr)
                self.assertFalse((self.fixture / "output.bin").exists())

    def test_artifact_overwrites_and_private_paths_rejected(self):
        (self.fixture / "output.bin").write_bytes(b"original")
        for command in ('read_artifact /var/tmp/test-artifact "$TEST_FIXTURE/output.bin"',
                        'read_artifact /root/signer/poc.key.pem "$TEST_FIXTURE/key.bin"'):
            self.assertNotEqual(self.function(command, check=False).returncode, 0)
        self.assertEqual((self.fixture / "output.bin").read_bytes(), b"original")
        self.assertEqual(self.calls(), [])

    def test_shared_guest_reader_rejects_private_key_contents(self):
        private = self.fixture / "disallowed.txt"
        private.write_text("-----BEGIN RSA PRIVATE KEY-----\nnot-real-key\n")
        encoded = base64.b64encode(str(private).encode()).decode()
        result = subprocess.run(["python3", str(ROOT / "scripts/Read-ArtifactChunk.py"), encoded, "0"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_public_profile_exact_certificate_and_overwrite_guard(self):
        self.certificate()
        self.function('new_security_profile "$TEST_FIXTURE/public.der" "$TEST_RUN/guest-security-profile.json"')
        profile = json.loads((self.run / "guest-security-profile.json").read_text())
        self.assertEqual(base64.b64decode(profile["uefiSettings"]["additionalSignatures"]["db"][0]["value"][0]),
                         (self.fixture / "public.der").read_bytes())
        self.assertNotEqual(self.function(
            'new_security_profile "$TEST_FIXTURE/public.der" "$TEST_RUN/guest-security-profile.json"',
            check=False).returncode, 0)
        self.assertNotEqual(self.function(
            'new_security_profile "$TEST_FIXTURE/test.key.pem" "$TEST_FIXTURE/rejected.json"',
            check=False).returncode, 0)

    def test_cleanup_ownership_mismatch_prevents_deletion(self):
        result = self.bash(["cleanup.sh", "--run-directory", str(self.run), "--remove-run"],
                           env=dict(self.env, MOCK_MODE="ownership"), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["group", "delete"] for call in self.calls()))

    def test_only_test_managed_commands_are_deleted(self):
        self.function("remove_test_commands", mode="policy-commands")
        deletes = [call for call in self.calls() if "delete" in call]
        self.assertEqual(len(deletes), 1)
        self.assertIn("/runCommands/poc-old?", deletes[0][deletes[0].index("--url")+1])

    def test_cleanup_requires_reboot_proof(self):
        result = self.bash(["cleanup.sh", "--run-directory", str(self.run)], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("delete" in call or "deallocate" in call for call in self.calls()))

    def test_full_removal_waits_and_records_absence(self):
        state = dict(group=True, vms={}, commands={})
        (self.fixture / "state.json").write_text(json.dumps(state))
        self.bash(["cleanup.sh", "--run-directory", str(self.run), "--remove-run"])
        summary = json.loads((self.run / "evidence/cleanup-summary.json").read_text())
        self.assertIs(summary["exists"], False)

    def test_full_mock_deployment_and_retention(self):
        result, run = self.full_deployment()
        self.assertEqual(result.returncode, 0, result.stdout+"\n"+result.stderr)
        summary = json.loads((run / "evidence/cleanup-summary.json").read_text())
        self.assertEqual(summary["targetPowerState"], "deallocated")
        state = json.loads((self.fixture / "state.json").read_text())
        self.assertEqual(state["vms"], {self.config["targetVm"]: "deallocated"})
        self.assertTrue(state["restarted"])
        self.assertIn("DEPLOYMENT_VERIFIED", result.stdout)

    def test_quota_failure_allocates_nothing(self):
        result, _ = self.full_deployment("quota")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["group", "create"] for call in self.calls()))

    def test_wrong_gallery_signer_stops_before_target_creation(self):
        result, _ = self.full_deployment("wrong-signer")
        self.assertNotEqual(result.returncode, 0)
        creates = [call for call in self.calls() if call[:2] == ["vm", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertNotIn("DEPLOYMENT_VERIFIED", result.stdout)

    def test_unchanged_boot_id_is_not_acceptance(self):
        result, run = self.full_deployment("same-boot")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((run / "evidence/cleanup-summary.json").exists())
        self.assertNotIn("DEPLOYMENT_VERIFIED", result.stdout)
        self.assertTrue(any(call[:2] == ["vm", "deallocate"] for call in self.calls()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
