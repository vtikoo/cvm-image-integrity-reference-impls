#!/usr/bin/env python3
import base64
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

RECIPE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("attest_guest", RECIPE / "attest-guest.py")
attest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attest)
ENDPOINT = "https://example.attest.azure.net"
NONCE = "ab" * 32


def b64(value):
    return base64.b64encode(value).decode()


def response_fixture(complete=False):
    tpm = {
        "PcrSet": list(attest.PCRS),
        "PCRs": [{"Index": index, "Digest": b64(bytes([index + 1]) * 32)} for index in attest.PCRS],
        "PcrQuote": b64(b"quote-fixture-not-cryptographically-verified"),
        "PcrSignature": b64(b"signature-fixture"),
        "AikCert": b64(b"certificate-fixture"),
        "AikPub": b64(b"key-fixture"),
    }
    request = {
        "TpmInfo": tpm, "TcgLogs": b64(b"event-log-fixture"),
        "IsolationInfo": {"Type": "SevSnp", "Evidence": {
            "Proof": b64(b"TEE-proof-fixture"), "RunTimeData": b64(b'{"user-data":"fixture"}'),
        }},
    }
    covered = list(attest.PCRS if complete else attest.PCRS[:-1])
    claims = {
        "x-ms-azurevm-attested-pcrs": covered,
        "x-ms-azurevm-attested-pcr-values": {
            f"pcr{index}": b64(bytes([index + 1]) * 32) for index in covered
        },
    }
    token = ".".join((b64(b'{"alg":"RS256"}'), b64(json.dumps(claims).encode()),
                      b64(b"fixture-signature-not-verified")))
    return {
        "provider": "maa", "endpoint": ENDPOINT, "passed": True,
        "token": token, "request": json.dumps(request),
    }


class AttestationTests(unittest.TestCase):
    def test_requests_exact_pcr_set_including_uki_pcr11_and_hardware_user_data(self):
        response = response_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "sdk.json"
            config.write_text('{"revision":"fixture"}')
            with patch.object(attest.os, "geteuid", return_value=0), \
                    patch.object(attest, "SDK_BUILD", config), \
                    patch.object(attest.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps(response))) as command:
                warning = io.StringIO()
                with contextlib.redirect_stderr(warning):
                    receipt = attest.collect(ENDPOINT, NONCE, root / "output")
            arguments = command.call_args.args[0]
            self.assertIn("guest-attest", arguments)
            self.assertEqual(arguments[arguments.index("--pcr-index") + 1], "0,1,2,3,4,5,6,7,8,11,12")
            self.assertEqual(arguments[arguments.index("--user-data") + 1], "hex:" + NONCE)
            self.assertNotIn("--client-payload", arguments)
            self.assertIn("--show-request", arguments)
            self.assertEqual(receipt["result"], "EVIDENCE_COLLECTED")
            self.assertTrue(receipt["verification"].startswith("NOT_VERIFIED"))
            self.assertEqual(receipt["reportedPcr11Sha256"], "0c" * 32)
            self.assertEqual(json.loads((root / "output/request.json").read_text())["TpmInfo"]["PcrSet"],
                             [0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12])
            self.assertEqual(receipt["tokenClaimsUnverified"]["missingRequestedPcrs"], [12])
            self.assertFalse(receipt["tokenClaimsUnverified"]["requestedCoverageComplete"])
            self.assertEqual(receipt["tokenClaimsUnverified"]["reportedPcrValuesSha256"]["7"], "08" * 32)
            self.assertIn("ATTESTATION_TOKEN_PCR_COVERAGE_GAP=[12]", warning.getvalue())

    def test_rejects_loopback_wrong_endpoint_and_token_absence(self):
        for change in ({"provider": "loopback"}, {"endpoint": "https://other.attest.azure.net"},
                       {"passed": False}, {"token": ""}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                attest.validate_response(dict(response_fixture(), **change), ENDPOINT)

    def test_rejects_missing_uki_measurement_or_tee_evidence(self):
        response = response_fixture()
        original = json.loads(response["request"])
        variants = []
        request = copy.deepcopy(original)
        request["IsolationInfo"]["Type"] = "TrustedLaunch"
        variants.append(request)
        request = copy.deepcopy(original)
        request["TpmInfo"]["PcrSet"].remove(11)
        variants.append(request)
        request = copy.deepcopy(original)
        next(entry for entry in request["TpmInfo"]["PCRs"] if entry["Index"] == 11)["Digest"] = b64(bytes(32))
        variants.append(request)
        request = copy.deepcopy(original)
        request["TpmInfo"]["PCRs"][-1]["Digest"] = b64(b"short")
        variants.append(request)
        request = copy.deepcopy(original)
        request["TpmInfo"]["PCRs"].append(request["TpmInfo"]["PCRs"][-1])
        variants.append(request)
        for field in ("PcrQuote", "PcrSignature", "AikCert", "AikPub"):
            request = copy.deepcopy(original)
            request["TpmInfo"][field] = ""
            variants.append(request)
        request = copy.deepcopy(original)
        request["TcgLogs"] = ""
        variants.append(request)
        for request in variants:
            with self.subTest(request=request), self.assertRaises(ValueError):
                attest.validate_response(dict(response, request=json.dumps(request)), ENDPOINT)

    def test_sdk_failure_retains_diagnostics_but_no_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.object(attest.os, "geteuid", return_value=0), \
                    patch.object(attest.subprocess, "run", return_value=SimpleNamespace(
                        returncode=2, stdout="no TEE report")), self.assertRaisesRegex(ValueError, "SDK failed"):
                attest.collect(ENDPOINT, NONCE, output)
            self.assertFalse((output / "receipt.json").exists())
            self.assertTrue((output / "sdk-stderr.log").exists())

    def test_rejects_unbound_or_invalid_challenge_and_non_maa_endpoint(self):
        for endpoint, nonce in (("http://example.attest.azure.net", NONCE),
                                ("https://example.attest.azure.net/attest/SevSnpVm", NONCE),
                                ("https://user:password@example.attest.azure.net", NONCE),
                                (ENDPOINT, ""), (ENDPOINT, "ab" * 31), (ENDPOINT, "AB" * 32)):
            with self.subTest(endpoint=endpoint, nonce=nonce), self.assertRaises(ValueError):
                attest.validate_options(endpoint, nonce)

    def test_sdk_revision_and_pcr_policy_are_pinned(self):
        sdk = json.loads((RECIPE / "inputs.json").read_text())["attestationSdk"]
        self.assertRegex(sdk["revision"], r"^[0-9a-f]{40}$")
        self.assertEqual(sdk["pcrs"], list(attest.PCRS))
        self.assertEqual(sdk["patch"]["sha256"],
                         hashlib.sha256((RECIPE / sdk["patch"]["file"]).read_bytes()).hexdigest())
        build = (RECIPE / "scripts/build-attestation.sh").read_text()
        self.assertIn('apply --check "$patch_path"', build)
        self.assertIn('apply "$patch_path"', build)
        self.assertIn('cargo test --locked', build)

    def test_pre_hash_gate_checks_installed_native_collector_and_wrapper(self):
        script = (RECIPE / "build-image.sh").read_text()
        start = script.index('python3 - "$run" "$recipe"')
        gate = script[start:script.index("\nPY", start) + 3]
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            binary = run / "root/usr/local/bin/azure-guest-attest"
            wrapper = run / "root/usr/local/bin/cvm-attest"
            installed = run / "root/etc/cvm-verity/attestation-sdk.json"
            evidence = run / "evidence"
            binary.parent.mkdir(parents=True)
            installed.parent.mkdir(parents=True)
            evidence.mkdir()
            binary.write_bytes(b"patched SDK fixture")
            wrapper.write_bytes((RECIPE / "attest-guest.py").read_bytes())
            sdk = {"binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "patch": {"sha256": "pinned patch fixture"}}
            installed.write_text(json.dumps(sdk))
            (evidence / "attestation-sdk.json").write_text(json.dumps(sdk))

            def execute():
                return subprocess.run(["bash", "-eu", "-c", 'run=$1\nrecipe=$2\n' + gate,
                                       "test", str(run), str(RECIPE)],
                                      capture_output=True, text=True)

            result = execute()
            self.assertEqual(result.returncode, 0, result.stderr)
            record = evidence / "attestation-installation.json"
            self.assertEqual(json.loads(record.read_text())["wrapperSha256"],
                             hashlib.sha256(wrapper.read_bytes()).hexdigest())
            record.unlink()
            for target in (binary, wrapper, installed):
                original = target.read_bytes()
                target.write_bytes(b"{}" if target == installed else b"stale installed code")
                with self.subTest(target=target):
                    result = execute()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(record.exists())
                    self.assertIn("ValueError", result.stderr)
                target.write_bytes(original)

    def test_complete_token_coverage_is_reported_without_verification_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "sdk.json"
            config.write_text('{"revision":"fixture"}')
            with patch.object(attest.os, "geteuid", return_value=0), \
                    patch.object(attest, "SDK_BUILD", config), \
                    patch.object(attest.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps(response_fixture(complete=True)))):
                receipt = attest.collect(ENDPOINT, NONCE, root / "output")
            self.assertTrue(receipt["tokenClaimsUnverified"]["requestedCoverageComplete"])
            self.assertEqual(receipt["tokenClaimsUnverified"]["missingRequestedPcrs"], [])
            self.assertTrue(receipt["verification"].startswith("NOT_VERIFIED"))

    def test_rejects_missing_required_token_coverage_and_wrong_raw_values(self):
        original = response_fixture()
        claims = json.loads(attest.decode(original["token"].split(".")[1]))
        variants = []
        for covered in ([0, 7], [0, 1, 2, 3, 4, 5, 6, 7, 8], [True], [0, 0], "0,7,11"):
            changed = copy.deepcopy(claims)
            changed["x-ms-azurevm-attested-pcrs"] = covered
            variants.append(changed)
        changed = copy.deepcopy(claims)
        changed["x-ms-azurevm-attested-pcr-values"]["pcr7"] = b64(b"wrong" * 6)
        variants.append(changed)
        changed = copy.deepcopy(claims)
        del changed["x-ms-azurevm-attested-pcr-values"]["pcr11"]
        variants.append(changed)
        for changed in variants:
            token = original["token"].split(".")
            token[1] = b64(json.dumps(changed).encode())
            with self.subTest(claims=changed), self.assertRaises(ValueError):
                attest.validate_response(dict(original, token=".".join(token)), ENDPOINT)
        with self.assertRaises(ValueError):
            attest.validate_response(dict(original, token="opaque"), ENDPOINT)

    def test_tmpfs_sdk_overrides_are_explicit_and_paired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "patched-sdk"
            build = root / "build.json"
            build.write_text('{"patch":{"sha256":"fixture"}}')
            with patch.object(attest.os, "geteuid", return_value=0), \
                    patch.object(attest.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps(response_fixture()))) as command, \
                    contextlib.redirect_stderr(io.StringIO()):
                receipt = attest.collect(ENDPOINT, NONCE, root / "output", sdk, build)
            self.assertEqual(command.call_args.args[0][0], str(sdk))
            self.assertEqual(receipt["sdkBuild"]["patch"]["sha256"], "fixture")
            with patch.object(attest.os, "geteuid", return_value=0), self.assertRaisesRegex(ValueError, "both"):
                attest.collect(ENDPOINT, NONCE, root / "other-output", sdk, None)


class MaaSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "maa_setup", RECIPE / "scripts/setup-maa-test-provider.py")
        cls.maa = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(RECIPE / "scripts"), *sys.path]):
            spec.loader.exec_module(cls.maa)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(
            subscription_id="11111111-2222-3333-4444-555555555555",
            resource_group="rg-maa-test", provider_name="example",
            location="westus3", evidence_directory=str(self.root / "evidence"),
            allow_custom_db=True)
        self.original = ("version=1.0;\nauthorizationrules {\n"
                         + self.maa.DB_DENIAL + "\n"
                         + "\n".join(f'[type=="{name}", value==false] => deny();'
                                     for name in self.maa.PRESERVED_CHECKS)
                         + "\n};\nissuancerules {};\n")
        self.candidate = self.original.replace(self.maa.DB_DENIAL, "", 1)
        self.tags = None
        self.calls = []

    def response(self, policy, issuer=ENDPOINT):
        payload = {"iss": issuer, "x-ms-policy": self.maa.policy_token(policy)}
        return {"token": ".".join((b64(b'{"alg":"RS256"}'),
                                   b64(json.dumps(payload).encode()), "fixture-signature"))}

    def fake_azure(self, run, subscription, label, *args, body=None):
        self.calls.append(label)
        if label == "existing-providers":
            return []
        if label == "create-provider":
            self.tags = json.loads(body)["tags"]
            return {}
        if label.startswith("provider-"):
            return {"id": f"/subscriptions/{subscription}/resourceGroups/rg-maa-test/"
                          "providers/Microsoft.Attestation/attestationProviders/example",
                    "tags": self.tags,
                    "properties": {"status": "Ready", "trustModel": "AAD", "attestUri": ENDPOINT}}
        self.assertIn("--resource", args)
        self.assertEqual(args[args.index("--resource") + 1], "https://attest.azure.net")
        if label == "default-policy":
            return self.response(self.original)
        if label == "set-policy":
            payload = self.maa.jwt_payload(body)
            self.assertEqual(self.maa.decode(payload["AttestationPolicy"]).decode(), self.candidate)
            return {}
        if label == "readback-policy":
            return self.response(self.candidate)
        self.fail("Unexpected Azure operation: " + label)

    def test_setup_preserves_default_and_publishes_only_exact_exception(self):
        with patch.object(self.maa, "azure", side_effect=self.fake_azure):
            result = self.maa.setup(self.args)
        run = Path(self.args.evidence_directory)
        self.assertEqual((run / "default-policy.txt").read_text(), self.original)
        self.assertEqual((run / "test-policy.txt").read_text(), self.candidate)
        self.assertEqual((run / "readback-policy.txt").read_text(), self.candidate)
        restored = self.maa.jwt_payload((run / "default-policy.jwt").read_text())
        self.assertEqual(self.maa.decode(restored["AttestationPolicy"]).decode(), self.original)
        self.assertEqual((run / "endpoint.txt").read_text().strip(), ENDPOINT)
        self.assertEqual(result["testPolicySha256"], hashlib.sha256(self.candidate.encode()).hexdigest())
        self.assertIn("does not pin", result["verification"])

    def test_existing_provider_is_never_updated(self):
        with patch.object(self.maa, "azure", return_value=[{"name": "example"}]) as azure:
            with self.assertRaisesRegex(self.maa.deploy.DeploymentError, "already exists"):
                self.maa.setup(self.args)
        self.assertEqual(azure.call_count, 1)
        self.assertFalse((Path(self.args.evidence_directory) / "setup.json").exists())

    def test_explicit_approval_is_required_before_any_azure_call(self):
        self.args.allow_custom_db = False
        with patch.object(self.maa, "azure") as azure:
            with self.assertRaisesRegex(self.maa.deploy.DeploymentError, "approval"):
                self.maa.setup(self.args)
        azure.assert_not_called()

    def test_default_policy_drift_is_rejected(self):
        for changed in (
            self.original.replace(self.maa.DB_DENIAL, ""),
            self.original + self.maa.DB_DENIAL,
            self.original.replace('[type=="secureboot", value==false] => deny();', ""),
        ):
            with self.subTest(policy=changed), self.assertRaises(self.maa.deploy.DeploymentError):
                self.maa.relax_custom_db(changed)

    def test_readback_mismatch_retains_failure_instead_of_success(self):
        def azure(*args, **kwargs):
            if args[2] == "readback-policy":
                return self.response(self.original)
            return self.fake_azure(*args, **kwargs)
        with patch.object(self.maa, "azure", side_effect=azure):
            with self.assertRaisesRegex(self.maa.deploy.DeploymentError, "exact requested bytes"):
                self.maa.setup(self.args)
        run = Path(self.args.evidence_directory)
        self.assertTrue(json.loads((run / "failure.json").read_text())["providerMayRemain"])
        self.assertFalse((run / "setup.json").exists())
        self.assertFalse((run / "endpoint.txt").exists())

    def test_policy_response_rejects_wrong_issuer_and_malformed_jwt(self):
        with self.assertRaisesRegex(self.maa.deploy.DeploymentError, "issuer"):
            self.maa.policy_text(self.response(self.original, "https://unexpected.attest.azure.net"),
                                 ENDPOINT)
        with self.assertRaisesRegex(self.maa.deploy.DeploymentError, "Malformed"):
            self.maa.policy_text({"token": "not-a-jwt"}, ENDPOINT)

    def test_azure_failure_preserves_private_stderr_without_echoing_it(self):
        with patch.object(self.maa.deploy, "azure_executable", return_value=["az"]), \
                patch.object(self.maa.deploy, "command", return_value=SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"private-error-fixture")):
            with self.assertRaises(self.maa.deploy.DeploymentError) as error:
                self.maa.azure(self.root, self.args.subscription_id, "failed-operation",
                               "rest", "--method", "get", "--url", ENDPOINT)
        self.assertNotIn("private-error-fixture", str(error.exception))
        self.assertEqual((self.root / "failed-operation.stderr").read_bytes(),
                         b"private-error-fixture")


if __name__ == "__main__":
    unittest.main()
