#!/usr/bin/env python3
"""Offline predictor vectors, malformed inputs and independent systemd oracle."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid


RECIPE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RECIPE / "scripts"))
try:
    spec = importlib.util.spec_from_file_location("predict_pcrs", RECIPE / "scripts/predict-pcrs.py")
    predictor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(predictor)
finally:
    sys.path.pop(0)

OWNER = uuid.UUID("11111111-2222-3333-4444-555555555555")
CERTIFICATE = b"\x30\x03\x02\x01\x01"
MEASURE = Path("/usr/lib/systemd/systemd-measure")


def baseline_profile():
    import base64
    values = {"SecureBoot": b"\x01"}
    for name in ("PK", "KEK", "db", "dbx"):
        values[name] = predictor.certificate_list(OWNER, ("factory-" + name).encode())
    return {
        "schemaVersion": 1, "bootProfile": "azure-direct-uki-v1",
        "signatureOwnerGuid": str(OWNER), "provenance": "Synthetic test fixture; not firmware policy",
        "variables": {name: base64.b64encode(value).decode() for name, value in values.items()},
    }


def load_profile(profile=None):
    data = json.dumps(baseline_profile() if profile is None else profile).encode()
    return predictor.load_baseline(data, predictor.sha256(data).hex())


def synthetic_uki():
    sections = {
        ".sbat": b"sbat,1,SBAT Version,sbat,1,https://example.invalid\n",
        ".sdmagic": b"#### LoaderInfo: systemd-stub 255.4-test ####\0",
        ".osrel": b"ID=ubuntu\n\0", ".cmdline": b"roothash=" + b"ab" * 32 + b"\0",
        ".uname": b"test-kernel\0", ".initrd": b"synthetic archive",
        ".linux": b"synthetic kernel", ".pcrsig": b"not measured",
        ".pcrpkey": b"measured public key",
    }
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0x8664, len(sections))
    struct.pack_into("<H", data, 148, 240)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<I", data, 188, 512)
    struct.pack_into("<I", data, 212, 1024)
    struct.pack_into("<H", data, 220, 10)
    struct.pack_into("<I", data, 260, 16)
    for index, (name, value) in enumerate(sections.items()):
        header = 392 + index * 40
        data[header:header + len(name)] = name.encode()
        struct.pack_into("<IIII", data, header + 8, len(value), 4096 * (index + 1), 512, len(data))
        data.extend(value + bytes(512 - len(value)))
    data.extend(b"overlay!")
    struct.pack_into("<II", data, 296, len(data), 16)
    data.extend(struct.pack("<IHH", 16, 0x200, 2) + b"test_sig")
    return bytes(data)


class PredictionTests(unittest.TestCase):
    def test_disabled_secure_boot_omits_pcr7_without_changing_image_predictions(self):
        uki = synthetic_uki()
        enabled = predictor.predict(uki, CERTIFICATE, load_profile(), "sysinit:ready")
        disabled = predictor.predict(uki, CERTIFICATE, None, "sysinit:ready", secure_boot=False)
        self.assertEqual(disabled["bootProfile"], predictor.NO_SECURE_BOOT_PROFILE)
        self.assertEqual(disabled["pcr7Policy"], "not-evaluated")
        self.assertEqual(set(disabled["pcrs"]), {"4", "11", "12", "13"})
        self.assertEqual(set(disabled["events"]), {"4", "11", "12", "13"})
        for index in disabled["pcrs"]:
            self.assertEqual(disabled["pcrs"][index], enabled["pcrs"][index])
            self.assertEqual(disabled["events"][index], enabled["events"][index])
        self.assertEqual(disabled["pcr11Checkpoints"], enabled["pcr11Checkpoints"])
        with self.assertRaisesRegex(ValueError, "requires a pinned"):
            predictor.predict(uki, CERTIFICATE, None, "")
        with self.assertRaisesRegex(ValueError, "does not evaluate"):
            predictor.predict(uki, CERTIFICATE, load_profile(), "", secure_boot=False)

    def test_disabled_cli_requires_signature_but_no_firmware_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cvm.efi").write_bytes(synthetic_uki())
            (root / "signer.der").write_bytes(CERTIFICATE)
            args = ["predict-pcrs.py", "--disable-secure-boot", "--uki", str(root / "cvm.efi"),
                    "--signer-der", str(root / "signer.der"), "--phase-path", "sysinit:ready"]
            for failure in (None, ValueError("signature rejected")):
                with self.subTest(failure=failure), mock.patch.object(sys, "argv", args), \
                        mock.patch.object(predictor, "verify_signer", side_effect=failure) as verify, \
                        contextlib.redirect_stdout(io.StringIO()) as output, \
                        contextlib.redirect_stderr(io.StringIO()):
                    if failure:
                        with self.assertRaises(SystemExit) as caught:
                            predictor.main()
                        self.assertEqual(caught.exception.code, 2)
                        self.assertEqual(output.getvalue(), "")
                    else:
                        predictor.main()
                        result = json.loads(output.getvalue())
                        self.assertNotIn("7", result["pcrs"])
                        self.assertNotIn("firmwareBaselineSha256", result["inputs"])
                        for index in ("12", "13"):
                            self.assertEqual(result["pcrs"][index], "0" * 64)
                    verify.assert_called_once_with(synthetic_uki(), CERTIFICATE)
            for options in (
                ["--firmware-baseline", "unused.json"],
                ["--firmware-baseline-sha256", "0" * 64],
            ):
                with self.subTest(options=options), mock.patch.object(sys, "argv", args + options), \
                        contextlib.redirect_stdout(io.StringIO()) as output, \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    predictor.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
            for options in ([], ["--firmware-baseline", "unused.json"],
                            ["--firmware-baseline-sha256", "0" * 64]):
                with self.subTest(enabled_options=options), \
                        mock.patch.object(sys, "argv", [arg for arg in args if arg != "--disable-secure-boot"] + options), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    predictor.main()
                self.assertEqual(caught.exception.code, 2)

    def test_pcr7_serialized_efi_variable_vector_and_input_sensitivity(self):
        baseline = load_profile()
        result = predictor.predict(synthetic_uki(), CERTIFICATE, baseline, "sysinit:ready")
        self.assertEqual(result["pcrs"]["7"],
                         "6fbe2ec33bf330536564c35befe84e5e1aa147b0fa1e91deb7df30b7283b4521")
        self.assertEqual([event["label"] for event in result["events"]["7"]],
                         ["SecureBoot", "PK", "KEK", "db", "dbx", "EV_SEPARATOR", "db authority"])
        for name in predictor.VARIABLES[1:]:
            with self.subTest(variable=name):
                values = dict(baseline[0])
                values[name] += predictor.certificate_list(OWNER, b"another factory certificate")
                changed = predictor.predict(synthetic_uki(), CERTIFICATE, (values, OWNER), "sysinit:ready")
                self.assertNotEqual(result["pcrs"]["7"], changed["pcrs"]["7"])
                self.assertEqual(result["pcrs"]["4"], changed["pcrs"]["4"])
        changed = predictor.predict(synthetic_uki(), CERTIFICATE + b"x", baseline, "sysinit:ready")
        self.assertNotEqual(result["pcrs"]["7"], changed["pcrs"]["7"])
        other_owner = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        changed = predictor.predict(synthetic_uki(), CERTIFICATE, (baseline[0], other_owner), "sysinit:ready")
        self.assertNotEqual(result["pcrs"]["7"], changed["pcrs"]["7"])

    def test_authenticode_exclusions_and_raw_padding(self):
        uki = synthetic_uki()
        image = predictor.PEImage(uki)
        digest = image.authenticode()
        self.assertEqual(digest.hex(), "a734eef7b4764e0b44069373c405de733c86059fe4566f18932025dc42727105")
        for label, offset in (("checksum", image.checksum), ("signature", image.certificate + 8)):
            with self.subTest(excluded=label):
                changed = bytearray(uki)
                changed[offset] ^= 0x80
                self.assertEqual(digest, predictor.PEImage(bytes(changed)).authenticode())
        raw, _, virtual = image.sections[".linux"]
        for label, offset in (("raw padding", raw + virtual), ("overlay", image.certificate - 1)):
            with self.subTest(included=label):
                changed = bytearray(uki)
                changed[offset] ^= 0x80
                self.assertNotEqual(digest, predictor.PEImage(bytes(changed)).authenticode())
                original_pcr11 = predictor.predict(uki, CERTIFICATE, load_profile(), "")["pcrs"]["11"]
                changed_pcr11 = predictor.predict(bytes(changed), CERTIFICATE, load_profile(), "")["pcrs"]["11"]
                self.assertEqual(original_pcr11, changed_pcr11)

    def test_pcrsig_is_excluded_but_pcrpkey_is_measured_in_pcr11(self):
        uki = synthetic_uki()
        original = predictor.predict(uki, CERTIFICATE, load_profile(), "")
        for name in (".pcrsig", ".pcrpkey"):
            with self.subTest(section=name):
                changed = bytearray(uki)
                changed[predictor.PEImage(uki).sections[name][0]] ^= 1
                result = predictor.predict(bytes(changed), CERTIFICATE, load_profile(), "")
                self.assertNotEqual(original["pcrs"]["4"], result["pcrs"]["4"])
                self.assertEqual(original["pcrs"]["11"] == result["pcrs"]["11"], name == ".pcrsig")

    @unittest.skipUnless(MEASURE.is_file(), "Independent systemd-measure executable is unavailable")
    def test_pcr11_matches_systemd_measure_including_phase_checkpoints(self):
        uki = synthetic_uki()
        result = predictor.predict(uki, CERTIFICATE, load_profile(), "sysinit:ready")
        image = predictor.PEImage(uki)
        with tempfile.TemporaryDirectory() as directory:
            arguments = [str(MEASURE), "calculate", "--bank=sha256", "--json=short",
                         "--phase=", "--phase=sysinit", "--phase=sysinit:ready"]
            for name in predictor.MEASURED_SECTIONS:
                if name in image.sections:
                    path = Path(directory) / name[1:]
                    path.write_bytes(image.section(name))
                    arguments.append(f"--{name[1:]}={path}")
            oracle = json.loads(subprocess.check_output(arguments, stderr=subprocess.PIPE))
        expected = {entry.get("phase", ""): entry["hash"] for entry in oracle["sha256"]}
        self.assertEqual({entry["phasePath"]: entry["value"] for entry in result["pcr11Checkpoints"]},
                         expected)
        longer = predictor.predict(uki, CERTIFICATE, load_profile(), "enter-initrd:leave-initrd:sysinit:ready")
        self.assertNotEqual(result["pcrs"]["11"], longer["pcrs"]["11"])
        self.assertEqual(result["pcrs"]["4"], longer["pcrs"]["4"])
        self.assertEqual(result["pcrs"]["7"], longer["pcrs"]["7"])

    def test_rejects_bad_pin_and_malformed_firmware_baselines(self):
        data = json.dumps(baseline_profile()).encode()
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            predictor.load_baseline(data, "0" * 64)
        for change in (
            {"schemaVersion": True}, {"bootProfile": "shim-grub"},
            {"provenance": ""}, {"signatureOwnerGuid": str(uuid.UUID(int=0))},
            {"variables": {}}, {"variables": {**baseline_profile()["variables"], "db": "?"}},
            {"variables": {**baseline_profile()["variables"], "SecureBoot": "AA=="}},
            {"unrecognized": "value"},
        ):
            with self.subTest(change=change):
                profile = copy.deepcopy(baseline_profile())
                profile.update(change)
                with self.assertRaises(ValueError):
                    load_profile(profile)
        duplicate = data[:-1] + b', "schemaVersion": 1}'
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            predictor.load_baseline(duplicate, predictor.sha256(duplicate).hex())
        for malformed in (b"x", bytes(28), predictor.certificate_list(OWNER, b"x")[:-1]):
            with self.subTest(signature_list=malformed), self.assertRaises(ValueError):
                list(predictor.signature_entries(malformed))
        values, owner = load_profile()
        values["db"] += predictor.certificate_list(owner, CERTIFICATE)
        with self.assertRaisesRegex(ValueError, "already in"):
            predictor.predict(synthetic_uki(), CERTIFICATE, (values, owner), "")

    def test_rejects_unsupported_and_ambiguous_pe_images(self):
        uki = synthetic_uki()
        for label, offset, replacement in (
            ("truncated", 0, b"xx"), ("architecture", 132, b"\x4c\x01"),
            ("certificate bounds", 296, struct.pack("<I", len(uki) + 8)),
            ("certificate type", len(uki) - 10, b"\x01\x00"),
            ("duplicate section", 432, b".sbat\0\0\0"),
            ("overlapping raw data", 432 + 20, struct.pack("<I", 1024)),
            ("gapped raw data", 432 + 20, struct.pack("<I", 2048)),
            ("overlapping virtual data", 432 + 12, struct.pack("<I", 4096)),
            ("section data beyond file", 392 + 16, struct.pack("<I", len(uki) + 512)),
            ("measured zero-fill unsupported", 392 + 8 * 40 + 8, struct.pack("<I", 513)),
            ("unknown stub", uki.index(b"255.4-test"), b"256.4-test"),
        ):
            with self.subTest(case=label):
                changed = bytearray(uki)
                changed[offset:offset + len(replacement)] = replacement
                with self.assertRaises(ValueError):
                    predictor.predict(bytes(changed), CERTIFICATE, load_profile(), "")
        for data in (b"", b"MZ", uki[:400]):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                predictor.PEImage(data)
        for phase in ("sysinit:", "sysinit::ready", "ready\0", ":ready"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                predictor.predict(uki, CERTIFICATE, load_profile(), phase)

    def test_cli_emits_complete_predictions_only_after_signature_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cvm.efi").write_bytes(synthetic_uki())
            (root / "signer.der").write_bytes(CERTIFICATE)
            data = json.dumps(baseline_profile()).encode()
            (root / "baseline.json").write_bytes(data)
            args = ["predict-pcrs.py", "--uki", str(root / "cvm.efi"),
                    "--signer-der", str(root / "signer.der"),
                    "--firmware-baseline", str(root / "baseline.json"),
                    "--firmware-baseline-sha256", predictor.sha256(data).hex(),
                    "--phase-path", "sysinit:ready"]
            for failure in (None, ValueError("signature rejected"), FileNotFoundError("missing sbverify")):
                with self.subTest(failure=failure), mock.patch.object(sys, "argv", args), \
                        mock.patch.object(predictor, "verify_signer", side_effect=failure) as verify, \
                        contextlib.redirect_stdout(io.StringIO()) as output, \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    if failure:
                        with self.assertRaises(SystemExit) as caught:
                            predictor.main()
                        self.assertEqual(caught.exception.code, 2)
                        self.assertEqual(output.getvalue(), "")
                        self.assertIn(str(failure), errors.getvalue())
                    else:
                        predictor.main()
                        result = json.loads(output.getvalue())
                        self.assertEqual(set(result["pcrs"]), {"4", "7", "11", "12", "13"})
                        self.assertEqual(result["externalInputPolicy"], "no-external-inputs")
                        for index in ("12", "13"):
                            self.assertEqual(result["pcrs"][index], "0" * 64)
                            self.assertEqual(result["events"][index], [])
                        self.assertEqual(result["inputs"]["ukiSha256"], predictor.sha256(synthetic_uki()).hex())
                        self.assertTrue(all(len(value) == 64 for value in result["pcrs"].values()))
                    verify.assert_called_once_with(synthetic_uki(), CERTIFICATE)


if __name__ == "__main__":
    unittest.main()
