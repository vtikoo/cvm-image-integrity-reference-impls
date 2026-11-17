#!/usr/bin/env python3
"""Real userspace component tests. No Marketplace disk, Azure, or VM boot."""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

RECIPE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("image_policy", RECIPE / "scripts/image_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
UKIFY = os.environ.get("UKIFY", "/usr/lib/systemd/ukify")
STUB = os.environ.get("EFI_STUB", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub")
DRACUT_BASE = os.environ.get("DRACUT_BASE", "/usr/lib/dracut")


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args}\n{result.stdout}")
    return result.stdout


class ComponentTests(unittest.TestCase):
    def test_real_squashfs_build_path_and_verity_cover_the_padded_partition(self):
        script = (RECIPE / "build-image.sh").read_text()
        start = script.index('if [[ "$root_filesystem" = squashfs ]]; then\n    mksquashfs')
        pack = script[start:script.index("veritysetup format", start)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "root"
            source.mkdir()
            payload = source / "workload"
            payload.write_text("verified workload\n")
            payload.chmod(0o750)
            if os.geteuid() == 0:
                os.chown(payload, 12345, 12346)
            (source / "alias").symlink_to("workload")
            os.link(payload, source / "hardlink")
            os.setxattr(payload, b"user.cvm-test", b"preserved")
            (root / "evidence").mkdir()
            (root / "staging.ext4").touch()
            data, hashes = root / "data", root / "hashes"
            data.write_bytes(bytes(8 * 1024 * 1024))
            hashes.write_bytes(bytes(1024 * 1024))
            env = dict(os.environ, run=str(root), data=str(data), data_mib="8", root_filesystem="squashfs")
            run("bash", "-euc", 'fail() { echo "$*" >&2; exit 1; }\nunmount_last() { :; }\n' + pack, env=env)
            self.assertIn("gzip", (root / "evidence/squashfs.txt").read_text())
            extracted = root / "extracted"
            run("unsquashfs", "-no-progress", "-processors", "1", "-d", str(extracted), str(data))
            self.assertEqual((extracted / "workload").read_bytes(), payload.read_bytes())
            self.assertEqual((extracted / "workload").stat().st_mode & 0o777, 0o750)
            self.assertEqual((extracted / "workload").stat().st_uid, payload.stat().st_uid)
            self.assertEqual((extracted / "workload").stat().st_gid, payload.stat().st_gid)
            self.assertEqual(os.readlink(extracted / "alias"), "workload")
            self.assertEqual((extracted / "hardlink").stat().st_ino, (extracted / "workload").stat().st_ino)
            self.assertEqual(os.getxattr(extracted / "workload", b"user.cvm-test"), b"preserved")
            formatted = run("veritysetup", "format", str(data), str(hashes),
                            "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096")
            root_hash = re.search(r"Root hash:\s+([0-9a-f]{64})", formatted)[1]
            run("veritysetup", "verify", str(data), str(hashes), root_hash)
            with data.open("r+b") as stream:
                stream.seek(4096 * 8)
                stream.write(b"\xff")
            result = subprocess.run(["veritysetup", "verify", str(data), str(hashes), root_hash],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Verification failed", result.stdout)
            before = data.read_bytes()
            result = subprocess.run(
                ["bash", "-euc", 'fail() { echo "$*" >&2; exit 1; }\nunmount_last() { :; }\n' + pack],
                env=dict(env, data_mib="0"), text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SquashFS image exceeds the data partition", result.stderr)
            self.assertEqual(data.read_bytes(), before)

    def test_real_verity_format_verify_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, hashes = root / "data", root / "hash"
            data.write_bytes(bytes(range(256)) * (4 * 1024 * 1024 // 256))
            hashes.write_bytes(bytes(1024 * 1024))
            formatted = run("veritysetup", "format", str(data), str(hashes),
                            "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096")
            root_hash = re.search(r"Root hash:\s+([0-9a-f]{64})", formatted)[1]
            run("veritysetup", "verify", str(data), str(hashes), root_hash)
            with data.open("r+b") as stream:
                stream.seek(4096 * 8)
                stream.write(b"\xff")
            result = subprocess.run(["veritysetup", "verify", str(data), str(hashes), root_hash],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Verification failed", result.stdout)
            wrong_hash = "0" * 64
            result = subprocess.run(["veritysetup", "verify", str(data), str(hashes), wrong_hash],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(result.returncode, 0)

    def test_real_dracut_systemd_and_signed_uki_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "dracut"
            shutil.copytree(DRACUT_BASE, base)
            module = base / "modules.d/91cvm-verity"
            shutil.copytree(RECIPE / "dracut/91cvm-verity", module)
            shutil.copy(RECIPE / "scripts/check-root.sh", module / "check-root.sh")
            shutil.copy(RECIPE / "scripts/mount-volatile-root.sh", module / "mount-volatile-root.sh")
            initrd = root / "initrd"
            (root / "empty").mkdir()
            env = dict(os.environ, dracutbasedir=str(base))
            output = run("dracut", "--force", "--no-kernel", "--no-hostonly",
                         "--no-hostonly-cmdline", "--conf", "/dev/null", "--confdir", str(root / "empty"),
                         "--modules", "systemd systemd-initrd systemd-veritysetup dracut-systemd cvm-verity",
                         "--gzip", str(initrd), env=env)
            self.assertIn("cvm-verity", output)
            inventory = run("lsinitrd", str(initrd))
            for name in ("systemd-veritysetup-generator", "systemd-veritysetup",
                         "systemd-volatile-root", "cvm-check-root", "cvm-verity-root.service",
                         "cvm-mount-volatile-root", "initrd-switch-root.service.d/cvm-verity.conf",
                         "systemd-volatile-root.service.d/cvm-verity.conf"):
                self.assertIn(name, inventory)
            self.assertNotIn("snap-bootstrap", inventory)
            key, cert = root / "key.pem", root / "cert.pem"
            run("openssl", "req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=Local component test/")
            signer = root / "signer.der"
            run("openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(signer))
            key.chmod(0o600)
            kernel = root / "vmlinuz"
            kernel.write_bytes(b"synthetic kernel payload: packaging test, not boot evidence\n")
            cmdline = root / "cmdline"
            uki = root / "cvm.efi"
            for filesystem in ("ext4", "squashfs"):
                with self.subTest(filesystem=filesystem):
                    cmdline.write_text(policy.command_line(
                        "ab" * 32, "11111111-2222-3333-4444-555555555555",
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", filesystem) + "\n")
                    run(UKIFY, "build", "--config", "/dev/null", "--linux", str(kernel),
                        "--initrd", str(initrd), "--stub", STUB, "--cmdline", "@" + str(cmdline),
                        "--uname", "test-only", "--os-release", "@/etc/os-release", "--no-sign-kernel",
                        "--secureboot-private-key", str(key), "--secureboot-certificate", str(cert),
                        "--output", str(uki))
                    run("sbverify", "--cert", str(cert), str(uki))
                    run("python3", str(RECIPE / "scripts/image_policy.py"), "check-uki",
                        str(uki), str(cmdline), str(kernel), str(initrd))
                    predicted = json.loads(run(
                        "python3", str(RECIPE / "scripts/predict-pcrs.py"), "--disable-secure-boot",
                        "--uki", str(uki), "--signer-der", str(signer), "--phase-path", "sysinit:ready"))
                    self.assertEqual(set(predicted["pcrs"]), {"4", "11", "12", "13"})
                    self.assertEqual(predicted["pcr7Policy"], "not-evaluated")
            tampered = root / "tampered.efi"
            tampered.write_bytes(uki.read_bytes().replace(b"ab" * 32, b"cd" * 32, 1))
            result = subprocess.run(["sbverify", "--cert", str(cert), str(tampered)],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            result = subprocess.run(
                ["python3", str(RECIPE / "scripts/predict-pcrs.py"), "--disable-secure-boot",
                 "--uki", str(tampered), "--signer-der", str(signer), "--phase-path", "sysinit:ready"],
                text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("sbverify failed", result.stderr)
            cmdline.write_text(cmdline.read_text().replace("ab" * 32, "cd" * 32))
            result = subprocess.run(["python3", str(RECIPE / "scripts/image_policy.py"), "check-uki",
                                     str(uki), str(cmdline), str(kernel), str(initrd)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(".cmdline does not match", result.stdout)


if __name__ == "__main__":
    unittest.main()
