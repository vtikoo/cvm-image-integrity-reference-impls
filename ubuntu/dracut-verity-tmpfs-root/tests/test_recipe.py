#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RECIPE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("image_policy", RECIPE / "scripts/image_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
INPUTS = json.loads((RECIPE / "inputs.json").read_text())
DATA_UUID = "11111111-2222-3333-4444-555555555555"
HASH_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, content in {
            "etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
            "etc/machine-id": "",
            "etc/fstab": "# source\nUUID=old / ext4 defaults 0 1\n"
                         "LABEL=UEFI /boot/efi vfat defaults 0 1\n"
                         "LABEL=BOOT /boot ext4 defaults 0 1\n/swapfile none swap sw 0 0\n",
            "etc/waagent.conf": "ResourceDisk.Format=y\nResourceDisk.EnableSwap=y\n",
            "etc/ssh/ssh_host_rsa_key": "fixture-private-host-key",
            "etc/ssh/ssh_host_rsa_key.pub": "fixture-public-host-key",
            "var/lib/dbus/machine-id": "old",
        }.items():
            policy.write(self.root, name, content)

    def test_finalization_preserves_no_writable_disk_mount(self):
        policy.finalize(self.root, INPUTS["imageUrn"])
        self.assertEqual((self.root / "etc/fstab").read_text(), "# source\n")
        self.assertEqual((self.root / "etc/machine-id").read_text(), "")
        self.assertFalse(list((self.root / "etc/ssh").glob("ssh_host_*")))
        self.assertFalse((self.root / "var/lib/dbus/machine-id").exists())
        self.assertIn("resize_rootfs: false", (self.root / "etc/cloud/cloud.cfg.d/99-cvm-verity.cfg").read_text())
        self.assertIn("ResourceDisk.EnableSwap=n", (self.root / "etc/waagent.conf").read_text())
        self.assertTrue((self.root / "etc/systemd/system/local-fs.target.requires/cvm-root-policy.service").exists())
        self.assertEqual(json.loads((self.root / "etc/cvm-verity/source.json").read_text())["imageUrn"], INPUTS["imageUrn"])

    def test_rejects_booted_source(self):
        policy.write(self.root, "var/lib/cloud/instances/instance/boot-finished", "")
        with self.assertRaisesRegex(ValueError, "unbooted"):
            policy.finalize(self.root, INPUTS["imageUrn"])

    def test_rejects_provisioned_machine_id(self):
        policy.write(self.root, "etc/machine-id", "0123456789abcdef0123456789abcdef\n")
        with self.assertRaisesRegex(ValueError, "machine-id"):
            policy.finalize(self.root, INPUTS["imageUrn"])

    def test_rejects_other_userspace(self):
        policy.write(self.root, "etc/os-release", "ID=ubuntu\nVERSION_ID=22.04\n")
        with self.assertRaisesRegex(ValueError, "24.04"):
            policy.finalize(self.root, INPUTS["imageUrn"])

    def test_rejects_additional_persistent_mounts(self):
        with (self.root / "etc/fstab").open("a") as stream:
            stream.write("UUID=state /var ext4 defaults 0 2\n")
        with self.assertRaisesRegex(ValueError, "persistent mount"):
            policy.finalize(self.root, INPUTS["imageUrn"])

    def test_rejects_missing_root_entry(self):
        policy.write(self.root, "etc/fstab", "# no root\n")
        with self.assertRaisesRegex(ValueError, "one source root"):
            policy.finalize(self.root, INPUTS["imageUrn"])

    def test_cmdline_binds_hash_and_both_partition_ids(self):
        values = policy.command_line("ab" * 32, DATA_UUID, HASH_UUID).split()
        self.assertIn("roothash=" + "ab" * 32, values)
        self.assertIn("root=/dev/mapper/root", values)
        self.assertIn("systemd.verity_root_data=/dev/disk/by-partuuid/" + DATA_UUID, values)
        self.assertIn("systemd.verity_root_hash=/dev/disk/by-partuuid/" + HASH_UUID, values)
        self.assertIn("systemd.volatile=overlay", values)
        self.assertIn("systemd.verity_root_options=panic-on-corruption", values)
        self.assertIn("rootflags=ro,noload", values)
        self.assertFalse(any("ignore-corruption" in arg or "check-at-most-once" in arg for arg in values))
        for bad in ("", "latest", "AB" * 32, "a" * 63):
            with self.subTest(root_hash=bad), self.assertRaises(ValueError):
                policy.command_line(bad, DATA_UUID, HASH_UUID)
        with self.assertRaises(ValueError):
            policy.command_line("ab" * 32, DATA_UUID, DATA_UUID)
        with self.assertRaises(ValueError):
            policy.command_line("ab" * 32, "LABEL=root", HASH_UUID)

    def test_pin_is_newer_cvm_not_generic_gen2(self):
        self.assertEqual(INPUTS["imageUrn"], "Canonical:ubuntu-24_04-lts:cvm:24.04.202610280")
        self.assertNotIn("latest", INPUTS["imageUrn"])


class ChrootResolverTests(unittest.TestCase):
    def test_build_mounts_require_private_propagation(self):
        script = (RECIPE / "build-image.sh").read_text()
        start = script.index("propagation=$(findmnt")
        guard = script[start:script.index("exec > ", start)]
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory)
            (tools / "findmnt").write_text(
                '#!/bin/bash\nprintf "%s\\n" "$TEST_PROPAGATION"\nexit "${TEST_FINDMNT_EXIT:-0}"\n')
            (tools / "findmnt").chmod(0o755)
            for propagation, status in (("private", "0"), ("shared", "0"),
                                        ("slave", "0"), ("", "0"), ("private", "1")):
                with self.subTest(propagation=propagation, status=status):
                    env = dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
                               TEST_PROPAGATION=propagation, TEST_FINDMNT_EXIT=status)
                    result = subprocess.run(
                        ["bash", "-eu", "-c", 'run=$1\nfail() { echo "$*" >&2; exit 1; }\n' + guard,
                         "test", directory], env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, propagation == "private" and status == "0")

    def test_readable_temporary_resolver_and_exact_original_restoration(self):
        script = (RECIPE / "build-image.sh").read_text()
        start = script.index('resolver="$run/root/etc/resolv.conf"')
        prepare = script[start:script.index('if test -e "$run/root/usr/sbin/policy-rc.d"', start)]
        start = script.index('rm "$resolver"')
        restore = script[start:script.index('chroot "$run/root" apt-get clean', start)]
        for original in ("file", "dangling-symlink", "absent"):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "root"
                (root / "etc").mkdir(parents=True)
                (root / "run").mkdir()
                resolver = root / "etc/resolv.conf"
                target = "../run/systemd/resolve/stub-resolv.conf"
                contents = "nameserver 192.0.2.53\n"
                if original == "file":
                    resolver.write_text(contents)
                    resolver.chmod(0o640)
                elif original == "dangling-symlink":
                    resolver.symlink_to(target)
                prefix = 'umask 077\nrun=$1\n'
                subprocess.run(["bash", "-eu", "-c", prefix + prepare, "test", directory], check=True)
                self.assertFalse(resolver.is_symlink())
                self.assertEqual(resolver.stat().st_mode & 0o777, 0o644)
                self.assertEqual(resolver.read_bytes(), Path("/etc/resolv.conf").read_bytes())
                subprocess.run(["bash", "-eu", "-c",
                                prefix + 'resolver="$run/root/etc/resolv.conf"\n' + restore,
                                "test", directory], check=True)
                self.assertFalse((root / "run/original-resolv.conf").is_symlink())
                self.assertFalse((root / "run/original-resolv.conf").exists())
                if original == "file":
                    self.assertEqual(resolver.read_text(), contents)
                    self.assertEqual(resolver.stat().st_mode & 0o777, 0o640)
                elif original == "dangling-symlink":
                    self.assertTrue(resolver.is_symlink())
                    self.assertEqual(os.readlink(resolver), target)
                else:
                    self.assertFalse(resolver.exists())
                    self.assertFalse(resolver.is_symlink())


class RootGuardTests(unittest.TestCase):
    def run_guard(self, change=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            tools = {
                "findmnt": """#!/bin/bash
case "$*" in
  *'FSTYPE --mountpoint'*) echo "${ROOT_FS:-overlay}";;
  *'OPTIONS --mountpoint'*) echo "${ROOT_OPTIONS:-rw,lowerdir=/lower,upperdir=/upper/u,workdir=/upper/w}";;
  *'FSTYPE -T'*) echo "${UPPER_FS:-tmpfs}";;
  *'TARGET -T'*'/upper/w') test "${TARGET_ERROR:-0}" = 0 || exit 1; echo "${WORK_TARGET:-/upper}";;
  *'TARGET -T'*) test "${TARGET_ERROR:-0}" = 0 || exit 1; echo /upper;;
  *'-S /dev/mapper/root'*) echo "ext4 ${LOWER_OPTIONS:-ro,noload}";;
  *) echo "Unexpected findmnt invocation: $*" >&2; exit 1;;
esac
""",
                "dmsetup": """#!/bin/bash
case "$1" in
table) echo "0 4096 ${DM_TYPE:-verity} 1 /dev/dm-1 /dev/dm-2";;
status) echo "0 4096 verity ${DM_STATUS:-V}";;
*) exit 1;;
esac
""",
                "swapon": '#!/bin/bash\ntest "${SWAP_ERROR:-0}" = 0 || exit 1\nprintf "%s" "${SWAP_DEVICE:-}"\n',
            }
            for tool, contents in tools.items():
                (path / tool).write_text(contents)
                (path / tool).chmod(0o755)
            env = dict(os.environ, PATH=str(path) + ":" + os.environ["PATH"])
            if change:
                env.update(change)
            return subprocess.run(["bash", str(RECIPE / "scripts/check-root.sh"), "/sysroot"],
                                  env=env, text=True, capture_output=True)

    def test_accepts_only_healthy_verity_and_tmpfs_overlay(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CVM_ROOT_POLICY_PASSED", result.stdout)

    def test_rejects_unsafe_or_corrupt_root(self):
        for change in (
            {"ROOT_FS": "ext4"}, {"ROOT_FS": "ext4\noverlay"},
            {"ROOT_OPTIONS": "ro,upperdir=/upper/u,workdir=/upper/w"},
            {"ROOT_OPTIONS": "rw"}, {"UPPER_FS": "ext4"}, {"UPPER_FS": "rootfs"},
            {"LOWER_OPTIONS": "rw"},
            {"DM_TYPE": "linear"}, {"DM_STATUS": "C"}, {"SWAP_DEVICE": "/dev/sdb1\n"},
            {"SWAP_ERROR": "1"}, {"TARGET_ERROR": "1"}, {"WORK_TARGET": "/different-tmpfs"},
        ):
            with self.subTest(change=change):
                result = self.run_guard(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("CVM_ROOT_POLICY_PASSED", result.stdout)
                self.assertIn("CVM_ROOT_POLICY_FAILED", result.stderr)

    def test_switch_root_requires_guard_not_just_ordering(self):
        contents = (RECIPE / "dracut/91cvm-verity/switch-root.conf").read_text()
        self.assertIn("Requires=cvm-verity-root.service", contents)
        self.assertIn("After=cvm-verity-root.service", contents)

    def test_volatile_setup_overrides_native_detached_backing_mounts(self):
        contents = (RECIPE / "dracut/91cvm-verity/volatile-root.conf").read_text()
        self.assertIn("ExecStart=\nExecStart=/usr/local/libexec/cvm-mount-volatile-root /sysroot", contents)
        self.assertIn("StandardError=journal+console", contents)
        module = (RECIPE / "dracut/91cvm-verity/module-setup.sh").read_text()
        self.assertIn("systemd-volatile-root.service.d/cvm-verity.conf", module)
        self.assertIn("inst_script \"$moddir/mount-volatile-root.sh\"", module)

    def test_volatile_setup_supports_shared_parent_mounts(self):
        helper = (RECIPE / "scripts/mount-volatile-root.sh").read_text()
        self.assertIn('mount --bind "$root" "$base/lower"', helper)
        self.assertIn('umount "$root"', helper)
        self.assertNotIn("mount --move", helper)
        module = (RECIPE / "dracut/91cvm-verity/module-setup.sh").read_text()
        self.assertIn("mount umount mkdir ln", module)


if __name__ == "__main__":
    unittest.main()
