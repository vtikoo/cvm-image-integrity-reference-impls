#!/usr/bin/env python3
"""Guest acceptance; supply build evidence retained independently of the guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
WORKLOAD = Path("/var/tmp/cvm-dracut-reboot-test")


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def device_number(value):
    if ":" in value and not value.startswith("/"):
        return tuple(int(part) for part in value.split(":"))
    stat = os.stat(value)
    return os.major(stat.st_rdev), os.minor(stat.st_rdev)


def cloud_init_status():
    result = subprocess.run(["cloud-init", "status", "--wait", "--format=json"],
                            text=True, capture_output=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    require(result.returncode in (0, 2), f"Cloud-init status failed: {result.returncode}")
    status = json.loads(result.stdout)
    require(isinstance(status, dict) and status.get("status") == "done",
            "Cloud-init has not completed")
    require(status.get("errors") == [], "Cloud-init has fatal errors")
    for stage in ("init", "init-local", "modules-config", "modules-final"):
        if stage in status:
            require(isinstance(status[stage], dict) and status[stage].get("errors") == [],
                    f"Cloud-init stage {stage} has fatal errors")
    warnings = status.get("recoverable_errors")
    require(isinstance(warnings, dict), "Missing cloud-init recoverable-error report")
    if result.returncode == 2 or warnings:
        print("CVM_CLOUD_INIT_RECOVERABLE_WARNINGS=" + json.dumps(warnings), file=sys.stderr)
    return status


def verify_attestation_collector(expected, root=Path("/")):
    sdk = expected["attestationSdk"]
    installed = json.loads((root / "etc/cvm-verity/attestation-sdk.json").read_text())
    provenance = {key: value for key, value in sdk.items() if key != "wrapperSha256"}
    require(installed == provenance, "Installed SDK provenance differs from build evidence")
    for name, field in (("azure-guest-attest", "binarySha256"), ("cvm-attest", "wrapperSha256")):
        digest = hashlib.sha256((root / "usr/local/bin" / name).read_bytes()).hexdigest()
        require(digest == sdk[field], f"Installed {name} differs from build evidence")
    return sdk


def verify_verity_mount(expected):
    subprocess.run(["/usr/local/libexec/cvm-check-root", "/"], check=True, stdout=sys.stderr)
    table = run("dmsetup", "table", "root").split()
    require(len(table) >= 13 and table[2:4] == ["verity", "1"], "Unexpected verity table")
    require(table[10] == "sha256" and table[11] == expected["rootHash"], "Live root hash differs from the UKI")
    data = "/dev/disk/by-partuuid/" + str(uuid.UUID(expected["dataPartUuid"]))
    hashes = "/dev/disk/by-partuuid/" + str(uuid.UUID(expected["hashPartUuid"]))
    require(device_number(table[4]) == device_number(data), "Wrong live data device")
    require(device_number(table[5]) == device_number(hashes), "Wrong live hash device")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_json", type=Path)
    parser.add_argument("signer_der", type=Path)
    parser.add_argument("--previous-boot-id")
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run as root")
    expected = json.loads(args.build_json.read_text())
    collector = None
    if "attestationSdk" in expected:
        collector = verify_attestation_collector(expected)
    else:
        print("CVM_ATTESTATION_COLLECTOR_NOT_CHECKED: legacy build record lacks SDK evidence",
              file=sys.stderr)
    require(run("uname", "-r") == expected["kernel"], "Kernel does not match build evidence")
    efivars = Path("/sys/firmware/efi/efivars")
    require((efivars / f"SecureBoot-{GUID}").read_bytes()[4:] == b"\x01", "Secure Boot is not enabled")
    require((efivars / f"SetupMode-{GUID}").read_bytes()[4:] == b"\x00", "Firmware is in Setup Mode")
    cert = args.signer_der.read_bytes()
    require(len(cert) > 256 and cert in (efivars / f"db-{DB_GUID}").read_bytes(),
            "The expected UKI signer is not in firmware db")
    require(Path("/sys/class/tpm/tpm0").exists(), "No TPM device")
    cmdline = Path("/proc/cmdline").read_text().split()
    for parameter in (
        "roothash=" + expected["rootHash"],
        "systemd.verity_root_data=/dev/disk/by-partuuid/" + expected["dataPartUuid"],
        "systemd.verity_root_hash=/dev/disk/by-partuuid/" + expected["hashPartUuid"],
        "root=/dev/mapper/root", "systemd.volatile=overlay",
    ):
        require(cmdline.count(parameter) == 1, f"Missing or duplicate expected boot parameter: {parameter}")
    verify_verity_mount(expected)
    require(run("systemctl", "is-active", "walinuxagent.service") == "active", "Azure guest agent is not active")
    require(run("systemctl", "--failed", "--no-legend", "--plain") == "", "Failed systemd units")
    cloud_init = cloud_init_status()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if args.previous_boot_id:
        require(boot_id != str(uuid.UUID(args.previous_boot_id)), "No real reboot occurred")
        require(not WORKLOAD.exists(), "Tmpfs workload survived reboot")
        workload = "absent after distinct boot"
    else:
        require(not WORKLOAD.exists(), "Workload path already exists; use a fresh acceptance run")
        mounts = run("findmnt", "-n", "-o", "OPTIONS", "--mountpoint", "/").split(",")
        upper = next(option.removeprefix("upperdir=") for option in mounts if option.startswith("upperdir="))
        before = os.statvfs(upper)
        require(before.f_bavail * before.f_frsize > 256 * 1024 * 1024,
                "Insufficient tmpfs space for the acceptance workload")
        WORKLOAD.mkdir()
        with (WORKLOAD / "payload").open("wb") as stream:
            for _ in range(128):
                stream.write(bytes(1024 * 1024))
            stream.flush()
            os.fsync(stream.fileno())
        for index in range(2048):
            (WORKLOAD / f"small-{index}").write_text("volatile\n")
        (WORKLOAD / "boot-id").write_text(boot_id)
        after = os.statvfs(upper)
        allocated = (before.f_bfree - after.f_bfree) * before.f_frsize
        inodes = before.f_ffree - after.f_ffree
        require(allocated >= 128 * 1024 * 1024, "Workload did not allocate at least 128 MiB of tmpfs")
        require(inodes >= 2050, "Workload did not allocate the expected tmpfs inodes")
        workload = {"allocatedBytes": allocated, "allocatedInodes": inodes}
    print(json.dumps({"result": "GUEST_ACCEPTANCE_PASSED", "bootId": boot_id,
                      "rootHash": expected["rootHash"], "workload": workload,
                      "attestationSdk": collector,
                      "cloudInit": cloud_init}, indent=2))


if __name__ == "__main__":
    main()
