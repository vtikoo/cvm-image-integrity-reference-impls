#!/usr/bin/env python3
"""Offline policy and signed boot-input validation for this configuration."""

import argparse
import json
from pathlib import Path
import re
import uuid


def command_line(root_hash, data_uuid, hash_uuid):
    if not re.fullmatch(r"[0-9a-f]{64}", root_hash):
        raise ValueError("Expected a SHA-256 root hash")
    data_uuid, hash_uuid = str(uuid.UUID(data_uuid)), str(uuid.UUID(hash_uuid))
    if data_uuid == hash_uuid:
        raise ValueError("Data and hash partition identifiers must differ")
    return (
        "console=tty0 console=ttyS0,115200n8 "
        "root=/dev/mapper/root rootfstype=ext4 ro rootflags=ro,noload "
        f"roothash={root_hash} "
        f"systemd.verity_root_data=/dev/disk/by-partuuid/{data_uuid} "
        f"systemd.verity_root_hash=/dev/disk/by-partuuid/{hash_uuid} "
        "systemd.verity_root_options=panic-on-corruption "
        "rd.systemd.verity=1 rd.veritytab=0 systemd.volatile=overlay "
        "rd.systemd.gpt_auto=0 systemd.gpt_auto=0 rd.fstab=0 "
        "rd.shell=0 rd.emergency=reboot panic=30"
    )


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def finalize(root, image_urn):
    release = dict(
        line.split("=", 1) for line in (root / "etc/os-release").read_text().splitlines()
        if "=" in line
    )
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise ValueError("Only the Ubuntu 24.04 userspace is supported")
    if list((root / "var/lib/cloud/instances").glob("*")):
        raise ValueError("Source must be an unbooted generalized Marketplace image")
    if (root / "etc/machine-id").read_text().strip() not in ("", "uninitialized"):
        raise ValueError("Source has a provisioned machine-id")
    # Rebuild the disk without persistent writable or unverified boot mounts.
    fstab = []
    roots = 0
    for line in (root / "etc/fstab").read_text().splitlines():
        fields = line.split()
        if not fields or line.lstrip().startswith("#"):
            fstab.append(line)
            continue
        if len(fields) < 4:
            raise ValueError(f"Malformed fstab entry: {line}")
        if fields[1] == "/":
            roots += 1
        elif fields[1] not in ("/boot", "/boot/efi") and fields[2] != "swap":
            raise ValueError(f"Unsupported persistent mount: {fields[1]}")
    if roots != 1:
        raise ValueError(f"Expected one source root entry, found {roots}")
    write(root, "etc/fstab", "\n".join(fstab) + "\n")
    write(root, "etc/machine-id", "")
    for path in (root / "etc/ssh").glob("ssh_host_*_key*"):
        path.unlink()
    dbus_id = root / "var/lib/dbus/machine-id"
    if dbus_id.is_file() and not dbus_id.is_symlink():
        dbus_id.unlink()
    write(root, "etc/cloud/cloud.cfg.d/99-cvm-verity.cfg",
          'growpart:\n  mode: "off"\nresize_rootfs: false\n')
    write(root, "etc/systemd/journald.conf.d/cvm-verity.conf",
          "[Journal]\nStorage=volatile\nRuntimeMaxUse=64M\n")
    waagent = root / "etc/waagent.conf"
    text = waagent.read_text()
    for setting in ("ResourceDisk.Format", "ResourceDisk.EnableSwap"):
        text = re.sub(rf"^{re.escape(setting)}=.*\n?", "", text, flags=re.MULTILINE)
        text += f"\n{setting}=n\n"
    waagent.write_text(text)
    write(root, "etc/cvm-verity/source.json", json.dumps({
        "imageUrn": image_urn,
        "bootIntegration": "dracut-systemd-signed-uki",
        "rootPolicy": "dm-verity lower; volatile tmpfs overlay",
    }, indent=2) + "\n")
    # The EFI partition is deliberately not mounted after switch-root.
    write(root, "etc/systemd/system/cvm-root-policy.service",
          "[Unit]\nDescription=Check verified volatile root\n"
          "DefaultDependencies=no\nAfter=systemd-remount-fs.service\n"
          "Before=local-fs.target\nOnFailure=emergency.target\n"
          "[Service]\nType=oneshot\nExecStart=/usr/local/libexec/cvm-check-root /\n"
          "RemainAfterExit=yes\n[Install]\nRequiredBy=local-fs.target\n")
    target = root / "etc/systemd/system/local-fs.target.requires"
    target.mkdir(parents=True, exist_ok=True)
    (target / "cvm-root-policy.service").symlink_to("../cvm-root-policy.service")


def pe_section(path, section):
    import struct
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("Not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    offset = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    matches = []
    for index in range(count):
        header = offset + index * 40
        if data[header:header + 8].rstrip(b"\0").decode() == section:
            virtual_size, _, raw_size, raw_offset = struct.unpack_from("<IIII", data, header + 8)
            if virtual_size > raw_size or raw_offset + raw_size > len(data):
                raise ValueError("Truncated PE section")
            matches.append(data[raw_offset:raw_offset + virtual_size])
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {section} section")
    return matches[0]


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    finalize_args = sub.add_parser("finalize")
    finalize_args.add_argument("root", type=Path)
    finalize_args.add_argument("image_urn")
    cmd = sub.add_parser("cmdline")
    cmd.add_argument("root_hash")
    cmd.add_argument("data_uuid")
    cmd.add_argument("hash_uuid")
    check = sub.add_parser("check-uki")
    check.add_argument("uki")
    check.add_argument("cmdline", type=Path)
    check.add_argument("kernel", type=Path)
    check.add_argument("initrd", type=Path)
    args = parser.parse_args()
    if args.action == "finalize":
        finalize(args.root, args.image_urn)
    elif args.action == "cmdline":
        print(command_line(args.root_hash, args.data_uuid, args.hash_uuid))
    else:
        expected = {
            ".cmdline": args.cmdline.read_bytes(),
            ".linux": args.kernel.read_bytes(),
            ".initrd": args.initrd.read_bytes(),
        }
        for section, value in expected.items():
            actual = pe_section(args.uki, section)
            if section == ".cmdline":
                actual = actual.rstrip(b"\0")
            if actual != value:
                raise ValueError(f"Signed UKI {section} does not match the build input")


if __name__ == "__main__":
    main()
