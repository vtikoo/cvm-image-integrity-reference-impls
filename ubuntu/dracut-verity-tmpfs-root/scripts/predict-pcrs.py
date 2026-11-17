#!/usr/bin/env python3
"""Offline SHA256 PCR4/7/11/12/13 predictions for direct-UKI systemd 255."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import ssl
import struct
import subprocess
import tempfile
import uuid

from image_policy import pe_section_data


BOOT_PROFILE = "azure-direct-uki-v1"
NO_SECURE_BOOT_PROFILE = "azure-direct-uki-no-secureboot-v1"
GLOBAL_GUID = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
SECURITY_GUID = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
VARIABLES = ("SecureBoot", "PK", "KEK", "db", "dbx")
MEASURED_SECTIONS = (
    ".linux", ".osrel", ".cmdline", ".initrd", ".splash", ".dtb",
    ".uname", ".sbat", ".pcrpkey",
)


def sha256(data):
    return hashlib.sha256(data).digest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate baseline key: {key}")
        result[key] = value
    return result


def signature_entries(data):
    offset = 0
    while offset < len(data):
        require(offset + 28 <= len(data), "Truncated EFI signature-list header")
        kind = uuid.UUID(bytes_le=data[offset:offset + 16])
        size, header_size, entry_size = struct.unpack_from("<III", data, offset + 16)
        require(kind in (X509_GUID, SHA256_GUID), "Unsupported EFI signature-list type")
        require(header_size == 0 and entry_size > 16 and size >= 28 + entry_size,
                "Unsupported or empty EFI signature list")
        end = offset + size
        require(end <= len(data) and (size - 28) % entry_size == 0,
                "Truncated or misaligned EFI signature list")
        require(kind != SHA256_GUID or entry_size == 48, "Invalid EFI SHA256 entry size")
        for start in range(offset + 28, end, entry_size):
            yield kind, data[start:start + 16], data[start + 16:start + entry_size]
        offset = end


def load_baseline(data, expected_sha256):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            "Baseline pin must be a lowercase SHA256 digest")
    require(sha256(data).hex() == expected_sha256, "Firmware baseline SHA256 pin mismatch")
    require(len(data) <= 256 * 1024, "Firmware baseline exceeds 256 KiB")
    profile = json.loads(data, object_pairs_hook=unique_object)
    require(isinstance(profile, dict) and set(profile) == {
        "schemaVersion", "bootProfile", "signatureOwnerGuid", "variables", "provenance",
    }, "Unexpected firmware baseline fields")
    require(type(profile["schemaVersion"]) is int and profile["schemaVersion"] == 1
            and profile["bootProfile"] == BOOT_PROFILE, "Unsupported firmware baseline model")
    require(isinstance(profile["provenance"], str) and profile["provenance"].strip(),
            "Baseline provenance must be recorded")
    require(isinstance(profile["signatureOwnerGuid"], str), "Invalid signature owner GUID")
    owner = uuid.UUID(profile["signatureOwnerGuid"])
    require(owner.int != 0, "Signature owner GUID must not be zero")
    values = profile["variables"]
    require(isinstance(values, dict) and set(values) == set(VARIABLES),
            "Baseline must contain exactly SecureBoot, PK, KEK, db and dbx")
    decoded = {}
    for name in VARIABLES:
        require(isinstance(values[name], str), f"Invalid {name} base64 value")
        decoded[name] = base64.b64decode(values[name], validate=True)
        require(decoded[name], f"Empty firmware variable: {name}")
        if name != "SecureBoot":
            list(signature_entries(decoded[name]))
    require(decoded["SecureBoot"] == b"\x01", "Baseline must have Secure Boot enabled")
    return decoded, owner


class PEImage:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:2] == b"MZ", "Truncated or invalid DOS header")
        pe = struct.unpack_from("<I", data, 60)[0]
        require(pe >= 64 and pe + 24 <= len(data) and data[pe:pe + 4] == b"PE\0\0",
                "Invalid PE header")
        machine, count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        table = optional + optional_size
        require(machine == 0x8664 and 0 < count <= 96 and optional_size >= 152
                and table + count * 40 <= len(data), "Unsupported or truncated PE32+ image")
        require(struct.unpack_from("<H", data, optional)[0] == 0x20b
                and struct.unpack_from("<H", data, optional + 68)[0] == 10
                and struct.unpack_from("<I", data, optional + 108)[0] >= 5,
                "Expected a PE32+ EFI application with a security directory")
        self.checksum = optional + 64
        self.security = optional + 144
        self.headers = struct.unpack_from("<I", data, optional + 60)[0]
        alignment = struct.unpack_from("<I", data, optional + 36)[0]
        require(512 <= alignment <= 65536 and alignment & (alignment - 1) == 0
                and table + count * 40 <= self.headers <= len(data)
                and self.headers % alignment == 0, "Invalid PE header size/alignment")
        self.certificate, certificate_size = struct.unpack_from("<II", data, self.security)
        require(self.certificate % 8 == 0 and certificate_size >= 8
                and self.certificate + certificate_size == len(data),
                "Expected an end-of-file Authenticode certificate table")
        length, revision, kind = struct.unpack_from("<IHH", data, self.certificate)
        require(8 < length <= certificate_size and (length + 7) // 8 * 8 == certificate_size
                and revision == 0x200 and kind == 2, "Expected exactly one PKCS7 signature")
        self.sections = {}
        raw_ranges, virtual_ranges = [], []
        for index in range(count):
            header = table + index * 40
            name = data[header:header + 8].rstrip(b"\0").decode("ascii")
            require(name and "\0" not in name and name not in self.sections,
                    "Invalid or duplicate PE section name")
            virtual_size, address, raw_size, offset = struct.unpack_from("<IIII", data, header + 8)
            self.sections[name] = (offset, raw_size, virtual_size)
            if raw_size:
                require(offset >= self.headers and offset % alignment == 0
                        and raw_size % alignment == 0 and offset + raw_size <= self.certificate,
                        "Invalid PE raw section bounds/alignment")
                raw_ranges.append((offset, offset + raw_size))
            if virtual_size:
                require(address >= self.headers, "PE virtual section overlaps headers")
                virtual_ranges.append((address, address + max(virtual_size, raw_size)))
        self.raw_end = self.headers
        for start, end in sorted(raw_ranges):
            require(start == self.raw_end, "Unsupported gapped or overlapping PE raw sections")
            self.raw_end = end
        for (_, end), (start, _) in zip(sorted(virtual_ranges), sorted(virtual_ranges)[1:]):
            require(end <= start, "Overlapping PE virtual sections")
        for name in (".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat", ".sdmagic"):
            require(name in self.sections and self.sections[name][2] > 0,
                    f"Missing required UKI section: {name}")
        marker = self.section(".sdmagic")
        require(re.fullmatch(rb"#### LoaderInfo: systemd-stub 255(?:\.[0-9]+)?(?:-[^ \x00]+)? ####\x00*",
                             marker) is not None, "Only the systemd-stub 255 measurement model is supported")

    def section(self, name):
        return pe_section_data(self.data, name)

    def authenticode(self):
        digest = hashlib.sha256()
        for start, end in (
            (0, self.checksum), (self.checksum + 4, self.security),
            (self.security + 8, self.headers), (self.headers, self.raw_end),
            (self.raw_end, self.certificate),
        ):
            digest.update(self.data[start:end])
        return digest.digest()


def checked_command(arguments, **kwargs):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    require(result.returncode == 0,
            f"{arguments[0]} failed: {(result.stderr + result.stdout).decode(errors='replace')[:2000]}")
    return result.stdout


def verify_signer(uki, certificate):
    der = checked_command(["openssl", "x509", "-inform", "DER", "-outform", "DER"], input=certificate)
    require(der == certificate, "Signer must be exactly one canonical DER certificate")
    with tempfile.TemporaryDirectory(prefix="cvm-pcr-signature-") as directory:
        root = Path(directory)
        (root / "cvm.efi").write_bytes(uki)
        (root / "signer.pem").write_text(ssl.DER_cert_to_PEM_cert(certificate))
        checked_command(["sbverify", "--cert", str(root / "signer.pem"), str(root / "cvm.efi")])


def variable(guid, name, value):
    encoded = name.encode("utf-16-le")
    return guid.bytes_le + struct.pack("<QQ", len(encoded) // 2, len(value)) + encoded + value


def certificate_list(owner, certificate):
    return (X509_GUID.bytes_le + struct.pack("<III", 44 + len(certificate), 0, 16 + len(certificate))
            + owner.bytes_le + certificate)


def phase_names(path):
    names = path.split(":") if path else []
    require(len(names) <= 16 and all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in names),
            "Invalid explicit PCR11 phase path")
    return names


def predict(uki, certificate, baseline, phase_path, *, secure_boot=True):
    image = PEImage(uki)
    if secure_boot:
        require(baseline is not None, "Secure Boot prediction requires a pinned firmware baseline")
        values, owner = baseline
        require(not any(kind == X509_GUID and value == certificate
                        for kind, _, value in signature_entries(values["db"])),
                "Custom signer is already in the baseline db")
    else:
        require(baseline is None, "Disabled Secure Boot prediction does not evaluate a firmware baseline")
    phases = phase_names(phase_path)
    events = {str(index): [] for index in ((4, 7, 11, 12, 13) if secure_boot else (4, 11, 12, 13))}
    pcrs = {index: bytes(32) for index in events}

    def extend(index, label, digest):
        key = str(index)
        pcrs[key] = sha256(pcrs[key] + digest)
        events[key].append({"label": label, "digest": digest.hex(), "pcrAfter": pcrs[key].hex()})

    extend(4, "Calling EFI Application from Boot Option",
           sha256(b"Calling EFI Application from Boot Option"))
    extend(4, "EV_SEPARATOR", sha256(bytes(4)))
    extend(4, "signed UKI Authenticode", image.authenticode())
    if secure_boot:
        for name in VARIABLES:
            value = values[name]
            if name == "db":
                value += certificate_list(owner, certificate)
            extend(7, name, sha256(variable(
                GLOBAL_GUID if name in ("SecureBoot", "PK", "KEK") else SECURITY_GUID, name, value)))
        extend(7, "EV_SEPARATOR", sha256(bytes(4)))
        extend(7, "db authority", sha256(variable(SECURITY_GUID, "db", owner.bytes_le + certificate)))
    for name in MEASURED_SECTIONS:
        if name in image.sections and image.sections[name][2]:
            extend(11, name + " name including NUL", sha256(name.encode("ascii") + b"\0"))
            extend(11, name + " VirtualSize bytes", sha256(image.section(name)))
    checkpoints = [{"phasePath": "", "value": pcrs["11"].hex()}]
    for index, name in enumerate(phases):
        extend(11, "phase " + name, sha256(name.encode("ascii")))
        checkpoints.append({"phasePath": ":".join(phases[:index + 1]), "value": pcrs["11"].hex()})
    return {
        "schemaVersion": 1, "bank": "sha256",
        "bootProfile": BOOT_PROFILE if secure_boot else NO_SECURE_BOOT_PROFILE,
        "pcr7Policy": "firmware-baseline" if secure_boot else "not-evaluated",
        "stubModel": "systemd-255", "phasePath": phase_path,
        "externalInputPolicy": "no-external-inputs",
        "pcrs": {index: value.hex() for index, value in pcrs.items()},
        "pcr11Checkpoints": checkpoints, "events": events,
        "scope": "Predictions only; not attestation verification or firmware baseline approval. "
                 "PCR12/13 assume no external inputs and no extensions by any producer; "
                 "these expectations neither disable inputs nor establish authenticated PCR coverage.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uki", required=True, type=Path)
    parser.add_argument("--signer-der", required=True, type=Path)
    parser.add_argument("--disable-secure-boot", action="store_true",
                        help="Omit PCR7 and firmware-baseline inputs; does not attest Secure Boot state")
    parser.add_argument("--firmware-baseline", type=Path)
    parser.add_argument("--firmware-baseline-sha256")
    parser.add_argument("--phase-path", required=True,
                        help="Expected ordered PCR11 phases, e.g. sysinit:ready; empty means UKI only")
    args = parser.parse_args()
    if args.disable_secure_boot:
        if args.firmware_baseline is not None or args.firmware_baseline_sha256 is not None:
            parser.error("--disable-secure-boot does not accept firmware-baseline inputs")
    elif args.firmware_baseline is None or args.firmware_baseline_sha256 is None:
        parser.error("Secure Boot prediction requires --firmware-baseline and --firmware-baseline-sha256")
    try:
        baseline = None
        if not args.disable_secure_boot:
            baseline_data = args.firmware_baseline.read_bytes()
            baseline = load_baseline(baseline_data, args.firmware_baseline_sha256)
        uki, certificate = args.uki.read_bytes(), args.signer_der.read_bytes()
        result = predict(uki, certificate, baseline, args.phase_path, secure_boot=not args.disable_secure_boot)
        verify_signer(uki, certificate)
        result["inputs"] = {
            "ukiSha256": sha256(uki).hex(), "signerDerSha256": sha256(certificate).hex(),
        }
        if not args.disable_secure_boot:
            result["inputs"]["firmwareBaselineSha256"] = sha256(baseline_data).hex()
    except (OSError, ValueError, struct.error) as error:
        parser.exit(2, f"PCR prediction failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
