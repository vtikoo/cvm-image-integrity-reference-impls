#!/usr/bin/env python3
"""Collect PCR-11 guest evidence and a MAA response; not a remote verifier."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

PCRS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12)
SDK = "/usr/local/bin/azure-guest-attest"
SDK_BUILD = Path("/etc/cvm-verity/attestation-sdk.json")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_options(endpoint, nonce):
    url = urlsplit(endpoint)
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and not url.fragment, "Supply an explicit HTTPS MAA endpoint without credentials or fragment")
    require(url.path in ("", "/", "/attest/AzureGuest"), "Use the AzureGuest endpoint, not TEE-only attestation")
    require(re.fullmatch(r"[0-9a-f]{64}", nonce) is not None,
            "Nonce must be exactly 32 bytes as lowercase hex, supplied by the verifier")


def decode(value):
    require(isinstance(value, str) and value, "Missing base64 evidence")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def validate_response(response, endpoint):
    require(isinstance(response, dict), "Expected an SDK JSON object")
    require(response.get("provider") == "maa" and response.get("endpoint") == endpoint,
            "Unexpected provider or endpoint; loopback/default fallback is not accepted")
    require(response.get("passed") is True and isinstance(response.get("token"), str)
            and response["token"], "MAA returned no token")
    request = json.loads(response["request"])
    require(isinstance(request, dict), "Expected an attestation request object")
    isolation = request["IsolationInfo"]
    require(isolation["Type"] in ("SevSnp", "Tdx") and isolation.get("Evidence"),
            "Confidential VM TEE evidence is required; Trusted Launch is not accepted")
    evidence = isolation["Evidence"]
    require(decode(evidence["Proof"]) and decode(evidence["RunTimeData"]), "Missing TEE proof or runtime data")
    tpm = request["TpmInfo"]
    require(tpm["PcrSet"] == list(PCRS) and all(type(index) is int for index in tpm["PcrSet"]),
            "Submitted PCR set must include exactly 0-8,11,12")
    entries = tpm["PCRs"]
    require([entry["Index"] for entry in entries] == list(PCRS)
            and all(type(entry["Index"]) is int for entry in entries),
            "Missing, duplicate or unexpected PCR values")
    values = {entry["Index"]: decode(entry["Digest"]) for entry in entries}
    require(all(len(value) == 32 for value in values.values()), "Expected SHA-256 PCR values")
    require(values[11] != bytes(32), "PCR 11 is unmeasured; UKI measurement evidence is required")
    for field in ("PcrQuote", "PcrSignature", "AikCert", "AikPub"):
        require(decode(tpm[field]), f"Missing TPM evidence: {field}")
    require(decode(request["TcgLogs"]), "Missing TPM event log for UKI measurement replay")
    token_parts = response["token"].split(".")
    require(len(token_parts) == 3 and all(token_parts), "Expected a signed MAA JWT")
    claims = json.loads(decode(token_parts[1]))
    require(isinstance(claims, dict), "Expected token claims object")
    covered = claims.get("x-ms-azurevm-attested-pcrs")
    require(isinstance(covered, list) and all(type(index) is int for index in covered)
            and len(covered) == len(set(covered)) and set(covered).issubset(PCRS),
            "Invalid token-reported PCR coverage")
    require(set(PCRS) - {12} <= set(covered), "Token omits required PCR 0-8 or 11 coverage")
    reported_values = claims.get("x-ms-azurevm-attested-pcr-values")
    require(isinstance(reported_values, dict)
            and set(reported_values) == {f"pcr{index}" for index in covered},
            "Missing or inconsistent token-reported PCR values")
    require(all(decode(reported_values[f"pcr{index}"]) == values[index] for index in covered),
            "Token-reported PCR values differ from submitted values")
    return request, values[11].hex()


def collect(endpoint, nonce, output, sdk=None, sdk_build=None):
    validate_options(endpoint, nonce)
    require(os.geteuid() == 0, "Run with sudo for TPM access")
    require((sdk is None) == (sdk_build is None), "Supply both SDK binary and build record overrides")
    sdk = SDK if sdk is None else str(sdk)
    sdk_build = SDK_BUILD if sdk_build is None else sdk_build
    require(Path(sdk).is_absolute() and Path(sdk_build).is_absolute(), "SDK paths must be absolute")
    require(not output.exists(), "Output directory already exists")
    output.mkdir(mode=0o700, parents=False)
    command = [
        sdk, "guest-attest", "--provider", "maa", "--endpoint", endpoint,
        "--user-data", "hex:" + nonce, "--pcr-index", ",".join(map(str, PCRS)),
        "--json", "--show-request",
    ]
    with (output / "sdk-stderr.log").open("x") as log:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=log,
                                timeout=300, check=False)
    (output / "sdk-response.json").write_text(result.stdout)
    require(result.returncode == 0, f"SDK failed ({result.returncode}); see {output}/sdk-stderr.log")
    response = json.loads(result.stdout)
    request, pcr11 = validate_response(response, endpoint)
    claims = json.loads(decode(response["token"].split(".")[1]))
    covered = claims["x-ms-azurevm-attested-pcrs"]
    missing = sorted(set(PCRS) - set(covered))
    if missing:
        print("ATTESTATION_TOKEN_PCR_COVERAGE_GAP=" + json.dumps(missing), file=sys.stderr)
    (output / "request.json").write_text(json.dumps(request, indent=2) + "\n")
    (output / "token.txt").write_text(response["token"] + "\n")
    receipt = {
        "result": "EVIDENCE_COLLECTED",
        "verification": "NOT_VERIFIED: verify MAA token and authenticated quote remotely",
        "requestedPcrs": list(PCRS),
        "reportedPcr11Sha256": pcr11,
        "nonceHex": nonce,
        "sdkBuild": json.loads(Path(sdk_build).read_text()),
        "sdkPathUntrusted": sdk,
        "tokenClaimsUnverified": {
            "reportedPcrs": covered,
            "reportedPcrValuesSha256": {
                str(index): decode(claims["x-ms-azurevm-attested-pcr-values"][f"pcr{index}"]).hex()
                for index in covered
            },
            "missingRequestedPcrs": missing,
            "requestedCoverageComplete": not missing,
        },
        "localCmdlineUntrusted": Path("/proc/cmdline").read_text().strip(),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--nonce", required=True, help="Verifier-generated 32-byte challenge in lowercase hex")
    parser.add_argument("--output", required=True, type=Path, help="New directory under /run; parent must exist")
    parser.add_argument("--sdk", type=Path, help="Explicit test SDK binary; requires --sdk-build")
    parser.add_argument("--sdk-build", type=Path, help="Build record for --sdk; both paths are locally untrusted")
    args = parser.parse_args()
    require(args.output.is_absolute() and Path("/run") in args.output.resolve().parents,
            "Store evidence in a new absolute directory under /run")
    os.umask(0o077)
    print(json.dumps(collect(args.endpoint, args.nonce, args.output, args.sdk, args.sdk_build), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ATTESTATION_COLLECTION_FAILED: {error}", file=sys.stderr)
        sys.exit(1)
