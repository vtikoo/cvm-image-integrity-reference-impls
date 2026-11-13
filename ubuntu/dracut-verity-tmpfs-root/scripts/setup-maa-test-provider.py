#!/usr/bin/env python3
"""Create a dedicated AAD-trust AzureGuest provider with one test-only exception."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote, urlsplit
import uuid

import deploy

ARM_API = "2020-10-01"
POLICY_API = "2025-06-01"
RESOURCE_TYPE = "Microsoft.Attestation/attestationProviders"
PRESERVED_CHECKS = (
    "secureboot",
    "x-ms-azurevm-default-securebootkeysvalidated",
    "x-ms-azurevm-debuggersdisabled",
    "x-ms-azurevm-signingdisabled",
    "x-ms-azurevm-dbxvalidated",
)
DB_DENIAL = '[type=="x-ms-azurevm-dbvalidated", value==false] => deny();'


def decode(value):
    deploy.require(isinstance(value, str) and value, "Missing base64 policy data")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def jwt_payload(token):
    deploy.require(isinstance(token, str), "Missing policy JWT")
    parts = token.split(".")
    deploy.require(len(parts) == 3 and parts[0] and parts[1], "Malformed policy JWT")
    payload = json.loads(decode(parts[1]))
    deploy.require(isinstance(payload, dict), "Policy JWT payload must be an object")
    return payload


def policy_text(response, endpoint):
    # Policy readback is authenticated by HTTPS, not by this JWT decoder.
    outer = jwt_payload(response["token"])
    deploy.require(outer.get("iss") == endpoint, "Unexpected policy-response issuer")
    stored = jwt_payload(outer["x-ms-policy"])
    return decode(stored["AttestationPolicy"]).decode("utf-8")


def relax_custom_db(policy):
    deploy.require(policy.count(DB_DENIAL) == 1,
                   "Expected exactly one default custom-db denial; refusing other policy changes")
    for name in PRESERVED_CHECKS:
        clause = f'[type=="{name}", value==false] => deny();'
        deploy.require(policy.count(clause) == 1,
                       "Required default denial is missing or ambiguous: " + name)
    return policy.replace(DB_DENIAL, "", 1)


def policy_token(policy):
    def encode(value):
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    header = encode(b'{"alg":"none"}')
    payload = encode(json.dumps({"AttestationPolicy": encode(policy.encode("utf-8"))},
                                separators=(",", ":")).encode("utf-8"))
    return header + "." + payload + "."


def azure(run, subscription, label, *args, body=None):
    argv = [*deploy.azure_executable(), *args]
    if body is not None:
        path = run / (label + "-request.txt")
        deploy.private_write(path, body)
        argv += ["--body", "@" + deploy.azure_body_path(path)]
    argv += ["--subscription", subscription, "--only-show-errors", "--output", "json"]
    result = deploy.command(argv, check=False)
    deploy.private_write(run / (label + ".stdout"), result.stdout)
    deploy.private_write(run / (label + ".stderr"), result.stderr)
    deploy.require(result.returncode == 0,
                   f"Azure operation {label} failed (exit {result.returncode}); see private stderr evidence")
    return json.loads(result.stdout)


def setup(args):
    deploy.require(args.allow_custom_db, "Explicit --allow-custom-db approval is required")
    subscription = str(uuid.UUID(args.subscription_id))
    deploy.require(re.fullmatch(r"[a-z][a-z0-9]{2,23}", args.provider_name) is not None,
                   "Use a globally unique provider name: 3-24 lowercase letters/numbers, starting with a letter")
    run = deploy.validate_run_path(args.evidence_directory)
    run.mkdir(mode=0o700, parents=True)
    resource_id = (f"/subscriptions/{subscription}/resourceGroups/{args.resource_group}"
                   f"/providers/{RESOURCE_TYPE}/{args.provider_name}")
    arm_url = "https://management.azure.com" + quote(resource_id, safe="/") + "?api-version=" + ARM_API
    setup_id = str(uuid.uuid4())
    try:
        existing = azure(run, subscription, "existing-providers", "resource", "list",
                         "--resource-group", args.resource_group, "--resource-type", RESOURCE_TYPE)
        deploy.require(not any(item["name"].lower() == args.provider_name for item in existing),
                       "Provider already exists; refusing to change a shared or existing provider")
        body = {"location": args.location, "properties": {},
                "tags": {"purpose": "cvm-custom-db-attestation-test", "setupId": setup_id}}
        azure(run, subscription, "create-provider", "rest", "--method", "put", "--url", arm_url,
              "--headers", "Content-Type=application/json", body=json.dumps(body))
        deadline = time.monotonic() + 300
        index = 0
        while True:
            provider = azure(run, subscription, f"provider-{index}", "rest",
                             "--method", "get", "--url", arm_url)
            deploy.require(provider["id"].lower() == resource_id.lower()
                           and provider.get("tags", {}).get("setupId") == setup_id,
                           "Created provider identity/ownership readback mismatch")
            properties = provider["properties"]
            deploy.require(properties["trustModel"] == "AAD", "Only AAD-trust test providers are supported")
            if properties["status"] == "Ready":
                break
            deploy.require(properties["status"] == "NotReady" and time.monotonic() < deadline,
                           "Created provider did not become ready")
            time.sleep(5)
            index += 1
        endpoint = properties["attestUri"]
        parsed = urlsplit(endpoint)
        deploy.require(parsed.scheme == "https" and parsed.hostname
                       and parsed.hostname.endswith(".attest.azure.net")
                       and not parsed.username and not parsed.password and parsed.port is None
                       and not parsed.query and not parsed.fragment and not parsed.path,
                       "Expected an Azure public-cloud HTTPS attestation endpoint")
        policy_url = endpoint + "/policies/AzureGuest?api-version=" + POLICY_API
        response = azure(run, subscription, "default-policy", "rest", "--method", "get",
                         "--resource", "https://attest.azure.net", "--url", policy_url)
        original = policy_text(response, endpoint)
        deploy.private_write(run / "default-policy.txt", original)
        deploy.private_write(run / "default-policy.jwt", policy_token(original))
        candidate = relax_custom_db(original)
        deploy.private_write(run / "test-policy.txt", candidate)
        token = policy_token(candidate)
        deploy.private_write(run / "test-policy.jwt", token)
        azure(run, subscription, "set-policy", "rest", "--method", "put",
              "--resource", "https://attest.azure.net", "--url", policy_url,
              "--headers", "Content-Type=text/plain", body=token)
        response = azure(run, subscription, "readback-policy", "rest", "--method", "get",
                         "--resource", "https://attest.azure.net", "--url", policy_url)
        readback = policy_text(response, endpoint)
        deploy.private_write(run / "readback-policy.txt", readback)
        deploy.require(readback == candidate, "Published policy differs from the exact requested bytes")
        summary = {"result": "CUSTOM_DB_TEST_PROVIDER_READY", "resourceId": resource_id,
                   "endpoint": endpoint, "attestationType": "AzureGuest", "trustModel": "AAD",
                   "removedDenial": DB_DENIAL, "preservedChecks": list(PRESERVED_CHECKS),
                   "defaultPolicySha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
                   "testPolicySha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                   "verification": "TEST ONLY: does not pin the custom signer or expected image"}
        deploy.write_json(run / "setup.json", summary)
        deploy.private_write(run / "endpoint.txt", endpoint + "\n")
        return summary
    except (deploy.DeploymentError, ValueError, KeyError, OSError) as error:
        deploy.write_json(run / "failure.json",
                          {"result": "SETUP_FAILED", "resourceId": resource_id,
                           "error": str(error), "providerMayRemain": True})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", required=True, help="Existing dedicated test resource group")
    parser.add_argument("--provider-name", required=True)
    parser.add_argument("--location", default="westus3")
    parser.add_argument("--evidence-directory", required=True)
    parser.add_argument("--allow-custom-db", action="store_true", required=True,
                        help="Approve removing only the default dbvalidated=false denial for this test")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(setup(args), indent=2))
    except (deploy.DeploymentError, ValueError, KeyError, OSError) as error:
        print("MAA_TEST_SETUP_FAILED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
