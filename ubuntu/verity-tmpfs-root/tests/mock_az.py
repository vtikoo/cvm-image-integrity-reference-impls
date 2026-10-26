#!/usr/bin/env python3
"""Azure CLI double: deliberately rejects every unimplemented operation."""
import base64
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import urllib.parse

run = pathlib.Path(os.environ["TEST_RUN"])
fixture = pathlib.Path(os.environ["TEST_FIXTURE"])
args = sys.argv[1:]
mode = os.environ.get("MOCK_MODE", "")
with (fixture / "calls.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\n")
config = json.loads((run / "config.json").read_text()) if (run / "config.json").exists() else {}
state_file = fixture / "state.json"
state = json.loads(state_file.read_text()) if state_file.exists() else dict(group=False, vms={}, commands={})


def value(flag):
    return args[args.index(flag) + 1]


def emit(result=None):
    state_file.write_text(json.dumps(state))
    if result is not None:
        print(json.dumps(result))
    sys.exit(0)


def resource_id(kind, name):
    return (f"/subscriptions/{config['subscriptionId']}/resourceGroups/{config['resourceGroup']}"
            f"/providers/{kind}/{name}")


def vm_model(name):
    helper = name == config["helperVm"]
    return dict(name=name, id=resource_id("Microsoft.Compute/virtualMachines", name),
                tags=dict(session=config["runId"], purpose="canonical-manifest-tmpfs",
                          role="helper" if helper else "reference"),
                identity=dict(principalId="00000000-0000-0000-0000-000000000001"),
                securityProfile=dict(securityType="ConfidentialVM",
                                     uefiSettings=dict(secureBootEnabled=True, vTpmEnabled=True)),
                networkProfile=dict(networkInterfaces=[dict(id=resource_id("Microsoft.Network/networkInterfaces", name+"-nic"))]),
                storageProfile=dict(osDisk=dict(managedDisk=dict(
                    id=resource_id("Microsoft.Compute/disks", name+"-os"),
                    securityProfile=dict(securityEncryptionType="VMGuestStateOnly")))))


def artifact(path):
    if path.endswith("custom-uki-build.json"):
        certificate = (fixture / "public.der").read_bytes()
        return json.dumps(dict(signature_verified_with_poc_certificate=True,
                               certificate_sha256=hashlib.sha256(certificate).hexdigest(),
                               signed_uki_sha256="b"*64,
                               build_directory="/var/tmp/canonical-build/custom-uki-1")).encode()
    if path.endswith("signer.der"):
        return (fixture / "public.der").read_bytes()
    if path.endswith("build-evidence.tar.gz"):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            data = ("a"*64+"\n").encode()
            entry = tarfile.TarInfo("evidence/root-hash.txt")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        return output.getvalue()
    if path.endswith("canonical-reference-evidence.json"):
        return json.dumps(dict(boot_id="first-boot")).encode()
    if path.endswith("canonical-reboot-evidence.json"):
        return json.dumps(dict(boot_id="second-boot" if mode != "same-boot" else "first-boot")).encode()
    if path == "/var/tmp/test-artifact":
        return (fixture / "artifact.bin").read_bytes()
    raise ValueError(f"Unexpected artifact path: {path}")


if args[:2] == ["group", "exists"]:
    print(str(state["group"]).lower())
    emit()
if args[:2] == ["group", "show"]:
    emit(dict(tags=dict(session="not-this-run" if mode == "ownership" else config["runId"])))
if args[:2] == ["group", "create"]:
    state["group"] = True
    emit()
if args[:2] == ["group", "delete"]:
    state["group"] = False
    emit()
if args[:2] == ["vm", "list-skus"]:
    emit([dict(name=config["vmSize"], restrictions=[], family="standardDCASv6Family",
               capabilities=[dict(name="vCPUs", value="4")])])
if args[:2] == ["vm", "list-usage"]:
    emit([dict(name=dict(value=name), currentValue=0, limit=0 if mode == "quota" else 16)
          for name in ("standardDCASv6Family", "cores")])
if args[:3] == ["vm", "image", "show"]:
    emit()
if args[:2] == ["vm", "list"]:
    emit([vm_model(name) for name in state["vms"]])
if args[:2] == ["vm", "create"]:
    name = value("-n")
    if len(state["vms"]) >= 2 or name in state["vms"]:
        raise ValueError("VM cap/overwrite guard failed")
    if value("--security-type") != "ConfidentialVM" or value("--nsg-rule") != "NONE":
        raise ValueError("Incorrect VM safety configuration")
    state["vms"][name] = "running"
    emit(vm_model(name))
if args[:2] == ["vm", "show"]:
    emit(vm_model(value("-n")))
if args[:2] == ["vm", "deallocate"]:
    state["vms"][value("-n")] = "deallocated"
    emit()
if args[:2] == ["vm", "get-instance-view"]:
    emit(dict(instanceView=dict(statuses=[dict(code="PowerState/"+state["vms"][value("-n")])])))
if args[:2] == ["vm", "delete"]:
    del state["vms"][value("-n")]
    emit()
if args[:2] == ["vm", "restart"]:
    state["restarted"] = True
    emit()
if args[:3] == ["vm", "run-command", "list"]:
    if mode == "policy-commands":
        commands = [dict(name="policy-owned", id="policy-owned")]
        if state.get("testCommandPresent", True):
            commands.append(dict(name="poc-old", id=resource_id(
                "Microsoft.Compute/virtualMachines", config["targetVm"])+"/runCommands/poc-old"))
        emit(commands)
    emit([])
if args[:3] in (["network", "nsg", "create"], ["network", "vnet", "create"],
                 ["network", "nic", "delete"], ["network", "public-ip", "delete"],
                 ["network", "nsg", "rule"]):
    emit()
if args[:4] == ["network", "vnet", "subnet", "update"]:
    emit(dict(id=resource_id("Microsoft.Network/virtualNetworks", config["network"])+"/subnets/poc"))
if args[:3] == ["network", "nic", "show"]:
    emit(dict(ipConfigurations=[dict(publicIPAddress=dict(
        id=resource_id("Microsoft.Network/publicIPAddresses", config["helperVm"]+"-ip")))]))
if args[:3] == ["network", "nsg", "list"]:
    emit([])
if args[:2] == ["disk", "create"]:
    emit(dict(id=resource_id("Microsoft.Compute/disks", config["sourceDisk"])))
if args[:2] == ["disk", "delete"]:
    emit()
if args[:3] == ["storage", "account", "create"]:
    emit(dict(id=resource_id("Microsoft.Storage/storageAccounts", config["storageAccount"])))
if args[:3] == ["storage", "account", "delete"] or args[:4] == ["storage", "account", "network-rule", "add"]:
    emit()
if args[:3] == ["storage", "container-rm", "create"] or args[:2] == ["sig", "create"]:
    emit()
if args[:3] == ["role", "assignment", "create"]:
    emit(dict(id=resource_id("Microsoft.Authorization/roleAssignments", "test-assignment"),
              principalId=value("--assignee-object-id"), scope=value("--scope")))
if args[:3] == ["role", "assignment", "delete"]:
    emit()
if args[:3] in (["sig", "image-definition", "create"], ["sig", "image-definition", "show"]):
    emit(dict(features=[dict(name="SecurityType", value="TrustedLaunchAndConfidentialVmSupported")]))
if args[:2] == ["resource", "list"]:
    emit([dict(name=config["targetVm"], type="Microsoft.Compute/virtualMachines")])
if args and args[0] == "rest":
    method = value("--method").lower()
    url = value("--url")
    path = urllib.parse.urlsplit(url).path
    if method == "patch":
        emit()
    if "/runCommands/" in path:
        name = path.rsplit("/", 1)[1]
        if method == "delete" and mode == "policy-commands" and name.startswith("poc-"):
            state["testCommandPresent"] = False
            emit()
        if method == "put":
            body = json.loads(pathlib.Path(value("--body")[1:]).read_text())
            script = body["properties"]["source"]["script"]
            if "-----BEGIN PRIVATE KEY-----" in script:
                raise ValueError("Private key in managed request")
            state["commands"][name] = dict(script=script, polls=0)
            emit()
        if method == "get":
            if value("--url-parameters") != "$expand=instanceView":
                raise ValueError("Missing instance-view expansion")
            command = state["commands"][name]
            command["polls"] += 1
            script = command["script"]
            markers = dict(
                helper_tools="HELPER_TOOLS_READY",
                custom_uki_build="CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED",
                producer_build="PRODUCER_BUILD_AND_TESTS_PASSED", source_ready="SOURCE_DISK_READY",
                image_build="IMAGE_BUILD_AND_NEGATIVE_TESTS_PASSED", vhd_upload="VHD_UPLOAD_PASSED",
                collect_build_evidence="BUILD_EVIDENCE_ARCHIVED",
                reference_before_reboot="REFERENCE_BOOT_AND_SMOKE_PASSED",
                reference_after_reboot="VOLATILE_REBOOT_AND_UNCHANGED_LOWER_PASSED",
                test="TEST_PASSED")
            if name.startswith("poc-read-"):
                line = next(line for line in script.splitlines() if line.startswith("python3 - "))
                fields = line.split()
                remote = base64.b64decode(fields[2]).decode()
                index = int(fields[3])
                data = artifact(remote)
                local_artifact = fixture / "managed-artifact.bin"
                local_artifact.write_bytes(data)
                encoded_path = base64.b64encode(str(local_artifact).encode()).decode()
                reader = pathlib.Path(__file__).resolve().parents[1] / "scripts/Read-ArtifactChunk.py"
                encoded = subprocess.check_output([sys.executable, str(reader), encoded_path, str(index)], text=True)
                chunk = json.loads(encoded.splitlines()[0])
                if mode == "tamper":
                    chunk["sha256"] = "0"*64
                if mode == "changed-chunk" and index > 0:
                    chunk["sha256"] = "1"*64
                output = json.dumps(chunk)
                output += "\nMANAGED_ARTIFACT_CHUNK_READY"
            else:
                output = markers[name.removeprefix("poc-").replace("-", "_")]
            status = "Pending" if command["polls"] == 1 or mode == "pending" else "Succeeded"
            if mode == "failed":
                status = "Failed"
            if mode == "missing-marker":
                output = "no terminal marker"
            emit(dict(properties=dict(instanceView=dict(executionState=status,
                                                        exitCode=1 if mode == "exit-code" else 0,
                                                        output=output, error=""))))
    if "/versions/" in path:
        if method == "put":
            state["version"] = json.loads(pathlib.Path(value("--body")[1:]).read_text())
            emit(state["version"])
        if method == "get":
            if value("--url-parameters") != "$expand=ReplicationStatus,UefiSettings":
                raise ValueError("Missing UEFI expansion")
            version = state["version"]
            version["properties"]["provisioningState"] = "Succeeded"
            version["properties"]["replicationStatus"] = dict(aggregatedState="Completed")
            if mode == "wrong-signer":
                version["properties"]["securityProfile"]["uefiSettings"]["additionalSignatures"]["db"][0]["value"] = ["wrong"]
            emit(version)
raise ValueError(f"Unimplemented Azure operation: {args}")
