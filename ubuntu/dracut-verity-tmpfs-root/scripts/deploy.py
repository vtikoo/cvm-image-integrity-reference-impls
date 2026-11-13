#!/usr/bin/env python3
"""Private-network Azure controller for the Dracut recipe (stdlib only).

Azure authorization and authenticated SSH are separate trust boundaries. Managed
Run Command provides basic acceptance; optional SSH mode also collects SDK evidence.
"""

import argparse
import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import urlsplit


RECIPE = Path(__file__).resolve().parents[1]
CHECKOUT = RECIPE.parents[1]
PURPOSE = "dracut-verity-tmpfs"
BUILDER_IMAGE = "Canonical:ubuntu-24_04-lts:server:24.04.202610250"
API = "2024-07-01"
GALLERY_API = "2024-03-03"
PCRS = list(range(9)) + [11, 12]
ARTIFACT_READER = CHECKOUT / "ubuntu/verity-tmpfs-root/scripts/Read-ArtifactChunk.py"


class DeploymentError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_write(path, data, exclusive=True):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
    if os.name != "nt":
        path.chmod(0o600)


def write_json(path, value, exclusive=True):
    private_write(path, json.dumps(value, indent=2) + "\n", exclusive)


def read_json(path):
    return json.loads(Path(path).read_text())


def child_of(path, parent):
    return path == parent or parent in path.parents


def validate_run_path(value, must_be_new=True):
    path = Path(value).expanduser().absolute()
    require(not path.is_symlink(), "Run directory cannot be a symbolic link")
    resolved = path.resolve()
    require(not child_of(resolved, CHECKOUT.resolve()), "Run directory must be outside the repository")
    require(resolved != Path(resolved.anchor) and len(resolved.parts) > 2,
            "Use a dedicated run directory, not a filesystem root or home root")
    if must_be_new:
        require(not path.exists(), "Use a new run directory; refusing to overwrite evidence")
    else:
        require(path.is_dir(), "Run directory does not exist")
        if os.name != "nt":
            require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
                    "Run directory must be owned by this user with mode 0700")
    return resolved


def validate_endpoint(value):
    url = urlsplit(value)
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and not url.fragment and not url.query and url.path in ("", "/", "/attest/AzureGuest"),
            "Supply an approved explicit HTTPS AzureGuest MAA endpoint without credentials/query")


def ssh_path(value):
    path = Path(value).as_posix()
    require(not any(character in path for character in "\r\n"), "SSH paths cannot contain newlines")
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def jump_configuration(config, private_key):
    user, host = config["sshJumpHost"].split("@")
    return "\n".join((
        "Host cvm-dracut-jump", "  HostName " + host, "  User " + user,
        "  IdentityFile " + ssh_path(private_key),
        "  UserKnownHostsFile " + ssh_path(config["sshJumpKnownHosts"]),
        "  GlobalKnownHostsFile " + ssh_path(Path(config["runDirectory"]) / "empty-global-known-hosts"),
        "  IdentitiesOnly yes", "  BatchMode yes", "  StrictHostKeyChecking yes",
        "  UpdateHostKeys no", "  ForwardAgent no", "  ClearAllForwardings yes",
        "  HostKeyAlgorithms ssh-ed25519", "  ConnectTimeout 15", "  ConnectionAttempts 1", "",
    ))


def configuration(args):
    require(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
                         args.subscription_id), "Subscription must be a GUID")
    require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{2,62}", args.resource_group),
            "Invalid new dedicated resource-group name")
    require(re.fullmatch(r"[a-z][a-z0-9-]{2,11}", args.prefix), "Prefix must be 3-12 lowercase characters")
    require(re.fullmatch(r"[a-z][a-z0-9]+", args.location), "Invalid Azure location")
    require(re.fullmatch(r"Standard_DC[0-9]+es_v6", args.vm_size),
            "The reference must use an Intel TDX DCes_v6 size")
    require(re.fullmatch(r"Canonical:ubuntu-24_04-lts:server:24\.04\.[0-9]+", args.builder_image),
            "Builder must use a pinned standard Canonical Ubuntu 24.04 server image")
    key_path = Path(args.ssh_public_key).expanduser().resolve()
    require(bool(args.ssh_public_key.strip()), "SSH public key path must not be empty")
    if args.maa_endpoint:
        validate_endpoint(args.maa_endpoint)
    require(bool(args.ssh_jump_host) == bool(args.ssh_jump_known_hosts),
            "Supply both --ssh-jump-host and --ssh-jump-known-hosts")
    if args.ssh_jump_host:
        require(re.fullmatch(r"[a-z_][a-zA-Z0-9_-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*",
                             args.ssh_jump_host),
                "SSH jump host must be user@hostname without options or whitespace")
    net = ipaddress.ip_network(args.network_address_prefix)
    subnet = ipaddress.ip_network(args.subnet_prefix)
    private_ranges = [ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    require(net.version == 4 and any(net.subnet_of(item) for item in private_ranges)
            and subnet.subnet_of(net) and subnet.prefixlen <= 28, "Use an RFC1918 IPv4 VNet/subnet")
    if args.ssh_source_cidr:
        source = ipaddress.ip_network(args.ssh_source_cidr)
        require(source.version == 4 and any(source.subnet_of(item) for item in private_ranges),
                "SSH source must be an approved corporate RFC1918 CIDR, never Internet SSH")
    run = validate_run_path(args.run_directory or Path.home() / "cvm-dracut-runs" / args.prefix)
    run_id = str(uuid.uuid4())
    prefix = args.prefix
    inputs = read_json(RECIPE / "inputs.json")
    config = {
        "schemaVersion": 1, "subscriptionId": args.subscription_id.lower(),
        "resourceGroup": args.resource_group, "prefix": prefix, "runId": run_id,
        "purpose": PURPOSE, "location": args.location, "vmSize": args.vm_size,
        "builderVmSize": "Standard_D8s_v5", "builderImage": args.builder_image,
        "sourceImage": inputs["imageUrn"], "maximumVms": 2, "adminUsername": "cvmadmin",
        "builderVm": prefix + "-builder", "referenceVm": prefix + "-reference",
        "sourceDisk": prefix + "-source", "network": prefix + "-vnet", "subnet": "cvm",
        "networkSecurityGroup": prefix + "-nsg", "natGateway": prefix + "-nat",
        "outboundIp": prefix + "-egress", "networkAddressPrefix": str(net),
        "subnetPrefix": str(subnet), "sshSourceCidr": args.ssh_source_cidr,
        "storageAccount": "dv" + prefix.replace("-", "") + run_id.replace("-", "")[:8],
        "container": "images", "gallery": prefix.replace("-", "_") + "_gallery",
        "imageDefinition": "ubuntu2404-dracut-verity", "imageVersion": "1.0.0",
        "runDirectory": str(run), "sshPublicKey": str(key_path),
        "maaEndpoint": args.maa_endpoint,
        "validationTransport": args.validation_transport,
        "sshJumpHost": args.ssh_jump_host,
        "sshJumpKnownHosts": str(Path(args.ssh_jump_known_hosts).expanduser().resolve())
        if args.ssh_jump_known_hosts else None,
        "privateConnectivity": (
            "Managed validation needs no inbound route; user must confirm/configure network access for later SSH"
            if args.validation_transport == "managed" else
            "SSH validation requires an approved route to the new private subnet"),
        "attestationVerification": "NOT_VERIFIED: collection only; PCR12 token coverage may be absent",
    }
    return config


def command(argv, *, data=None, timeout=300, check=True):
    try:
        result = subprocess.run([str(x) for x in argv], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeploymentError(f"Command could not complete: {Path(str(argv[0])).name}") from error
    if check and result.returncode:
        # Do not echo Azure errors/bodies: they may contain credentials or tokens.
        raise DeploymentError(f"{Path(str(argv[0])).name} {argv[1] if len(argv) > 1 else ''} failed (exit {result.returncode})")
    return result


def azure_executable():
    executable = shutil.which("az") or "az"
    if os.name == "nt" and Path(executable).suffix.lower() in (".cmd", ".bat"):
        # Bypass cmd.exe's second expansion of %, &, and nested JSON quotes.
        # This is the Python shipped with the official Azure CLI MSI, not the
        # controller's potentially unrelated Python environment.
        cli_python = Path(executable).parent.parent / "python.exe"
        require(cli_python.is_file(),
                "Cannot locate Azure CLI's bundled python.exe beside az.cmd; use the official Azure CLI MSI")
        return [str(cli_python), "-IBm", "azure.cli"]
    return [executable]


def azure_body_path(path):
    launcher = Path(shutil.which("az") or "az")
    if os.name != "nt" and (launcher.parent.parent / "python.exe").is_file():
        require(shutil.which("wslpath"), "WSL Windows Azure CLI requires wslpath for request files")
        return command(["wslpath", "-w", str(path)]).stdout.decode().strip()
    return str(path)


def validate_public_key(path):
    require(path.is_file(), "SSH public key file does not exist")
    key = path.read_text().strip()
    parts = key.split()
    require(len(parts) >= 2 and parts[0] in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"),
            "Supply an OpenSSH public key")
    try:
        require(len(base64.b64decode(parts[1], validate=True)) > 32, "Invalid SSH public key")
    except ValueError as error:
        raise DeploymentError("Invalid SSH public key encoding") from error
    require("\n" not in key and "PRIVATE" not in key, "Public key must be a single OpenSSH key")


def public_profile(certificate):
    require(b"PRIVATE KEY" not in certificate and len(certificate) > 256,
            "Expected a public DER signer certificate")
    canonical = command(["openssl", "x509", "-inform", "DER", "-outform", "DER"], data=certificate).stdout
    require(canonical == certificate, "Expected exactly one DER certificate without trailing bytes")
    command(["openssl", "x509", "-inform", "DER", "-checkend", "0", "-noout"], data=certificate)
    details = command(["openssl", "x509", "-inform", "DER", "-text", "-noout"], data=certificate).stdout
    require(b"Public Key Algorithm: rsaEncryption" in details and b"Public-Key: (3072 bit)" in details,
            "Expected the actual builder-generated RSA3072 signer")
    start = command(["openssl", "x509", "-inform", "DER", "-startdate", "-noout"], data=certificate).stdout.decode()
    not_before = time.strptime(start.strip().removeprefix("notBefore="), "%b %d %H:%M:%S %Y %Z")
    import calendar
    require(calendar.timegm(not_before) <= time.time(), "Signer certificate is not yet valid")
    return {"uefiSettings": {
        "signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
        "additionalSignatures": {"db": [{"type": "x509", "value": [base64.b64encode(certificate).decode()]}]},
    }}


def validate_gallery(model, profile, config):
    properties = model.get("properties", {})
    require(properties.get("provisioningState") == "Succeeded"
            and properties.get("replicationStatus", {}).get("aggregatedState") == "Completed",
            "Gallery provisioning and replication must both complete")
    require(properties.get("securityProfile", {}).get("uefiSettings") == profile["uefiSettings"],
            "Gallery must preserve exactly the independent signer and Microsoft template")
    require(model.get("id", "").lower() == version_id(config).lower(),
            "Unexpected Gallery version ID")
    require(model.get("tags", {}).get("runId") == config["runId"], "Gallery version ownership mismatch")
    regions = properties.get("publishingProfile", {}).get("targetRegions", [])
    require(len(regions) == 1
            and regions[0].get("name", "").lower().replace(" ", "") == config["location"].lower(),
            "Gallery replication region differs from the requested region")


def version_id(config):
    return (base_id(config) + "/providers/Microsoft.Compute/galleries/" + config["gallery"]
            + "/images/" + config["imageDefinition"] + "/versions/" + config["imageVersion"])


def base_id(config):
    return f"/subscriptions/{config['subscriptionId']}/resourceGroups/{config['resourceGroup']}"


def validate_acceptance(value, build, previous=None):
    require(value.get("result") == "GUEST_ACCEPTANCE_PASSED", "Guest acceptance did not pass")
    boot = str(uuid.UUID(value["bootId"]))
    require(value.get("rootHash") == build["rootHash"] and value.get("attestationSdk") == build["attestationSdk"],
            "Guest provenance differs from independent build evidence")
    ci = value.get("cloudInit", {})
    require(ci.get("status") == "done" and ci.get("errors") == []
            and isinstance(ci.get("recoverable_errors"), dict), "Cloud-init acceptance failed")
    workload = value.get("workload")
    if previous:
        require(boot != previous and workload == "absent after distinct boot",
                "Reboot must change boot UUID and discard the workload")
    else:
        require(isinstance(workload, dict) and type(workload.get("allocatedBytes")) is int
                and workload["allocatedBytes"] >= 128 * 1024 * 1024
                and type(workload.get("allocatedInodes")) is int and workload["allocatedInodes"] >= 2050,
                "Guest tmpfs workload thresholds were not met")
    return boot


def validate_receipt(receipt, nonce, build):
    require(receipt.get("result") == "EVIDENCE_COLLECTED"
            and receipt.get("verification") == "NOT_VERIFIED: verify MAA token and authenticated quote remotely",
            "Attestation receipt must explicitly remain NOT_VERIFIED")
    require(receipt.get("nonceHex") == nonce and receipt.get("requestedPcrs") == PCRS,
            "Attestation challenge/PCR selection mismatch")
    sdk = {key: value for key, value in build["attestationSdk"].items() if key != "wrapperSha256"}
    require(receipt.get("sdkBuild") == sdk
            and receipt.get("sdkPathUntrusted") == "/usr/local/bin/azure-guest-attest",
            "Attestation did not use the installed collector with independent provenance")
    require(re.fullmatch(r"[0-9a-f]{64}", receipt.get("reportedPcr11Sha256", "")),
            "Missing measured PCR11 evidence")
    require(receipt["reportedPcr11Sha256"] != "0" * 64, "PCR11 is unmeasured")
    coverage = receipt.get("tokenClaimsUnverified", {})
    reported = coverage.get("reportedPcrs", [])
    require(all(type(item) is int for item in reported) and len(set(reported)) == len(reported)
            and set(PCRS) - {12} <= set(reported) <= set(PCRS),
            "Token-reported PCR0-8/11 coverage is required (claims remain unverified)")
    missing = sorted(set(PCRS) - set(reported))
    require(coverage.get("missingRequestedPcrs") == missing
            and coverage.get("requestedCoverageComplete") is (not missing),
            "Token PCR12 omission must be recorded explicitly")
    values = coverage.get("reportedPcrValuesSha256", {})
    require(set(values) == {str(index) for index in reported}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in values.values()),
            "Missing token-reported SHA256 PCR values")
    return missing


def recipe_archive():
    files = [RECIPE / name for name in ("inputs.json", "build-image.sh", "attest-guest.py", "verify-guest.py")]
    for folder in ("dracut", "patches"):
        files.extend(path for path in (RECIPE / folder).rglob("*") if path.is_file())
    files.extend(RECIPE / "scripts" / name for name in (
        "build-attestation.sh", "check-root.sh", "image_policy.py", "mount-volatile-root.sh", "test-corruption.sh"))
    manifest = {}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path in sorted(files):
            require(not path.is_symlink(), "Recipe staging refuses symbolic links")
            content = path.read_bytes()
            require(not re.search(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", content),
                    "Recipe staging found private key material")
            name = path.relative_to(RECIPE).as_posix()
            manifest[name] = digest(content)
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o600
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue(), manifest


class Engine:
    def __init__(self, config, private_key=None):
        self.c = config
        self.run = Path(config["runDirectory"])
        self.evidence = self.run / "evidence"
        self.key = private_key
        self.group_created = False
        self.hosts = {}
        self.sequence = 0

    def record(self, name, value):
        write_json(self.evidence / (name + ".json"), value, exclusive=False)

    def az(self, *args, timeout=300, raw=False):
        result = command([*azure_executable(), *args, "--subscription", self.c["subscriptionId"],
                          "--only-show-errors", "--output", "tsv" if raw else "json"],
                         timeout=timeout, check=False)
        if result.returncode:
            self.sequence += 1
            diagnostic = self.evidence / f"azure-{self.sequence:03d}.stderr"
            private_write(diagnostic, result.stderr)
            private_write(diagnostic.with_suffix(".stdout"), result.stdout)
            raise DeploymentError(f"Azure operation failed (exit {result.returncode}); see private evidence {diagnostic.name}")
        if raw:
            output = result.stdout
            if output.startswith((b"b'", b'b"')):
                try:
                    output = ast.literal_eval(output.decode("ascii").strip())
                except (ValueError, SyntaxError, UnicodeDecodeError) as error:
                    raise DeploymentError("Azure returned malformed byte-literal text") from error
                require(isinstance(output, bytes), "Azure returned unexpected byte-literal text")
            return output.decode(errors="surrogateescape")
        try:
            return json.loads(result.stdout) if result.stdout.strip() else None
        except ValueError as error:
            raise DeploymentError("Azure returned invalid JSON") from error

    def tags(self, role):
        return ["purpose=" + PURPOSE, "runId=" + self.c["runId"], "role=" + role]

    def owned(self, model, role=None):
        tags = model.get("tags") or {}
        require(tags.get("purpose") == PURPOSE and tags.get("runId") == self.c["runId"]
                and (role is None or tags.get("role") == role), "Resource ownership tags do not match")
        ident = model.get("id", "")
        require(ident.lower() == base_id(self.c).lower()
                or ident.lower().startswith(base_id(self.c).lower() + "/"),
                "Resource is outside the dedicated run resource group")
        return model

    def owned_group(self):
        group = self.az("group", "show", "--name", self.c["resourceGroup"])
        self.owned(group, "run")
        return group

    def rest(self, method, ident, body=None, api=API, expand=None):
        url = "https://management.azure.com" + ident + "?api-version=" + api
        args = ["rest", "--method", method, "--url", url]
        if expand:
            args += ["--url-parameters", "$expand=" + expand]
        if body is not None:
            payload = json.dumps(body, separators=(",", ":"))
            # Files avoid native argument limits and inline JSON escape loss.
            path = self.evidence / ("azure-request-" + uuid.uuid4().hex + ".json")
            private_write(path, payload)
            args += ["--body", "@" + azure_body_path(path),
                     "--headers", "Content-Type=application/json"]
        return self.az(*args)

    def poll(self, fetch, done, description, timeout=1800, interval=15):
        deadline = time.monotonic() + timeout
        while True:
            value = fetch()
            properties = value.get("properties", value) if isinstance(value, dict) else {}
            state = properties.get("provisioningState", "")
            require(state not in ("Failed", "Canceled", "Cancelled", "Deleting"),
                    description + " reached a terminal failure")
            require(properties.get("replicationStatus", {}).get("aggregatedState") not in
                    ("Failed", "Canceled", "Cancelled"), description + " replication failed")
            if done(value):
                return value
            require(time.monotonic() < deadline, description + " timed out")
            time.sleep(interval)

    def vm(self, role):
        name = self.c[role + "Vm"]
        return self.owned(self.az("vm", "show", "--resource-group", self.c["resourceGroup"], "--name", name), role)

    def preflight(self):
        require(self.az("group", "exists", "--name", self.c["resourceGroup"]) is False,
                "Resource group must be new and dedicated")
        for image in (self.c["builderImage"], self.c["sourceImage"]):
            self.az("vm", "image", "show", "--urn", image, "--location", self.c["location"])
        usages = self.az("vm", "list-usage", "--location", self.c["location"])
        needs = {"cores": 0}
        for size in (self.c["builderVmSize"], self.c["vmSize"]):
            skus = self.az("vm", "list-skus", "--location", self.c["location"], "--size", size,
                           "--all", "--resource-type", "virtualMachines")
            matches = [item for item in skus if item["name"] == size]
            require(len(matches) == 1 and all(
                restriction.get("type") == "Zone" for restriction in matches[0].get("restrictions", [])),
                "VM SKU is restricted/unavailable for a non-zonal deployment")
            sku = matches[0]
            capabilities = {item["name"]: item["value"] for item in sku["capabilities"]}
            cpus = int(capabilities["vCPUs"])
            needs[sku["family"].lower()] = needs.get(sku["family"].lower(), 0) + cpus
            needs["cores"] += cpus
        for family, cpus in needs.items():
            matches = [item for item in usages if item["name"]["value"].lower() == family]
            require(len(matches) == 1, "Missing or duplicate VM quota family: " + family)
            values = [matches[0][field] for field in ("limit", "currentValue")]
            require(all((type(value) is int and value >= 0)
                        or (isinstance(value, str) and re.fullmatch(r"[0-9]+", value))
                        for value in values), "Invalid VM quota values: " + family)
            require(int(values[0]) - int(values[1]) >= cpus,
                    "Insufficient regional/family VM quota: " + family)
        self.record("quota-preflight", {"needs": needs})

    def network(self):
        c, group = self.c, self.c["resourceGroup"]
        self.az("group", "create", "-n", group, "-l", c["location"], "--tags", *self.tags("run"))
        self.group_created = True
        self.owned_group()
        self.az("network", "nsg", "create", "-g", group, "-n", c["networkSecurityGroup"],
                "-l", c["location"], "--tags", *self.tags("network"))
        if c["sshSourceCidr"]:
            self.az("network", "nsg", "rule", "create", "-g", group, "--nsg-name", c["networkSecurityGroup"],
                    "-n", "corporate-private-ssh", "--priority", "100", "--access", "Allow",
                    "--protocol", "Tcp", "--direction", "Inbound", "--source-address-prefixes", c["sshSourceCidr"],
                    "--destination-port-ranges", "22")
        self.az("network", "nsg", "rule", "create", "-g", group, "--nsg-name", c["networkSecurityGroup"],
                "-n", "deny-other-ssh", "--priority", "110", "--access", "Deny", "--protocol", "Tcp",
                "--direction", "Inbound", "--source-address-prefixes", "*", "--destination-port-ranges", "22")
        # Outbound NAT is explicit; the NAT address is never attached to a VM.
        self.az("network", "public-ip", "create", "-g", group, "-n", c["outboundIp"],
                "--sku", "Standard", "--allocation-method", "Static", "--tags", *self.tags("network"))
        self.az("network", "nat", "gateway", "create", "-g", group, "-n", c["natGateway"],
                "--public-ip-addresses", c["outboundIp"], "--tags", *self.tags("network"))
        self.az("network", "vnet", "create", "-g", group, "-n", c["network"],
                "--address-prefixes", c["networkAddressPrefix"], "--subnet-name", c["subnet"],
                "--subnet-prefixes", c["subnetPrefix"], "--tags", *self.tags("network"))
        subnet = self.az("network", "vnet", "subnet", "update", "-g", group, "--vnet-name", c["network"],
                         "-n", c["subnet"], "--network-security-group", c["networkSecurityGroup"],
                         "--nat-gateway", c["natGateway"], "--service-endpoints", "Microsoft.Storage")
        self.record("subnet", subnet)

    def boot_config(self):
        # Bootcmd runs again when the volatile root is recreated. Key material
        # comes from authenticated boot diagnostics, never ssh-keyscan.
        code = ("(while ! test -s /etc/ssh/ssh_host_ed25519_key.pub; do sleep 1; done; "
                "printf '\\nCVM_SSH_BOOT_BEGIN %s\\n%s\\nCVM_SSH_BOOT_END\\n' "
                '"$(cat /proc/sys/kernel/random/boot_id)" "$(cat /etc/ssh/ssh_host_ed25519_key.pub)") '
                "> /dev/ttyS0 2>&1 &")
        return "#cloud-config\nbootcmd:\n  - " + json.dumps(["bash", "-c", code]) + "\n"

    def new_vm(self, role, image):
        c, group = self.c, self.c["resourceGroup"]
        self.owned_group()
        inventory = self.az("vm", "list", "-g", group)
        require(len(inventory) < 2 and all(item["name"] != c[role + "Vm"] for item in inventory),
                "Refusing an existing VM or exceeding the two-VM cap")
        name = c[role + "Vm"]
        nic = self.az("network", "nic", "create", "-g", group, "-n", name + "-nic",
                      "--vnet-name", c["network"], "--subnet", c["subnet"], "--tags", *self.tags(role))
        nic_id = nic.get("NewNIC", nic).get("id")
        require(nic_id, "NIC creation did not return an ID")
        body = {
            "location": c["location"], "tags": dict(item.split("=", 1) for item in self.tags(role)),
            "properties": {
                "hardwareProfile": {"vmSize": c["builderVmSize"] if role == "builder" else c["vmSize"]},
                "diagnosticsProfile": {"bootDiagnostics": {"enabled": True}},
                "networkProfile": {"networkInterfaces": [{"id": nic_id}]},
                "osProfile": {
                    "computerName": name, "adminUsername": c["adminUsername"],
                    "customData": base64.b64encode(self.boot_config().encode()).decode(),
                    "linuxConfiguration": {"disablePasswordAuthentication": True, "ssh": {"publicKeys": [{
                        "path": f"/home/{c['adminUsername']}/.ssh/authorized_keys",
                        "keyData": Path(c["sshPublicKey"]).read_text().strip(),
                    }]}},
                },
                "storageProfile": {
                    "imageReference": {"id": image} if image.startswith("/") else dict(
                        zip(("publisher", "offer", "sku", "version"), image.split(":"))),
                    "osDisk": {"name": name + "-os", "createOption": "FromImage", "deleteOption": "Detach",
                               "diskSizeGB": 256 if role == "builder" else 64,
                               "managedDisk": {"storageAccountType": "StandardSSD_LRS"}},
                },
            },
        }
        if role == "builder":
            body["identity"] = {"type": "SystemAssigned"}
            body["properties"]["securityProfile"] = {
                "securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}}
        else:
            body["properties"]["securityProfile"] = {
                "securityType": "ConfidentialVM", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}}
            body["properties"]["storageProfile"]["osDisk"]["managedDisk"]["securityProfile"] = {
                "securityEncryptionType": "VMGuestStateOnly"}
        ident = base_id(c) + "/providers/Microsoft.Compute/virtualMachines/" + name
        self.rest("put", ident, body)
        self.poll(lambda: self.vm(role), lambda vm: vm.get("provisioningState") == "Succeeded", "VM creation")
        model = self.vm(role)
        require(model["diagnosticsProfile"]["bootDiagnostics"]["enabled"] is True,
                "Boot diagnostics must be enabled at creation")
        require(model["hardwareProfile"]["vmSize"] == (c["builderVmSize"] if role == "builder" else c["vmSize"]),
                "Actual VM size differs from requested size")
        if role == "reference":
            self.check_reference_model(model)
        self.record(role + "-model", model)
        # Tag every automatically generated resource that we will later delete.
        for resource_id in (model["storageProfile"]["osDisk"]["managedDisk"]["id"],):
            self.az("tag", "update", "--resource-id", resource_id, "--operation", "Merge",
                    "--tags", *self.tags(role))

    def check_reference_model(self, model):
        p = model["securityProfile"]
        osdisk = model["storageProfile"]["osDisk"]
        require(p["securityType"] == "ConfidentialVM" and p["uefiSettings"] == {
            "secureBootEnabled": True, "vTpmEnabled": True},
            "Actual reference must have ConfidentialVM, Secure Boot and vTPM")
        disk_size = osdisk.get("diskSizeGB", osdisk.get("diskSizeGb"))
        if disk_size is None:
            disk_id = osdisk["managedDisk"]["id"]
            require(disk_id.lower() == (base_id(self.c) + "/providers/Microsoft.Compute/disks/"
                                       + self.c["referenceVm"] + "-os").lower(),
                    "Unexpected reference OS disk ID")
            disk = self.az("disk", "show", "--ids", disk_id)
            require(disk.get("id", "").lower() == disk_id.lower(), "Reference OS disk readback mismatch")
            self.record("reference-disk", disk)
            disk_size = disk.get("diskSizeGB", disk.get("diskSizeGb"))
        require(type(disk_size) is int and disk_size == 64 and
                osdisk["managedDisk"]["securityProfile"]["securityEncryptionType"] == "VMGuestStateOnly",
                "Actual reference OS disk must be 64 GiB VMGuestStateOnly")
        require(model["storageProfile"]["imageReference"]["id"].lower() == version_id(self.c).lower(),
                "Reference did not use the accepted Gallery image")
        require(model["hardwareProfile"]["vmSize"] == self.c["vmSize"], "Reference SKU mismatch")
        require(model["diagnosticsProfile"]["bootDiagnostics"]["enabled"] is True,
                "Reference boot diagnostics are not enabled")

    def managed(self, name, script, marker, timeout=7200, *, role="builder"):
        require(role in ("builder", "reference"), "Invalid managed-command VM role")
        group = self.owned_group()
        self.vm(role)
        ident = (base_id(self.c) + "/providers/Microsoft.Compute/virtualMachines/"
                 + self.c[role + "Vm"] + "/runCommands/" + name)
        tags = dict(item.split("=", 1) for item in self.tags(role))
        # Match the legacy controller: avoid a policy tag repair rewriting the command.
        modified_by = (group.get("tags") or {}).get("ModifiedBy")
        if modified_by:
            tags["ModifiedBy"] = modified_by
        body = {"location": self.c["location"], "tags": tags,
                "properties": {"source": {"script": script}, "asyncExecution": True,
                               "timeoutInSeconds": timeout}}
        self.rest("put", ident, body)
        start_deadline = time.monotonic() + 600
        def fetch():
            result = self.rest("get", ident, expand="instanceView")
            self.record(name + "-runcommand", result)
            return result
        def done(result):
            view = result.get("properties", {}).get("instanceView", {})
            state = view.get("executionState", "")
            require(state not in ("Failed", "TimedOut", "Canceled", "Cancelled"),
                    "Managed command failed: " + name)
            require(state in ("Running", "Succeeded") or time.monotonic() < start_deadline,
                    "Managed command did not start: " + name)
            return state == "Succeeded"
        result = self.poll(fetch, done, "Managed command " + name, timeout + 600)
        view = result["properties"]["instanceView"]
        require(view.get("exitCode") == 0 and marker in view.get("output", ""),
                "Managed command exit code/terminal marker did not pass: " + name)
        return result

    def address(self, role):
        model = self.vm(role)
        nics = model["networkProfile"]["networkInterfaces"]
        require(len(nics) == 1, "Unexpected VM NIC inventory")
        nic = self.az("network", "nic", "show", "--ids", nics[0]["id"])
        self.owned(nic, role)
        configs = nic["ipConfigurations"]
        require(len(configs) == 1 and not configs[0].get("publicIPAddress"),
                "No public IP may be attached to a VM")
        address = configs[0]["privateIPAddress"]
        require(ipaddress.ip_address(address) in ipaddress.ip_network(self.c["subnetPrefix"]),
                "VM private address is outside the owned subnet")
        return address

    def bootstrap(self, role, phase, previous=None):
        self.vm(role)
        def fetch():
            log = self.az("vm", "boot-diagnostics", "get-boot-log", "-g", self.c["resourceGroup"],
                          "-n", self.c[role + "Vm"], raw=True)
            matches = re.findall(
                r"^CVM_SSH_BOOT_BEGIN ([0-9a-f-]{36})\r?\n(.*?)^CVM_SSH_BOOT_END\r?$",
                log, re.MULTILINE | re.DOTALL)
            if not matches:
                return {}
            boot, block = matches[-1]
            require("CVM_SSH_BOOT_BEGIN" not in block, "Nested SSH boot-key publication")
            keys = re.findall(r"^ssh-ed25519 ([A-Za-z0-9+/]+=*)(?: [^\r\n]*)?\r?$", block, re.MULTILINE)
            require(len(keys) == 1, "SSH boot-key publication must contain exactly one ED25519 key")
            boot = str(uuid.UUID(boot))
            if previous and boot == previous:
                return {}
            return {"bootId": boot, "hostKey": "ssh-ed25519 " + keys[0]}
        record = self.poll(fetch, bool, "Authenticated Azure boot host-key publication", timeout=900)
        if previous:
            require(record["hostKey"] != self.hosts[role]["hostKey"],
                    "Volatile-root reference did not regenerate its host key after reboot")
        address = self.address(role)
        alias = self.c["runId"] + "-" + role + "-" + record["bootId"]
        known = self.run / (role + "-" + phase + "-known-hosts")
        private_write(known, alias + " " + record["hostKey"] + "\n")
        record.update({"address": address, "alias": alias, "knownHosts": str(known)})
        self.hosts[role] = record
        self.record(role + "-" + phase + "-ssh-bootstrap", record)
        deadline = time.monotonic() + 600
        while True:
            result = self.ssh(role, "cat /proc/sys/kernel/random/boot_id", check=False)
            if result.returncode == 0:
                require(result.stdout.decode().strip() == record["bootId"],
                        "SSH boot UUID does not match authenticated boot diagnostics")
                return record["bootId"]
            # An SSH server that responds with a different key is never retrusted.
            require(b"REMOTE HOST IDENTIFICATION HAS CHANGED" not in result.stderr
                    and b"Host key verification failed" not in result.stderr, "SSH host-key authentication failed")
            require(time.monotonic() < deadline, "Authenticated private SSH was not reachable")
            time.sleep(10)

    def ssh(self, role, remote, data=None, check=True, timeout=1800):
        host = self.hosts[role]
        config = self.run / "ssh-jump.config" if self.c.get("sshJumpHost") else None
        if config:
            require(config.is_file(), "Missing independently authenticated SSH jump configuration")
        args = ["ssh", "-F", str(config) if config else "none", "-i", self.key, "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + ssh_path(host["knownHosts"]),
                "-o", "GlobalKnownHostsFile=" + ssh_path(self.run / "empty-global-known-hosts"),
                "-o", "HostKeyAlias=" + host["alias"], "-o", "HostKeyAlgorithms=ssh-ed25519",
                "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
                "-o", "CheckHostIP=no", "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=6"]
        if config:
            args += ["-J", "cvm-dracut-jump"]
        args += [self.c["adminUsername"] + "@" + host["address"], remote]
        result = command(args, data=data, timeout=timeout, check=False)
        self.sequence += 1
        private_write(self.evidence / f"ssh-{self.sequence:03d}.stderr", result.stderr)
        private_write(self.evidence / f"ssh-{self.sequence:03d}.stdout", result.stdout)
        if check:
            require(result.returncode == 0, f"Authenticated SSH operation failed (exit {result.returncode}); see private stderr evidence")
        return result

    def retrieve(self, role, remote, local):
        require(not re.search(r"private|\.key(?:$|/)", remote, re.I), "Private signing keys never leave the builder")
        if self.c.get("validationTransport", "ssh") == "managed":
            return self.retrieve_managed(role, remote, local)
        quoted = shlex.quote(remote)
        expected = self.ssh(role, "sudo sha256sum -- " + quoted).stdout.decode().split()[0]
        require(re.fullmatch(r"[0-9a-f]{64}", expected), "Remote artifact hash is malformed")
        content = self.ssh(role, "sudo cat -- " + quoted).stdout
        require(digest(content) == expected, "SSH artifact transfer hash mismatch")
        private_write(local, content)
        self.record(Path(local).name + "-transfer", {"remote": remote, "sha256": expected, "bytes": len(content)})
        return content

    def retrieve_managed(self, role, remote, local):
        require(not Path(local).exists(), "Refusing to overwrite retrieved evidence")
        encoded_path = base64.b64encode(remote.encode()).decode()
        chunks, expected, index, encoded = None, None, 0, []
        while chunks is None or index < chunks:
            script = ("#!/bin/bash\nset -euo pipefail\npython3 - "
                      + shlex.quote(encoded_path) + " " + str(index) + " <<'CVM_ARTIFACT'\n"
                      + ARTIFACT_READER.read_text() + "\nCVM_ARTIFACT\n")
            result = self.managed("cvm-read-" + uuid.uuid4().hex, script,
                                  "MANAGED_ARTIFACT_CHUNK_READY", timeout=300, role=role)
            lines = [line for line in result["properties"]["instanceView"]["output"].splitlines()
                     if line.startswith("{")]
            require(len(lines) == 1, "Managed artifact response is missing or truncated")
            chunk = json.loads(lines[0])
            require(type(chunk.get("chunks")) is int and chunk["chunks"] >= 1
                    and type(chunk.get("index")) is int and chunk["index"] == index
                    and re.fullmatch(r"[0-9a-f]{64}", chunk.get("sha256", ""))
                    and isinstance(chunk.get("payload"), str), "Malformed managed artifact chunk")
            if index == 0:
                chunks, expected = chunk["chunks"], chunk["sha256"]
            require(chunk["chunks"] == chunks and chunk["sha256"] == expected,
                    "Managed artifact changed during retrieval")
            encoded.append(chunk["payload"])
            index += 1
        content = gzip.decompress(base64.b64decode("".join(encoded), validate=True))
        require(digest(content) == expected, "Managed artifact transfer hash mismatch")
        private_write(local, content)
        self.record(Path(local).name + "-transfer", {
            "transport": "managed", "remote": remote, "sha256": expected, "bytes": len(content)})
        return content

    def remove_reference_commands(self):
        self.owned_group()
        self.vm("reference")
        def commands():
            return [item for item in self.az("vm", "run-command", "list", "-g", self.c["resourceGroup"],
                                            "--vm-name", self.c["referenceVm"])
                    if (item.get("tags") or {}).get("runId") == self.c["runId"]
                    and (item.get("tags") or {}).get("purpose") == PURPOSE
                    and (item.get("tags") or {}).get("role") == "reference"]
        for item in commands():
            self.owned(item, "reference")
            self.rest("delete", item["id"])
        self.poll(commands, lambda items: not items, "Reference managed-command removal", timeout=600)

    def build(self):
        payload, manifest = recipe_archive()
        self.record("recipe-manifest", manifest)
        self.record("recipe-archive", {"sha256": digest(payload), "bytes": len(payload)})
        stage = (
            "#!/bin/bash\nset -euo pipefail\numask 077\n"
            "test ! -e /opt/cvm-dracut\n"
            "install -d -m 700 /opt/cvm-dracut/checkout/ubuntu/dracut-verity-tmpfs-root /var/lib/cvm-dracut\n"
            "printf %s " + shlex.quote(base64.b64encode(payload).decode()) +
            " | base64 -d > /var/lib/cvm-dracut/recipe.tar.gz\n"
            "echo " + shlex.quote(digest(payload) + "  /var/lib/cvm-dracut/recipe.tar.gz") + " | sha256sum -c -\n"
            "tar --no-same-owner -xzf /var/lib/cvm-dracut/recipe.tar.gz "
            "-C /opt/cvm-dracut/checkout/ubuntu/dracut-verity-tmpfs-root\n"
            "cat > /var/lib/cvm-dracut/builder.sh <<'CVM_BUILDER_SCRIPT'\n"
            + (RECIPE / "scripts/deployment-builder.sh").read_text() + "\nCVM_BUILDER_SCRIPT\n"
            "bash /var/lib/cvm-dracut/builder.sh provision\n")
        self.managed("provision", stage, "DRACUT_BUILDER_PROVISIONED", timeout=3600)
        if self.c.get("validationTransport", "ssh") == "ssh":
            self.bootstrap("builder", "first")
        # The source has never been booted, and is attached only now.
        disk = self.az("disk", "create", "-g", self.c["resourceGroup"], "-n", self.c["sourceDisk"],
                       "--location", self.c["location"], "--image-reference", self.c["sourceImage"],
                       "--security-type", "ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey",
                       "--sku", "StandardSSD_LRS", "--hyper-v-generation", "V2", "--os-type", "Linux",
                       "--tags", *self.tags("source"))
        self.owned(disk, "source")
        self.record("source-disk", disk)
        self.rest("patch", self.vm("builder")["id"], {"properties": {"storageProfile": {"dataDisks": [{
            "lun": 0, "name": self.c["sourceDisk"], "createOption": "Attach", "managedDisk": {"id": disk["id"]},
            "caching": "ReadOnly", "deleteOption": "Detach",
        }]}}})
        self.managed("build", "bash /var/lib/cvm-dracut/builder.sh build\n",
                     "DRACUT_DEPLOYMENT_BUILD_PASSED", timeout=14400)
        root = "/var/lib/cvm-dracut"
        for remote, local in (
            (root + "/output/evidence/build.json", "build.json"),
            (root + "/output/signer.der", "signer.der"),
            (root + "/provenance.json", "provenance.json"),
            (root + "/output/evidence/output.sha256", "output.sha256"),
            (root + "/output/build.log", "build.log"),
        ):
            self.retrieve("builder", remote, self.evidence / local)
        build, provenance = read_json(self.evidence / "build.json"), read_json(self.evidence / "provenance.json")
        self.validate_build(build, provenance, manifest)
        profile = public_profile((self.evidence / "signer.der").read_bytes())
        write_json(self.run / "guest-security-profile.json", profile)
        return build, provenance, profile

    def validate_build(self, build, provenance, manifest):
        require(provenance.get("result") == "DRACUT_DEPLOYMENT_BUILD_PASSED"
                and provenance.get("recipeFiles") == manifest, "Final builder provenance/recipe manifest mismatch")
        require(provenance.get("sourceMatchesOriginal") is True
                and provenance.get("sourceOriginalSha256") == provenance.get("sourceRawSha256")
                and re.fullmatch(r"[0-9a-f]{64}", provenance.get("sourceRawSha256", "")),
                "Source raw must match the original unmounted source")
        require(build.get("imageUrn") == self.c["sourceImage"]
                and build.get("kernel") == provenance.get("kernel")
                and re.fullmatch(r"[0-9][a-zA-Z0-9.+_-]*-azure(?:-fde)?", build.get("kernel", "")),
                "Build source/kernel provenance mismatch")
        kernels = provenance.get("sourceKernels", [])
        require(len(kernels) == 1 and kernels[0].get("kernel") == build["kernel"]
                and re.fullmatch(r"[0-9a-f]{64}", kernels[0].get("ukiSha256", "")),
                "The selected original UKI/module-tree kernel is not uniquely evidenced")
        require(re.fullmatch(r"[0-9a-f]{64}", provenance.get("rustupBinarySha256", "")),
                "Missing verified rustup binary provenance")
        for field in ("rootHash",):
            require(re.fullmatch(r"[0-9a-f]{64}", build.get(field, "")), "Invalid independent build hash")
        for field in ("dataPartUuid", "hashPartUuid"):
            uuid.UUID(build[field])
        hashes = provenance.get("outputs", {})
        require(all(re.fullmatch(r"[0-9a-f]{64}", hashes.get(name, ""))
                    for name in ("image.raw", "image.vhd", "cvm.efi", "signer.der")),
                "Final output hashes are missing")
        require(hashes["signer.der"] == digest((self.evidence / "signer.der").read_bytes())
                and provenance.get("buildJsonSha256") == digest((self.evidence / "build.json").read_bytes()),
                "Independent signer/build record hashes mismatch")
        log = (self.evidence / "build.log").read_text()
        require("DRACUT_VERITY_IMAGE_BUILD_PASSED" in log and "BUILD_FAILED" not in log,
                "Recipe build log does not show successful completion")
        sdk, expected = build.get("attestationSdk", {}), read_json(RECIPE / "inputs.json")["attestationSdk"]
        require(all(sdk.get(key) == value for key, value in expected.items()),
                "SDK repository/revision/patch/PCR provenance mismatch")
        require(sdk.get("wrapperSha256") == digest((RECIPE / "attest-guest.py").read_bytes())
                and re.fullmatch(r"[0-9a-f]{64}", sdk.get("binarySha256", "")),
                "Attestation collector hashes are missing or stale")
        require(sdk.get("rustc", "").startswith("rustc 1.95.0 "), "Build must use the pinned Rust 1.95.0 toolchain")

    def publish(self, build, provenance, profile):
        c, group = self.c, self.c["resourceGroup"]
        self.owned_group()
        builder = self.vm("builder")
        storage = self.az("storage", "account", "create", "-g", group, "-n", c["storageAccount"],
                          "-l", c["location"], "--sku", "Standard_LRS", "--kind", "StorageV2",
                          "--https-only", "true", "--allow-blob-public-access", "false",
                          "--allow-shared-key-access", "false", "--min-tls-version", "TLS1_2",
                          "--default-action", "Deny", "--bypass", "AzureServices",
                          "--public-network-access", "Enabled", "--tags", *self.tags("upload"))
        self.owned(storage, "upload")
        subnet = read_json(self.evidence / "subnet.json")
        self.az("storage", "account", "network-rule", "add", "-g", group, "--account-name",
                c["storageAccount"], "--subnet", subnet["id"])
        actual_storage = self.az("storage", "account", "show", "-g", group, "-n", c["storageAccount"])
        self.owned(actual_storage, "upload")
        self.check_storage(actual_storage, subnet["id"])
        self.record("upload-storage", actual_storage)
        self.az("storage", "container-rm", "create", "-g", group, "--storage-account", c["storageAccount"],
                "-n", c["container"])
        scope = storage["id"] + "/blobServices/default/containers/" + c["container"]
        role = self.az("role", "assignment", "create", "--assignee-object-id", builder["identity"]["principalId"],
                       "--assignee-principal-type", "ServicePrincipal", "--role", "Storage Blob Data Contributor",
                       "--scope", scope)
        require(role.get("scope", "").lower() == scope.lower()
                and role.get("principalId") == builder["identity"]["principalId"]
                and role.get("roleDefinitionId", "").lower().endswith("/ba92f5b4-2d11-453d-a403-e96b0029c9fe"),
                "Upload role must be exactly container-scoped Storage Blob Data Contributor for the builder")
        self.record("upload-role", role)
        blob = "https://" + c["storageAccount"] + ".blob.core.windows.net/" + c["container"] + "/dracut.vhd"
        script = "#!/bin/bash\nset -euo pipefail\numask 077\npython3 - " + " ".join(map(shlex.quote, (
            "/var/lib/cvm-dracut/output/image.vhd", blob, provenance["outputs"]["image.vhd"], build["rootHash"],
        ))) + " <<'CVM_UPLOAD'\n" + (RECIPE / "scripts/deployment-upload.py").read_text() + "\nCVM_UPLOAD\n"
        self.managed("upload", script, "DRACUT_VHD_UPLOAD_PASSED", timeout=7200)
        upload = json.loads(self.retrieve("builder", "/var/lib/cvm-dracut/upload.json", self.evidence / "upload.json"))
        require(upload.get("sha256") == provenance["outputs"]["image.vhd"]
                and upload.get("readbackSha256") == upload["sha256"]
                and upload.get("url") == blob and upload.get("rootHash") == build["rootHash"],
                "Page blob upload/readback does not match the verified VHD")
        self.az("sig", "create", "-g", group, "--gallery-name", c["gallery"], "-l", c["location"],
                "--tags", *self.tags("gallery"))
        definition = self.az("sig", "image-definition", "create", "-g", group, "--gallery-name", c["gallery"],
                             "--gallery-image-definition", c["imageDefinition"], "-l", c["location"],
                             "--publisher", "DracutReference", "--offer", "ubuntu2404", "--sku", "verity-tmpfs",
                             "--os-type", "Linux", "--os-state", "Generalized", "--hyper-v-generation", "V2",
                             "--architecture", "x64", "--features",
                             "SecurityType=TrustedLaunchAndConfidentialVmSupported", "--tags", *self.tags("gallery"))
        self.owned(definition, "gallery")
        definition = self.az("sig", "image-definition", "show", "-g", group, "--gallery-name", c["gallery"],
                             "--gallery-image-definition", c["imageDefinition"])
        require(definition.get("osState") == "Generalized" and definition.get("architecture") == "x64"
                and definition.get("hyperVGeneration") == "V2"
                and {"name": "SecurityType", "value": "TrustedLaunchAndConfidentialVmSupported"}
                in definition.get("features", []), "Gallery definition security model mismatch")
        self.record("gallery-definition", definition)
        body = {"location": c["location"], "tags": dict(item.split("=", 1) for item in self.tags("gallery")),
                "properties": {
                    "publishingProfile": {"replicaCount": 1, "excludeFromLatest": True,
                                          "storageAccountType": "Standard_LRS", "targetRegions": [{
                                              "name": c["location"], "regionalReplicaCount": 1,
                                              "storageAccountType": "Standard_LRS"}]},
                    "storageProfile": {"osDiskImage": {"source": {"uri": blob, "storageAccountId": storage["id"]}}},
                    "securityProfile": profile,
                }}
        self.record("gallery-request", body)
        self.rest("put", version_id(c), body, GALLERY_API)
        def fetch():
            model = self.rest("get", version_id(c), api=GALLERY_API, expand="ReplicationStatus,UefiSettings")
            self.record("gallery-version", model)
            return model
        model = self.poll(fetch, lambda item: item.get("properties", {}).get("provisioningState") == "Succeeded"
                          and item["properties"].get("replicationStatus", {}).get("aggregatedState") == "Completed",
                          "Gallery replication", timeout=3600)
        validate_gallery(model, profile, c)

    def check_storage(self, model, subnet):
        rules = model.get("networkRuleSet", {})
        networks = rules.get("virtualNetworkRules", [])
        require(model.get("allowSharedKeyAccess") is False
                and model.get("allowBlobPublicAccess") is False
                and model.get("enableHttpsTrafficOnly") is True
                and model.get("minimumTlsVersion") == "TLS1_2"
                and rules.get("defaultAction") == "Deny" and rules.get("bypass") == "AzureServices"
                and not rules.get("ipRules") and not rules.get("resourceAccessRules")
                and len(networks) == 1 and networks[0].get("virtualNetworkResourceId", "").lower() == subnet.lower(),
                "Upload storage must deny public access/shared keys and allow only the builder subnet plus trusted Azure services")

    def acceptance(self, build):
        if self.c.get("validationTransport", "ssh") == "managed":
            return self.acceptance_managed(build)
        first_boot = self.bootstrap("reference", "first")
        root = "/run/cvm-controller-" + self.c["runId"]
        self.ssh("reference", "sudo install -d -m 700 " + shlex.quote(root))
        for path, name in ((RECIPE / "verify-guest.py", "verify-guest.py"),
                           (self.evidence / "build.json", "build.json"), (self.evidence / "signer.der", "signer.der")):
            content = path.read_bytes()
            self.ssh("reference", "sudo tee " + shlex.quote(root + "/" + name) + " >/dev/null", content)
            actual = self.ssh("reference", "sudo sha256sum " + shlex.quote(root + "/" + name)).stdout.decode().split()[0]
            require(actual == digest(content), "Staged acceptance artifact hash mismatch")
        remote = "sudo python3 " + " ".join(shlex.quote(root + "/" + name)
                                          for name in ("verify-guest.py", "build.json", "signer.der"))
        first = self.ssh("reference", remote)
        private_write(self.evidence / "acceptance-first.json", first.stdout)
        before = json.loads(first.stdout)
        require(validate_acceptance(before, build) == first_boot, "First acceptance boot UUID is stale")
        # A reboot is requested over the already authenticated SSH session.
        self.ssh("reference", "sudo systemd-run --unit=cvm-controller-reboot --on-active=3s /usr/sbin/reboot")
        after_boot = self.bootstrap("reference", "reboot", previous=first_boot)
        # /run and the volatile root were discarded: restage independent records.
        self.ssh("reference", "sudo install -d -m 700 " + shlex.quote(root))
        for path, name in ((RECIPE / "verify-guest.py", "verify-guest.py"),
                           (self.evidence / "build.json", "build.json"), (self.evidence / "signer.der", "signer.der")):
            self.ssh("reference", "sudo tee " + shlex.quote(root + "/" + name) + " >/dev/null", path.read_bytes())
            actual = self.ssh("reference", "sudo sha256sum " + shlex.quote(root + "/" + name)).stdout.decode().split()[0]
            require(actual == digest(path.read_bytes()), "Reboot acceptance staging hash mismatch")
        after = self.ssh("reference", remote + " --previous-boot-id " + shlex.quote(first_boot))
        private_write(self.evidence / "acceptance-reboot.json", after.stdout)
        require(validate_acceptance(json.loads(after.stdout), build, first_boot) == after_boot,
                "Reboot acceptance boot UUID is stale")
        nonce = secrets.token_hex(32)
        write_json(self.evidence / "challenge.json", {"nonceHex": nonce, "endpoint": self.c["maaEndpoint"],
                                                     "bootId": after_boot})
        attdir = "/run/cvm-attest-" + self.c["runId"]
        collection = self.ssh("reference", "sudo /usr/local/bin/cvm-attest --endpoint " + shlex.quote(self.c["maaEndpoint"])
                              + " --nonce " + nonce + " --output " + shlex.quote(attdir), check=False)
        local = self.evidence / "attestation"
        local.mkdir(mode=0o700)
        expected_files = {"sdk-stderr.log", "sdk-response.json", "request.json", "token.txt", "receipt.json"}
        listing = self.ssh("reference", "sudo find " + shlex.quote(attdir)
                           + " -mindepth 1 -maxdepth 1 -type f -printf '%f\\n'", check=False)
        actual_files = set(listing.stdout.decode().splitlines())
        for name in sorted(actual_files & expected_files):
            self.retrieve("reference", attdir + "/" + name, local / name)
        require(collection.returncode == 0 and listing.returncode == 0 and actual_files == expected_files,
                "Attestation collection failed or returned incomplete evidence; partial private evidence retained")
        self.validate_attestation_files(local, nonce, build)
        receipt = read_json(local / "receipt.json")
        missing = validate_receipt(receipt, nonce, build)
        self.record("acceptance-complete", {
            "result": "ACCEPTANCE_COMPLETE", "runId": self.c["runId"], "beforeBootId": first_boot,
            "afterBootId": after_boot, "buildSha256": digest((self.evidence / "build.json").read_bytes()),
            "signerSha256": digest((self.evidence / "signer.der").read_bytes()),
            "attestationVerification": receipt["verification"], "tokenMissingRequestedPcrs": missing,
            "limitations": ["MAA JWT signature/issuer/audience not cryptographically verified",
                            "AK certificate/TPM quote not independently verified",
                            "Event log not independently replayed against expected UKI/PCR11",
                            "Token PCR12 coverage may be absent; no claim of PCR12 attestation"],
        })

    def acceptance_managed(self, build):
        previous = None
        root = "/run/cvm-controller-" + self.c["runId"]
        for phase in ("first", "reboot"):
            script = "#!/bin/bash\nset -euo pipefail\numask 077\n"
            script += "test ! -e " + shlex.quote(root) + "\ninstall -d -m 700 " + shlex.quote(root) + "\n"
            for path, name in ((RECIPE / "verify-guest.py", "verify-guest.py"),
                               (self.evidence / "build.json", "build.json"),
                               (self.evidence / "signer.der", "signer.der")):
                data = path.read_bytes()
                destination = shlex.quote(root + "/" + name)
                script += "printf %s " + base64.b64encode(data).decode() + " | base64 -d > " + destination + "\n"
                script += "echo " + shlex.quote(digest(data) + "  " + root + "/" + name) + " | sha256sum -c -\n"
            script += "python3 " + " ".join(shlex.quote(root + "/" + name)
                                          for name in ("verify-guest.py", "build.json", "signer.der"))
            if previous:
                script += " --previous-boot-id " + shlex.quote(previous)
            script += " > " + shlex.quote(root + "/acceptance.json") + "\necho CVM_MANAGED_ACCEPTANCE_PASSED\n"
            self.managed("cvm-reference-" + phase, script, "CVM_MANAGED_ACCEPTANCE_PASSED",
                         timeout=1800, role="reference")
            content = self.retrieve("reference", root + "/acceptance.json",
                                    self.evidence / ("acceptance-" + phase + ".json"))
            boot = validate_acceptance(json.loads(content), build, previous)
            self.remove_reference_commands()
            if phase == "first":
                previous = boot
                self.az("vm", "restart", "-g", self.c["resourceGroup"], "-n", self.c["referenceVm"],
                        timeout=600)
        self.record("acceptance-complete", {
            "result": "ACCEPTANCE_COMPLETE", "runId": self.c["runId"],
            "validationTransport": "managed", "beforeBootId": previous, "afterBootId": boot,
            "buildSha256": digest((self.evidence / "build.json").read_bytes()),
            "signerSha256": digest((self.evidence / "signer.der").read_bytes()),
            "attestationCollection": "DEFERRED_TO_SSH",
            "attestationVerification": "NOT_RUN: invoke the installed collector over authenticated SSH after start",
            "limitations": ["Managed basic acceptance does not test SSH connectivity or obtain an MAA token",
                            "Expected-image remote verification and PCR12 token coverage remain unqualified"],
        })

    def validate_attestation_files(self, local, nonce, build):
        spec = importlib.util.spec_from_file_location("dracut_attestation_validation", RECIPE / "attest-guest.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        response = read_json(local / "sdk-response.json")
        request, pcr11 = verifier.validate_response(response, self.c["maaEndpoint"])
        require(request["IsolationInfo"]["Type"] == "Tdx", "Intel TDX guest evidence is required")
        require(read_json(local / "request.json") == request
                and (local / "token.txt").read_text().strip() == response["token"],
                "Retrieved token/request differ from the SDK response")
        receipt = read_json(local / "receipt.json")
        require(receipt.get("reportedPcr11Sha256") == pcr11, "Receipt PCR11 differs from actual SDK evidence")
        validate_receipt(receipt, nonce, build)
        claims = json.loads(verifier.decode(response["token"].split(".")[1]))
        covered = claims["x-ms-azurevm-attested-pcrs"]
        missing = sorted(set(PCRS) - set(covered))
        require(receipt["tokenClaimsUnverified"] == {
            "reportedPcrs": covered, "reportedPcrValuesSha256": {
                str(index): verifier.decode(claims["x-ms-azurevm-attested-pcr-values"][f"pcr{index}"]).hex()
                for index in covered},
            "missingRequestedPcrs": missing, "requestedCoverageComplete": not missing,
        }, "Receipt differs from the actual unverified token claims")
        for name in ("receipt.json", "sdk-response.json", "request.json", "token.txt", "sdk-stderr.log"):
            record = read_json(self.evidence / (name + "-transfer.json"))
            require(digest((local / name).read_bytes()) == record["sha256"],
                    "Retained attestation artifact hash differs from authenticated retrieval")

    def deallocate(self, role, wait=True):
        self.owned_group()
        self.vm(role)
        self.az("vm", "deallocate", "-g", self.c["resourceGroup"], "-n", self.c[role + "Vm"],
                *(["--no-wait"] if not wait else []), timeout=600)
        if wait:
            def fetch():
                view = self.az("vm", "get-instance-view", "-g", self.c["resourceGroup"], "-n", self.c[role + "Vm"])
                self.record(role + "-deallocation", view)
                return view
            self.poll(fetch, lambda item: any(status.get("code") == "PowerState/deallocated"
                                              for status in item.get("instanceView", {}).get("statuses", [])),
                      "VM deallocation", timeout=600)

    def failure(self, error):
        self.record("failure", {"result": "DEPLOYMENT_FAILED", "error": str(error),
                                "evidencePreserved": True, "deallocation": "not yet confirmed"})
        print("DEPLOYMENT_FAILED; preserving private evidence and resources at " + str(self.run), file=sys.stderr)
        if not self.group_created:
            return
        try:
            self.owned_group()
            inventory = self.az("vm", "list", "-g", self.c["resourceGroup"])
        except DeploymentError as ownership_error:
            print("WARNING: failure deallocation could not establish ownership: " + str(ownership_error), file=sys.stderr)
            return
        for role in ("builder", "reference"):
            matches = [item for item in inventory if item["name"] == self.c[role + "Vm"]]
            if not matches:
                continue
            try:
                self.owned(matches[0], role)
                self.deallocate(role, wait=False)
                self.record(role + "-failure-deallocation", {"requested": True, "confirmed": False})
            except DeploymentError as deallocation_error:
                self.record(role + "-failure-deallocation", {"requested": False, "error": str(deallocation_error)})
                print("WARNING: owned VM deallocation failed: " + str(deallocation_error), file=sys.stderr)

    def acceptance_gate(self):
        summary = read_json(self.evidence / "acceptance-complete.json")
        require(summary.get("result") == "ACCEPTANCE_COMPLETE" and summary.get("runId") == self.c["runId"],
                "Cleanup retain requires complete successful acceptance")
        build = read_json(self.evidence / "build.json")
        require(summary.get("buildSha256") == digest((self.evidence / "build.json").read_bytes())
                and summary.get("signerSha256") == digest((self.evidence / "signer.der").read_bytes()),
                "Acceptance independent input hashes changed")
        before = validate_acceptance(read_json(self.evidence / "acceptance-first.json"), build)
        after = validate_acceptance(read_json(self.evidence / "acceptance-reboot.json"), build, before)
        require(summary.get("beforeBootId") == before and summary.get("afterBootId") == after,
                "Acceptance boot evidence changed")
        transport = self.c.get("validationTransport", "ssh")
        require(summary.get("validationTransport", "ssh") == transport, "Acceptance transport changed")
        if transport == "managed":
            require(summary.get("attestationCollection") == "DEFERRED_TO_SSH"
                    and summary.get("attestationVerification", "").startswith("NOT_RUN:"),
                    "Managed acceptance must explicitly defer attestation to SSH")
        else:
            challenge = read_json(self.evidence / "challenge.json")
            require(challenge["bootId"] == after and challenge["endpoint"] == self.c["maaEndpoint"],
                    "Attestation challenge is not tied to the accepted boot/endpoint")
            validate_receipt(read_json(self.evidence / "attestation/receipt.json"), challenge["nonceHex"], build)
            self.validate_attestation_files(self.evidence / "attestation", challenge["nonceHex"], build)
        profile = public_profile((self.evidence / "signer.der").read_bytes())
        gallery = self.rest("get", version_id(self.c), api=GALLERY_API, expand="ReplicationStatus,UefiSettings")
        validate_gallery(gallery, profile, self.c)
        self.record("retained-gallery", gallery)

    def delete_owned_resource(self, ident, role):
        model = self.az("resource", "show", "--ids", ident)
        self.owned(model, role)
        self.az("resource", "delete", "--ids", ident, timeout=1800)

    def cleanup(self, remove=False):
        self.owned_group()
        if remove:
            # Delete only this run's dedicated RG, never local directories.
            self.az("group", "delete", "--name", self.c["resourceGroup"], "--yes", "--no-wait")
            self.poll(lambda: {"exists": self.az("group", "exists", "--name", self.c["resourceGroup"])},
                      lambda value: value["exists"] is False, "Resource group deletion", timeout=2400)
            self.record("cleanup-summary", {"resourceGroupDeleted": True, "localEvidenceRetained": True})
            return
        self.acceptance_gate()
        self.check_reference_model(self.vm("reference"))
        self.deallocate("reference")
        inventory = self.az("vm", "list", "-g", self.c["resourceGroup"])
        builders = [item for item in inventory if item["name"] == self.c["builderVm"]]
        if builders:
            builder = self.vm("builder")
            self.deallocate("builder")
        else:
            builder = self.owned(read_json(self.evidence / "builder-model.json"), "builder")
        resources = self.az("resource", "list", "-g", self.c["resourceGroup"])
        if any(resource["name"] == self.c["storageAccount"] for resource in resources):
            role_file = self.evidence / "upload-role.json"
            require(role_file.is_file(), "Missing upload role evidence")
            role = read_json(role_file)
            expected_scope = (base_id(self.c) + "/providers/Microsoft.Storage/storageAccounts/"
                              + self.c["storageAccount"] + "/blobServices/default/containers/" + self.c["container"])
            actual = self.az("role", "assignment", "list", "--scope", expected_scope)
            matching = [item for item in actual if item["id"].lower() == role["id"].lower()]
            if matching:
                require(matching[0]["principalId"] == builder["identity"]["principalId"]
                        and matching[0]["scope"].lower() == expected_scope.lower()
                        and matching[0]["roleDefinitionId"].lower().endswith("/ba92f5b4-2d11-453d-a403-e96b0029c9fe"),
                        "Refusing to revoke an unrelated upload role")
                self.az("role", "assignment", "delete", "--ids", role["id"])
            require(not any(item["id"].lower() == role["id"].lower()
                            for item in self.az("role", "assignment", "list", "--scope", expected_scope)),
                    "Upload role assignment remains after deletion")
        if builders:
            self.az("vm", "delete", "-g", self.c["resourceGroup"], "-n", self.c["builderVm"], "--yes", timeout=1800)
        # Inspect actual inventory before deleting: cleanup is safely repeatable.
        resources = self.az("resource", "list", "-g", self.c["resourceGroup"])
        for name, role in ((self.c["builderVm"] + "-nic", "builder"), (self.c["builderVm"] + "-os", "builder"),
                           (self.c["sourceDisk"], "source"), (self.c["storageAccount"], "upload")):
            for resource in resources:
                if resource["name"] == name:
                    self.delete_owned_resource(resource["id"], role)
        remaining = self.az("resource", "list", "-g", self.c["resourceGroup"])
        temporary = {self.c["builderVm"], self.c["builderVm"] + "-nic", self.c["builderVm"] + "-os",
                     self.c["sourceDisk"], self.c["storageAccount"]}
        require(not any(item["name"] in temporary for item in remaining), "Temporary resources remain after cleanup")
        vms = self.az("vm", "list", "-g", self.c["resourceGroup"])
        require(len(vms) == 1 and vms[0]["name"] == self.c["referenceVm"], "Unexpected retained VM inventory")
        self.record("cleanup-summary", {"temporaryResourcesDeleted": True, "referenceDeallocated": True,
                                       "galleryVersion": version_id(self.c), "resources": remaining,
                                       "sshAccess": "USER_CONFIRMATION_REQUIRED",
                                       "referenceVm": self.c["referenceVm"],
                                       "resourceGroup": self.c["resourceGroup"]})

    def deploy(self):
        try:
            self.preflight()
            self.network()
            self.new_vm("builder", self.c["builderImage"])
            build, provenance, profile = self.build()
            self.publish(build, provenance, profile)
            self.new_vm("reference", version_id(self.c))
            self.acceptance(build)
            self.cleanup()
        except BaseException as error:
            self.failure(error)
            raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    subs = result.add_subparsers(dest="action", required=True)
    deploy = subs.add_parser("deploy")
    for flag in ("subscription-id", "resource-group", "prefix", "ssh-public-key"):
        deploy.add_argument("--" + flag, required=True)
    deploy.add_argument("--ssh-private-key")
    deploy.add_argument("--location", default="westus3")
    deploy.add_argument("--vm-size", default="Standard_DC4es_v6")
    deploy.add_argument("--run-directory")
    deploy.add_argument("--maa-endpoint")
    deploy.add_argument("--validation-transport", choices=("managed", "ssh"), default="managed",
                        help="Managed basic acceptance by default; ssh also collects installed SDK evidence")
    deploy.add_argument("--ssh-source-cidr", help="Approved corporate RFC1918 source; controller must have private routing")
    deploy.add_argument("--ssh-jump-host", help="Optional user@host on an existing approved SSH path; uses the same private key")
    deploy.add_argument("--ssh-jump-known-hosts", help="Independently authenticated ED25519 known-hosts file for --ssh-jump-host")
    deploy.add_argument("--network-address-prefix", default="10.73.0.0/24")
    deploy.add_argument("--subnet-prefix", default="10.73.0.0/26")
    deploy.add_argument("--builder-image", default=BUILDER_IMAGE, help="Pinned standard Ubuntu 24.04 server URN")
    deploy.add_argument("--plan", action="store_true")
    cleanup = subs.add_parser("cleanup")
    cleanup.add_argument("--run-directory", required=True)
    cleanup.add_argument("--remove-run", action="store_true")
    return result


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.action == "deploy":
        config = configuration(args)
        if args.plan:
            print(json.dumps(config, indent=2))
            return 0
        ssh_validation = args.validation_transport == "ssh"
        if ssh_validation:
            require(args.ssh_private_key, "SSH validation requires --ssh-private-key")
            require(args.maa_endpoint, "SSH validation requires an approved --maa-endpoint; no provider/policy will be created")
            require(args.ssh_source_cidr, "SSH validation requires --ssh-source-cidr and approved private reachability")
        else:
            require(not (args.ssh_private_key or args.ssh_source_cidr or args.ssh_jump_host),
                    "Managed validation does not use SSH credentials/routing options; select --validation-transport ssh")
            require(ARTIFACT_READER.is_file(),
                    "Managed artifact retrieval requires the full checkout and legacy Read-ArtifactChunk.py helper")
        validate_public_key(Path(config["sshPublicKey"]))
        for tool in ("az", "tar", "openssl") + (("ssh", "ssh-keygen") if ssh_validation else ()):
            require(shutil.which(tool), "Missing required tool: " + tool)
        private = Path(args.ssh_private_key).expanduser().resolve() if ssh_validation else None
        if ssh_validation:
            require(private.is_file(), "SSH private key file does not exist")
        if config["sshJumpHost"]:
            known = Path(config["sshJumpKnownHosts"])
            require(known.is_file(), "SSH jump known-hosts file does not exist")
            host = config["sshJumpHost"].split("@")[1]
            command(["ssh-keygen", "-F", host, "-f", known])
        if ssh_validation and os.name != "nt":
            require(private.stat().st_mode & 0o077 == 0, "SSH private key must have mode 0600 or stricter")
        if ssh_validation:
            private_fingerprint = command(["ssh-keygen", "-lf", private]).stdout.decode().split()
            public_fingerprint = command(["ssh-keygen", "-lf", config["sshPublicKey"]]).stdout.decode().split()
            require(len(private_fingerprint) >= 2 and len(public_fingerprint) >= 2
                    and private_fingerprint[1] == public_fingerprint[1],
                    "SSH private/public key pair does not match (encrypted keys need a noninteractive SSH agent)")
        run = Path(config["runDirectory"])
        run.parent.mkdir(parents=True, exist_ok=True)
        run.mkdir(mode=0o700)
        (run / "evidence").mkdir(mode=0o700)
        write_json(run / "config.json", config)
        private_write(run / "empty-global-known-hosts", "")
        if config["sshJumpHost"]:
            private_write(run / "ssh-jump.config", jump_configuration(config, private))
        if os.name == "nt":
            print("WARNING: Windows ACLs are inherited; the run directory's parent must already be restricted to the operator. POSIX modes do not enforce Windows ACLs.", file=sys.stderr)
        Engine(config, str(private) if private else None).deploy()
        attestation = "NOT_VERIFIED" if ssh_validation else "NOT_RUN; collect over authenticated SSH after start"
        print("DEPLOYMENT_ACCEPTED: Gallery retained; reference deallocated; attestation " + attestation + "; evidence=" + str(run))
        print("SSH_HANDOFF: VM=" + config["resourceGroup"] + "/" + config["referenceVm"]
              + "; confirm or reconfigure approved network access before user-driven SSH/SDK testing."
              + " Start the VM when needed and authenticate its current host key through Azure diagnostics.")
    else:
        run = validate_run_path(args.run_directory, must_be_new=False)
        config = read_json(run / "config.json")
        require(config.get("schemaVersion") == 1 and config.get("purpose") == PURPOSE
                and Path(config["runDirectory"]).resolve() == run, "Invalid run ownership configuration")
        uuid.UUID(config["runId"])
        require(shutil.which("az"), "Missing required tool: az")
        if not args.remove_run:
            require(shutil.which("openssl"), "Missing required tool: openssl")
        engine = Engine(config)
        engine.group_created = True
        try:
            engine.cleanup(args.remove_run)
        except BaseException as error:
            engine.failure(error)
            raise
        print("RUN_REMOVED_LOCAL_EVIDENCE_RETAINED" if args.remove_run else "TEMPORARY_RESOURCES_REMOVED_REFERENCE_DEALLOCATED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DeploymentError, OSError, ValueError, KeyError, TypeError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
