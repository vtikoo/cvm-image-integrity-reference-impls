# Ubuntu 24.04 CVM: Dracut verity lower + tmpfs upper

[All configurations](../../README.md) | [Validation scope](VALIDATION.md)

Run commands from this configuration directory:

```text
ubuntu/dracut-verity-tmpfs-root
```

Build an image from a pinned, unbooted Ubuntu 24.04 CVM Marketplace disk,
publish it in **your** private Azure Compute Gallery, and launch **your**
Confidential VM with Secure Boot and vTPM. No access to the original test
resources or signing keys is required.

This independent recipe uses **Dracut/systemd**, not Canonical snap-bootstrap.
The signed UKI embeds the root hash and both verity partition identifiers.
The effective root is a writable overlay backed by tmpfs over a read-only
dm-verity lower; it has no writable disk fallback.

### Related reference

See Azure's [AzureStack-Tools Confidential Computing CVM Image Builder](https://github.com/Azure/AzureStack-Tools/tree/master/ConfidentialComputing/CvmImageBuilder)
for another Dracut/systemd, UKI and dm-verity implementation. This recipe is not
a direct port: that builder creates Ubuntu with `debootstrap`, uses SquashFS and
limits writable state to selected directories; this recipe preserves the pinned
Marketplace kernel/modules and uses an ext4 verity lower with a whole-root tmpfs
overlay.

**Experimental:** manual Gallery 1.0.4 publication, Intel TDX first/reboot SSH
acceptance and installed native-collector MAA testing passed. The shared controller
built/uploaded a fresh image and completed Gallery replication; recovered managed
first/reboot acceptance and cleanup also passed. An uninterrupted one-command
deployment has not yet been demonstrated. PCR12 token coverage, stateless boot and production-complete
expected-image remote verification remain unqualified.

## Supported baseline

| Component | Pin or demonstrated configuration |
| --- | --- |
| Marketplace image | `Canonical:ubuntu-24_04-lts:cvm:24.04.202610280` |
| Demonstrated source kernel | `7.0.0-1016-azure-fde`, with matching source modules |
| Boot integration | Ubuntu 24.04, Dracut 060 / systemd 255 families |
| Attestation SDK | Commit `8774be30f452060c56372d34ccbe34c3d3f3c577` plus the SHA-256-pinned [native systemd log patch](patches/sdk-systemd-event-log.patch) |
| Attestation PCR selection | Exactly `0-8,11,12`; tested MAA token covers `0-8,11` |
| Reference CVM | `Standard_DC4es_v6`, Intel TDX, Secure Boot/vTPM, `VMGuestStateOnly` |
| Builder | Dedicated Ubuntu 24.04 x86-64 Linux, separate from the reference CVM |
| Controllers | Bash on Linux or PowerShell 7 on Windows, both using Python 3 |

The source pin and SDK patch hash are in [inputs.json](inputs.json).
Never substitute the builder kernel or silently select a newer Marketplace
version. Source provenance, layout, signed modules, original kernel, signed
UKI sections and fixed-VHD checks are build gates.

## Testing components and production hardening

This is a build/boot and attestation **test reference, not a production-hardened
image**. It preserves cloud-init, the Azure Linux Guest Agent, SSH and inherited
Ubuntu update facilities for provisioning, compatibility and testing. Their
presence is not a recommendation to retain these management paths in production.

dm-verity protects the lower filesystem, not all runtime behavior. Privileged
cloud-init modules, guest extensions or SSH sessions can execute code and shadow
verified files through the writable tmpfs upper without changing the lower
disk. Passing root-policy checks or collecting a MAA token does not demonstrate
that these runtime management paths are hardened.

Before using a derivative image in production, define and validate a hardening
policy appropriate to the workload. Examples include:

| Component | Purpose in this test reference | Production hardening |
| --- | --- | --- |
| cloud-init | Azure metadata/network setup, deployment-supplied username/public key and the controller's custom-data SSH host-key publication | Restrict modules and user-data processing, following the [Azure sample's restricted cloud-init policy](https://github.com/Azure/AzureStack-Tools/blob/master/ConfidentialComputing/CvmImageBuilder/rootfs-files/cloud-init-hardened.yaml) as a starting point. Block arbitrary user/vendor-data execution and retain only required provisioning/metadata behavior. |
| Azure Linux Guest Agent (`waagent`/`walinuxagent`) | Managed Run Command, VM extensions and platform integration used during testing | Remove the guest agent from the production image when these management features are not required. Review provisioning and platform-reporting implications; Managed Run Command and agent-based extensions will no longer be available. This agent is distinct from the installed attestation collector. |
| OpenSSH server | Interactive diagnostics, SSH acceptance and manual collector execution | Disable SSH, including both `ssh.service` and socket activation through `ssh.socket`; remove the server if unnecessary and close inbound SSH access. Use an explicitly designed production attestation/operations path instead. |
| Ubuntu automatic updates | Inherited Marketplace facilities; this recipe does not establish a hardened update policy | Disable automatic APT/unattended upgrades, including `apt-daily.timer` and `apt-daily-upgrade.timer`, and review any other retained automatic updaters. Deliver security fixes through controlled image rebuilds and redeployment instead. |

Do not copy the sample's cloud-init configuration unchanged while expecting this
reference's deployment workflow to keep working: the sample disables runtime
user creation, whereas this controller supplies the login username/key through
Azure provisioning and uses a cloud-init `bootcmd` for host-key publication.
A hardened derivative must replace or deliberately retain those specific
provisioning functions and verify that untrusted input cannot re-enable excluded
behavior.

Apply production changes **during image construction, before verity generation
and UKI signing**, then rebuild, publish and qualify the resulting image and its
expected measurements. Runtime changes to this test VM disappear at reboot.
The existing managed/SSH acceptance paths intentionally depend on the retained
test components; production images without them need an alternative validation
and attestation path, not silently skipped checks. These examples are not a
complete production security baseline.

## Choose where to build

| Workflow | Image preparation | Azure VMs |
| --- | --- | --- |
| [deploy.sh](deploy.sh) or [Deploy.ps1](Deploy.ps1) | Automatically provisioned dedicated Azure builder | Builder + reference; maximum two |
| [Manual Linux workflow](LOCAL-BUILD.md) | Your existing exclusive Ubuntu 24.04 builder | One reference CVM; no automatic builder |

Running the Bash controller on Linux does **not** make that host the builder.
Both entry points call the same [Python engine](scripts/deploy.py), so
ownership, publication, SSH and cleanup gates are shared rather than duplicated.
Neither controller invokes the legacy Canonical producer or snap-bootstrap
build. The unbooted source is a disk, not a third VM.

The manual workflow remains available through [build-image.sh](build-image.sh).
Never run image mounts/builds on a shared or production host.

## Prerequisites for automatic deployment

- Python 3, Azure CLI, OpenSSL and `tar` on the controller.
  Windows additionally requires PowerShell 7; Linux does not require PowerShell.
  The optional SSH-validation mode also needs OpenSSH client tools.
- `az login` using your organization's permitted authentication flow.
- An existing OpenSSH keypair. Supply only the public key for provisioning;
  the private key stays on your client for later SSH. Default managed acceptance
  does not need the private key.
- A new dedicated resource group and a new private run directory outside the
  checkout. Protect Windows evidence using a private user directory/appropriate
  ACLs; tokens and raw VM evidence must not be shared or committed.
- Permission/quota for the builder and selected CVM, disks, networking,
  Gallery, private upload storage and container-scoped role assignments.
- Default basic acceptance and build-artifact retrieval use Azure Managed Run
  Command, so no inbound route, jump host or peering is required.
- Optional `--validation-transport ssh` requires an approved network path from
  the controller to builder/reference SSH.
  Supply the approved RFC1918 source with `--ssh-source-cidr` /
  `-SshSourceCidr`; the VMs have private addresses only. The controller creates
  an outbound NAT gateway, not inbound public VM addresses or Internet SSH
  rules during validation. Organization policy and existing private routing must permit access
  to the new subnet; the controller does not establish hub peering or VPNs.
- An explicit approved MAA `AzureGuest` endpoint for optional SSH-mode SDK
  collection or later manual SDK runs. The controller does not
  create a provider or weaken its policy. Default policies may reject custom
  firmware signers. To create a separately owned test provider, use the opt-in
  [Azure CLI setup helper](scripts/setup-maa-test-provider.py) and
  [creation, policy-readback and cleanup instructions](LOCAL-BUILD.md#create-your-own-test-provider).
  It removes only the `dbvalidated=false` denial; this is not production
  expected-image verification.
- Approved guest outbound access to package repositories, Rust distribution,
  GitHub, Azure management/extension endpoints, restricted upload storage and
  the approved MAA provider.

The default CVM region is `westus3`; confirm your own capacity and quota.
`--plan` / `-Plan` makes no Azure calls, writes no files and needs no existing
key files or credentials.

## Run on Linux

Preview first:

```bash
bash deploy.sh --subscription-id '<your-subscription-guid>' \
  --resource-group rg-my-dracut --prefix mydracut \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --location westus3 --plan
```

Remove `--plan` to deploy. Optional `--vm-size` and `--run-directory` select the
reference size and private evidence directory (default
`$HOME/cvm-dracut-runs/<prefix>`). `--network-address-prefix` and `--subnet-prefix`
select a non-overlapping private network compatible with your approved routing.
Existing resource groups and
run directories are rejected; failed runs are not silently resumed.

Default `--validation-transport managed` verifies first boot and a real reboot
through Managed Run Command. Installed collector hashes/provenance are checked,
but the SDK is **not run** and no MAA token is collected; the result records
`NOT_RUN` / `DEFERRED_TO_SSH`. After success, the reference remains deallocated.

### User-driven SSH and SDK testing

The controller retains the reference **deallocated and private-only**. Its
completion message identifies the resource group/VM and asks you to confirm or
reconfigure approved network access before SSH testing. The cleanup summary
records `sshAccess: USER_CONFIRMATION_REQUIRED`; this is not a successful SSH
connectivity check.

1. Inspect the retained VM's NIC/subnet NSGs, applicable corporate policies and
   routing. Confirm an approved private route, VPN or jump host. If public SSH is
   appropriate, configure its public endpoint and corporate-only source rules
   yourself under your organization's policy; never allow unrestricted Internet
   SSH.
2. Do not assume subscription defaults provide the required access. Check the
   effective rules on both NIC and subnet, including any higher-priority deny.
   The controller neither copies another VM's NSGs nor attaches a public VM IP
   or changes networking after acceptance.
3. Start the reference when needed. Authenticate its current host key through
   Azure boot diagnostics, then use your private login key to SSH and run the
   installed collector against your approved MAA endpoint. Each reboot
   regenerates the host key; never blindly accept a replacement.
4. Deallocate the reference again after manual testing to avoid compute charges.

To preserve the earlier end-to-end SSH acceptance/SDK-collection workflow,
select `--validation-transport ssh` and supply `--ssh-private-key`,
`--ssh-source-cidr` and `--maa-endpoint`. That mode still requires private routing
during acceptance; the later user-driven network handoff does not establish that route.
If the approved private route is through an existing SSH jump host, also add:

```bash
  --ssh-jump-host '<jump-user>@<approved-jump-address>' \
  --ssh-jump-known-hosts '/private/independently-authenticated-jump-known-hosts'
```

Both options are required together. The jump host uses the supplied private
key, independently pinned ED25519 host keys and strict checking; guest trust
remains independently pinned per boot. No agent forwarding is enabled.
Set `--ssh-source-cidr` to the jump host's private source CIDR and establish
approved routing/peering to the new subnet beforehand. The controller does not
create peering or change an existing jump host's ingress rules.

## Run with PowerShell

```powershell
.\Deploy.ps1 -SubscriptionId '<your-subscription-guid>' `
  -ResourceGroup 'rg-my-dracut' -Prefix 'mydracut' `
  -SshPublicKey "$HOME\.ssh\id_ed25519.pub" `
  -Location westus3 -Plan
```

Remove `-Plan` to execute. The PowerShell entry point requires the same Python
engine, not Git Bash, and has the same lifecycle and validation boundaries.
`-ValidationTransport managed` is the default. `-ValidationTransport ssh`
requires `-SshPrivateKey`, `-SshSourceCidr` and `-MaaEndpoint`.
`-NetworkAddressPrefix`, `-SubnetPrefix` and `-BuilderImage` match the corresponding
Bash options. `-SshJumpHost` and `-SshJumpKnownHosts` provide the same opt-in
authenticated jump path. Plan still validates CIDR syntax, so replace the example
placeholders even when previewing.

## What the controllers do

1. Validate inputs, dedicated resource ownership, image availability and quota.
2. Create the builder/network, install build prerequisites, and prepare the
   pinned, unbooted source disk without booting or mounting it writable.
3. Generate an RSA signer inside the builder; its private key never leaves.
4. Build the matching-kernel Dracut initramfs and signed UKI. Install the patched
   native SDK and expanded-PCR wrapper **before hashing**; verify installed
   binary/wrapper/provenance and retain independent build evidence.
5. Generate verity data, check exact UKI sections/signature and fixed-VHD format.
   Upload privately using the builder's managed identity,
   without storage account keys or SAS.
6. Publish the exact public signer plus Microsoft UEFI template. Require
   completed Gallery replication and exact signer/template readback.
7. Launch a `ConfidentialVM` with Secure Boot, vTPM and `VMGuestStateOnly`;
   verify its actual Azure security/image model.
8. Stage the independent inputs and verifier through Managed Run Command. Check
   firmware signer, kernel, live verity/hash/devices and read-only lower mount,
   tmpfs, agents/cloud-init and installed collector provenance.
9. Create the measured volatile workload, remove owned test commands, reboot
   through Azure and restage the verifier. Require a distinct boot ID plus loss
   of the complete workload. Retrieve JSON using compressed chunks with SHA256
   checks rather than relying on truncated command output.
10. Leave SDK execution to authenticated SSH after start (`NOT_RUN`), or in
    optional SSH-validation mode perform the installed-collector MAA collection.
11. Remove ownership-checked temporary build/upload resources and retain the
    Gallery image plus the **deallocated** reference CVM and local evidence.
    Provide a user-driven SSH/network-configuration handoff without changing
    the retained VM's networking.

In optional SSH-validation mode, authenticate the SSH host key through Azure
boot diagnostics. Stage the verifier and independent inputs; check firmware
signer, kernel, live verity/hash/devices, read-only lower mount, tmpfs,
agents/cloud-init and installed collector provenance.
Then authenticate the regenerated host key after reboot and collect from the
installed SDK with a fresh controller challenge and approved MAA endpoint;
retain explicit PCR12 coverage-gap reporting. No SDK override is used.

Guest acceptance confirms the mounted dm-verity lower and its expected hash/devices
on both boots; it does not scan all disk blocks. The default clean-room build
also omits full verification scans and deliberate corruption tests. They remain
available as [separately invoked qualification](LOCAL-BUILD.md#optional-disk-qualification),
not prerequisites for demonstrating the build/boot flow. Generating the verity
hash tree is still required.

No path disables Secure Boot, bypasses verity or changes centralized policy.
`VMGuestStateOnly` persists encrypted guest firmware/TPM state; it does not
request OS-disk encryption or an ephemeral OS disk.

## Validation and evidence

```bash
python3 tests/test_deployment.py
python3 tests/test_entrypoints.py
python3 tests/test_recipe.py
python3 tests/test_attestation.py
python3 tests/test_guest_validation.py
```

PowerShell entry-point checks:

```powershell
python .\tests\test_deployment.py
.\tests\Test-Entrypoints.ps1
```

Local controller tests mock Azure/SSH. The fresh managed run required controller
fixes and explicit recovery after publication; it is not an uninterrupted
one-command pass. Real userspace/SDK tests, manual Gallery 1.0.4 results and
the recovered managed Azure flow are distinguished in
[VALIDATION.md](VALIDATION.md).

Managed artifact retrieval reuses the legacy
[compressed chunk reader](../verity-tmpfs-root/scripts/Read-ArtifactChunk.py);
keep the full repository checkout available. This does not select the legacy
image producer or Canonical boot integration.

Keep configuration, independently retained build inputs, signer/readback,
first/reboot JSON, stderr, requested challenge and attestation evidence outside
the checkout. Both entry points submit REST JSON larger than 8 KiB through a
private request file using `--body @file`, following the legacy controller's
file-backed approach. WSL converts request paths for the Windows Azure CLI;
native Windows uses the CLI's bundled Python to avoid batch-file reparsing.
Failed Azure operations retain stdout/stderr privately rather than printing
potential credentials.

An SDK token/receipt is **not** a production remote verification
result. The wrapper says `NOT_VERIFIED`; collection and local consistency checks
do not authenticate expected UKI identity, AK/quote/TEE binding or quote
freshness. See [the relying-party requirements](LOCAL-BUILD.md#what-maa-does-and-what-the-verifier-must-check).

## Failure, retention and cleanup

Failures are explicit. The controller preserves evidence and requests
deallocation only of VMs whose run ownership is proven; verify the actual state
and ongoing retained-resource charges. Do not rerun over partial output.

To finish cleanup after a successful validated run:

```bash
bash cleanup.sh --run-directory '<private-run-directory>'
```

To remove the entire dedicated failed or retained run after inspecting evidence:

```bash
bash cleanup.sh --run-directory '<private-run-directory>' --remove-run
```

PowerShell equivalents:

```powershell
.\Cleanup.ps1 -RunDirectory '<private-run-directory>'
.\Cleanup.ps1 -RunDirectory '<private-run-directory>' -RemoveRun
```

Removal requires the resource group's matching run-ownership tags. It is not
an arbitrary resource-group deletion command, nor a mechanism to delete local
evidence. Removing the builder destroys its private signer; a later rebuild
needs a new signer/enrollment unless you retained an approved signing service.

## Limits

- Every writable root change disappears at reboot, including identities,
  logs, SSH host keys and agent state. Durable image changes belong before
  verity generation; application persistence is outside this recipe.
- The tmpfs upper can shadow executable/configuration files; the effective
  root is **not immutable**. Budget RAM for agents and workloads; do not add swap.
- Re-authenticate regenerated host keys. Never disable strict host-key checking
  or blindly accept an `ssh-keyscan` result.
- `NonPersistedTPM` remains blocked in the tested custom-key configuration.
  Do not disable Secure Boot to make a failed image boot.
- The tested custom-policy MAA token covers PCRs 0-8 and 11, **not PCR12**.
  Keep PCR12 in the request and do not claim complete coverage.
- No production-complete root-hash attestation, rollback protection,
  confidential OS-disk encryption or general CVM-family support is claimed.

For detailed boot/trust behavior, manual commands and SDK integration see
[LOCAL-BUILD.md](LOCAL-BUILD.md). Qualification history and explicit gaps are in
[VALIDATION.md](VALIDATION.md).
