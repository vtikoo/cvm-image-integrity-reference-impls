# CVM Image Integrity Reference Implementations

Reference implementations, deployment recipes, instructions, and validation for
Confidential VM image integrity. The common theme is enforcing and verifying image integrity, not a
particular Linux distribution or writable-root configuration.

## Configurations

| Configuration | Status |
| --- | --- |
| Canonical Ubuntu 22.04 CVM: dm-verity lower + volatile tmpfs upper | Implemented; documented below |
| Additional writable-state configurations and distributions, such as Azure Linux | Future extensions; not implemented |

The current `deploy.sh` (Linux) and `Deploy.ps1` (PowerShell) entry points run
the Canonical Ubuntu/tmpfs recipe only.
New configurations can add their own distro-specific preparation and boot
mechanisms while documenting their integrity guarantees and validation evidence.

## Current recipe: Canonical Ubuntu with a tmpfs root

Build your own image from a pinned Ubuntu 22.04 Confidential VM Marketplace
image, publish it in **your** private Azure Compute Gallery, and deploy **your**
Confidential VM with Secure Boot and vTPM enabled. No access to the original
author's Azure resources or private signing keys is required.

This recipe is a **custom-initrd / custom-signed UKI proof of concept**, not a stock-UKI
demonstration or production root-filesystem attestation solution.

## Supported baseline for the current recipe

The recipe deliberately pins the version that was demonstrated:

| Component | Pin |
| --- | --- |
| Marketplace image | `Canonical:ubuntu-22_04-lts:cvm:22.04.202610220` |
| Kernel | `6.8.0-1068-azure-fde` |
| Canonical snap-bootstrap | `2.76+ubuntu22.04.1` |
| Producer | [fork commit `5dc3d3f`](https://github.com/vtikoo/encrypt-cloud-image/commit/5dc3d3f85fdfa6f5bae8bc01edcbf55b2adcfabe) |
| Upstream producer starting point | PR 26, `dc393b4e94c48283ed8955f5d2623210a51c5239` |
| Demonstrated SKU | `Standard_DC4as_v6` |
| Controllers | Linux with Bash 4+; or PowerShell 7 on Windows |

Subscription, names, region, and DCas_v6 size are configurable. This is not an
automatic converter for arbitrary Ubuntu versions: kernel/module compatibility,
UKI identity, disk geometry, and manifest support are hard gates. Do not change
the Marketplace version to `latest` without revalidating those gates.

The original component scripts passed real Azure first-boot and reboot
acceptance. This extracted, parameterized entry point has local/CI validation;
a fresh-account deployment of the packaged entry point is not claimed.

## Prerequisites

- **Linux:** Bash 4+, Azure CLI, `jq`, Python 3, OpenSSL, GNU core utilities,
  `gzip`, and `tar`. PowerShell is **not** required for deployment or cleanup.
- **Windows:** PowerShell 7, Azure CLI, and `tar`; Git Bash is needed for local
  shell syntax tests.
- `az login` using an authentication flow allowed by your organization's policy.
- An existing OpenSSH **public** key file, such as `$HOME\.ssh\id_ed25519.pub`.
  Do not supply a private key.
- Permission to create a dedicated resource group, VMs/disks/networking, private
  Gallery and storage, and a container-scoped role assignment for the helper's
  managed identity (Contributor alone does not grant role-assignment permission).
- Quota/capacity for **two** selected CVMs in your chosen region. The recipe
  checks regional and VM-family CPU quota before allocation.
- Allowed guest outbound access to Ubuntu repositories, GitHub/Go dependencies,
  Azure management/extension endpoints, and the restricted upload storage.

The default region is `westus3`; choose a region with your own quota. No
subscription, tenant, private key, storage credential, or original run evidence
is included in this repository.

## Run on Linux

Clone this repository and review the scripts. Preview the configuration without
Azure calls, an existing key file, or resource creation:

```bash
bash deploy.sh --subscription-id '<your-subscription-guid>' \
  --resource-group rg-my-cvm-tmpfs --prefix mycvm \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" --location westus3 --plan
```

Remove `--plan` to deploy. Optional `--vm-size` and `--run-directory` correspond
to the PowerShell parameters. The default run directory is
`$HOME/canonical-cvm-runs/<prefix>`, outside the checkout. Existing run
directories and existing resource groups are rejected.

The Linux controller uses Azure CLI directly. It shares the guest-side UKI
rebuild, producer/image build, upload, artifact encoder, and first-boot/reboot
verification with the PowerShell controller, rather than invoking PowerShell.
It preserves the two-VM cap, ownership checks, execution-state/exit-code/marker
gates, hashed chunk retrieval, exact Gallery signer readback, and deallocation.

## Run with PowerShell

Clone this repository and review the scripts. Preview the derived configuration
without Azure calls or resource creation:

```powershell
.\Deploy.ps1 -SubscriptionId '<your-subscription-guid>' `
  -ResourceGroup 'rg-my-cvm-tmpfs' -Prefix 'mycvm' `
  -SshPublicKey "$HOME\.ssh\id_ed25519.pub" -Location westus3 -Plan
```

Then remove `-Plan` to execute. Use a **new, dedicated** resource group and a new
run directory. By default, configuration/evidence are saved outside the checkout
at `$HOME\canonical-cvm-runs\<prefix>`. An explicit `-RunDirectory` must also be
outside the repository.

The run:

1. Creates one helper from the pinned Marketplace image, with a system-assigned
   identity. Uses managed Run Command, not an inbound SSH allow rule.
2. Generates a new RSA-3072 signing key **inside the helper**, mode `0600`, and
   retrieves only its public certificate.
3. Rebuilds the initrd with the matching signed `dm-bufio`, `dm-verity`, and
   `overlay` modules and dependencies. Loads them before snap-bootstrap.
   Preserves the original kernel, command line, and every other UKI section.
4. Builds the pinned producer and its focused tests. Creates an **unbooted**
   Marketplace source disk and attaches it only after the helper is running.
   Never reboot the helper with this duplicate-layout source attached.
5. Finalizes/generalizes a disposable root copy before hashing, generates
   data/hash partitions and a one-lower-entry `read_only: true` manifest,
   installs the signed UKI, and verifies the fixed VHD and corruption enforcement.
6. Uploads through helper managed identity to a private, firewalled container.
   No SAS or storage account key is needed.
7. Publishes a `TrustedLaunchAndConfidentialVmSupported` Gallery definition and
   version with the helper's actual public signing certificate in UEFI `db`.
   Keeps `MicrosoftUefiCertificateAuthorityTemplate`.
8. Requires completed replication and exact signer/template readback using
   `$expand=ReplicationStatus,UefiSettings`. A successful PUT is insufficient.
9. Creates the second VM as **ConfidentialVM**, not Trusted Launch, with Secure
   Boot, vTPM, and `VMGuestStateOnly`.
10. Verifies the guest, firmware key, verity/tmpfs mounts, workload and real
    reboot. Deletes temporary build resources and leaves the reference VM
    **deallocated**, with the private Gallery image retained.

The scripts never disable Secure Boot, bypass verity, open inbound Internet SSH,
or alter centralized security policy. The helper and target use 64-GiB and
31-GiB OS disks respectively. Other retained resource charges still apply while
the target is deallocated.

## Validation and evidence

Linux controller tests use a strict local Azure CLI double, not Azure credentials:

```bash
python3 tests/test_bash.py
```

The test suite additionally uses `pwsh` to compare configuration with the
PowerShell controller; this is a **test-only** dependency, not a Linux deployment
dependency. CI supplies it. On Windows:

```powershell
.\tests\Test-Local.ps1
```

CI checks script syntax, configuration/plan guards, certificate-profile handling,
native Bash orchestration and failure paths against mocks, and builds/tests the
exact producer commit. CI does **not** create Azure resources or prove end-to-end
boot. A fresh Azure deployment driven by the Bash controller is not claimed.

A successful real run additionally requires:

- Canonical `snapd_recovery_mode=cloudimg-rootfs`, without an alternate
  `roothash=` / `systemd.volatile=overlay` boot path.
- Actual firmware `db` containing the certificate that signed the deployed UKI;
  actual Secure Boot enabled and a usable TPM device.
- Root overlay with a read-only dm-verity ext4 lower; expected root hash and live
  verity target/status `V`; upper/work on the same tmpfs; no swap.
- A 128-MiB write plus 2,048 small files, with byte/inode/memory measurements.
- Distinct boot IDs, disappearance of test writes and first-boot evidence, and
  full verification of the unchanged lower after reboot.
- Corrupted-clone verification/read failing with a verity I/O error.

First-boot managed test commands are removed before reboot so volatile agent
state cannot replay the workload and recreate its marker. Policy-owned managed
commands are not removed.

Inspect `evidence\verified-custom-uki-build.json`, `evidence\build`,
`evidence\gallery-image-version.json`, `evidence\reference-before-reboot-verified.json`,
`evidence\reference-after-reboot-verified.json`, `evidence\reboot-ids.json`, and
`evidence\cleanup-summary.json` under your run directory.

## Failure and cleanup

Errors are not treated as success. A failed run requests deallocation of VMs in
the ownership-tagged group; verify it completed. Keep evidence for diagnosis.
Do not blindly rerun over a partial build: stateful build stages reject
overwrites. After reviewing evidence, remove the entire failed run on Linux:

```bash
bash cleanup.sh --run-directory "$HOME/canonical-cvm-runs/mycvm" --remove-run
```

Without `--remove-run`, `cleanup.sh` requires successful reboot/Gallery evidence,
removes temporary build resources, and retains the deallocated reference and
Gallery. It is intended to finish a run whose validation passed but whose
cleanup did not complete; it does not silently resume arbitrary partial runs.

With PowerShell:

```powershell
.\scripts\custom-uki\Cleanup-CustomRun.ps1 `
  -RunDirectory "$HOME\canonical-cvm-runs\mycvm" -RemoveFailedRun
```

This verifies the resource group's run-ownership tag before deleting it.
The same command can remove a successful retained reference when you no longer
need it. Do not use a shared resource group. Removing the helper also destroys
its private UKI signing key; creating a new signed image requires a new signer
and corresponding enrollment.

## Limits and operational caveats

- **All writable root state disappears at reboot**, including package changes,
  machine identity, logs and agent state. Put durable image changes in the
  offline preparation stage before hashing; persistent application data is
  outside this recipe.
- The demonstrated environment consumed about 2.1 GiB of tmpfs before the smoke
  workload, including provisioned/policy-agent state. Budget RAM for your own
  agents and application writes; do not infer headroom from an empty overlay.
- On reboot, cloud-init can report recoverable provisioning-media warnings and
  fall back to IMDS. The observed guest had no fatal cloud-init errors, an active
  agent, and no failed systemd units. This recipe uses SSH public keys; do not
  assume IMDS fallback supports admin passwords or custom-data.
- The signing certificate is a short-lived 30-day POC certificate.
- `VMGuestStateOnly` is not a claim of OS-disk encryption.
- A signed UKI does **not** authenticate or attest the external manifest/root
  hash. No manifest-signature enforcement, remote root-hash attestation, GPU
  validation, or production security completeness is claimed.

## References

- [Producer fixes](https://github.com/vtikoo/encrypt-cloud-image/tree/poc/manifest-read-only-tmpfs)
- [Azure custom UEFI keys](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi)
- [Gallery version GET and UEFI expansion](https://learn.microsoft.com/en-us/rest/api/compute/gallery-image-versions/get)
