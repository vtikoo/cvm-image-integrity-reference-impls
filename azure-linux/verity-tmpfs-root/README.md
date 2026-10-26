# Azure Linux 3: verity lower + tmpfs upper

[All configurations](../../README.md) | [Validation scope](VALIDATION.md)

This is the Image Customizer configuration used for a functional Azure
root-verity/volatile-overlay experiment. It is **not a qualified Secure Boot or
Confidential VM reference**. The target base is the generic Azure Linux Gen2
Marketplace SKU, not the CVM SKU. The demonstrated VM used ConfidentialVM
security type and vTPM, but Secure Boot was **off**.

Run the commands below from `azure-linux/verity-tmpfs-root`. Unlike the Canonical
configuration, this directory provides an image-build wrapper and guest checks,
not an automated Azure resource/deployment controller. It contains no original
subscription/resource identifiers, SSH keys, signing material or raw run evidence.

## Pinned inputs

`inputs.json` records the exact build inputs; do not replace versions with
`latest` and assume the same boot integration.

| Component | Pin |
| --- | --- |
| Target base | `MicrosoftCBLMariner:azure-linux-3:azure-linux-3-gen2:3.20261022.01` |
| Image Customizer source | `microsoft/azure-linux-image-tools`, `ab96510020d9ae61d680ed999f71ca38bb8df784` |
| Dependency container | Digest pinned in `inputs.json`; its bundled IC executable is **not** used |
| Compiler | `go1.27.3 linux/amd64` |
| Package snapshot | `2026-10-25` |
| Observed kernel / systemd / dracut | `6.6.159.1-1.azl3` / `255-34.azl3` / `102-13.azl3` |
| Demonstrated region / size | westus3 / `Standard_DC4as_v6` |

The original builder used the Azure Linux 3 **CVM** SKU at the same Marketplace
version. That does not make the separately acquired **Gen2 target base** a CVM
base. Starting from the CVM target SKU is a separate, untested configuration.

## Image layout and boot

| Partition | Size | Purpose |
| --- | --- | --- |
| ESP | 512 MiB | UKI/add-on and EFI loader; runtime mount `/boot/efi`, read-only |
| Boot | 512 MiB | Separate `/boot`, read-only |
| Root data | 8 GiB | Protected ext4 data |
| Root hash | 256 MiB | Separate dm-verity hash tree |

There is no persistent `/var`, disk-backed upper or disk swap in the baseline.

```text
Pinned base + root-volatile.yaml + caller's SSH public key
  -> offline customization and initrd regeneration
  -> final root data + verity hash tree/root hash
  -> UKI + command-line add-on
  -> /dev/mapper/root, verified read-only, mounted at /sysroot in initrd
  -> systemd.volatile=overlay: lower=/sysroot, upper/work on tmpfs
  -> final writable /
```

Root verity/UKI support already exists in IC; no production Go patch is needed.
`storage.verity` and the filesystem's `deviceId: verityroot` select the verified
root. `systemd.volatile=overlay` only wraps that already-mounted root.
This does not use `os.overlays` to implement a root switch.

The YAML includes the demonstrated integration fixes:

- A `systemd-remount-fs` drop-in first requires an overlay on `/`, then remounts
  that effective root writable. Otherwise the root fstab `ro` option leaves the
  overlay read-only and cloud-init fails. The verity mapper remains read-only;
  there is no writable raw-root fallback.
- Dracut configuration is added before automatic initrd regeneration. The
  selected kernel has overlayfs built in; a missing `overlay.ko` alone is not a
  failure if `modules.builtin` proves support.
- Root filesystem growth is disabled before hashing.
- The boot random-seed updater is skipped on a read-only ESP.
- An empty Hyper-V KVP pool file avoids cloud-init's early missing-file race;
  no host KVP values are embedded.

## Build

Use a trusted Linux x86-64 builder; the demonstrated environment was Azure
Linux 3. Required tools are Bash, Docker with privileged-container access,
Git, Python 3, GNU core utilities and the exact Go compiler above.
The wrapper does not install host dependencies or create Azure resources.

1. Acquire an **unbooted** copy of the exact target Marketplace base into your
   own authorized scope. If using an attached source disk, keep it unmounted,
   confirm its LUN, and never boot the source or reboot the builder with it
   attached. Convert it to qcow2 outside this repository. For a source at LUN 0:

   ```bash
   container=$(python3 -c 'import json; print(json.load(open("inputs.json"))["dependencyContainer"])')
   base_directory="$HOME/azl-base"
   mkdir -p "$base_directory"
   docker pull "$container"
   docker run --rm --privileged -v /dev:/dev -v "$base_directory:/output" \
     --entrypoint /usr/bin/qemu-img "$container" convert -f raw -O qcow2 \
     /dev/disk/azure/scsi1/lun0 /output/base.qcow2
   ```

   Detach the disposable source disk after conversion. The wrapper consumes
   that qcow2 file read-only; it does not infer or verify its Marketplace origin.
   Record your acquisition/version evidence.

2. Supply your own existing **OpenSSH public key**, never a private key, and a
   new run directory outside this checkout:

   ```bash
   bash build-image.sh "$HOME/azl-base/base.qcow2" \
     "$HOME/.ssh/id_ed25519.pub" "$HOME/azl-integrity-runs/example"
   ```

   The wrapper compiles the pinned IC revision and overrides the container
   executable, applies the package snapshot and complete YAML, then performs
   read-only inspection. Existing run directories are rejected.

3. Retain `root-volatile.raw` and `evidence/` under the run directory. Evidence
   includes source-base/binary/output hashes, packages, GPT/fstab, final verity
   verification, extracted UKI/add-on command line and initrd inventory.
   Finalized ext4 inspection uses `ro,noload`; never replay its journal or
   customize the protected root after hash generation.

The fixed reference user is **`repro`**, with passwordless sudo for the
experiment. Your authorized public key is baked into its protected home
directory before hashing, so access does not depend on preserving a first-boot
write. Review/change that account and sudo policy before building for another
use. No private SSH host key is embedded; machine-id is empty in the reusable
lower. Each build gets its own root hash and partition identifiers; do not
hardcode the original experiment's hash.

## Azure publication and deployment

Use your own dedicated, authorized resources and supported quota. The original
functional path was:

1. Create a 16-GiB Linux Gen2 staging disk and attach it to the builder.
2. Verify its exact identity/size and that it is unmounted, copy the raw image,
   byte-compare the image range, then detach it. Copying to a wrong block
   device destroys its contents; no disk-write automation is supplied here.
3. Create a **generalized managed-image bridge** from that disk, then a
   generalized Compute Gallery definition with `ConfidentialVmSupported` and
   one regional image-version replica. Wait for completed replication.
4. Deploy the gallery version as ConfidentialVM, vTPM on, Secure Boot **off**,
   `VMGuestStateOnly`, matching the demonstrated development conditions.
   DC4as_v6 required CVM security type; direct attached-OS-disk creation and a
   direct managed-disk source for this gallery type were rejected.

This is not permission to allocate resources, nor a supported production CVM
boot-chain recipe. A gallery feature declaration does not qualify a generic
base for CVM use. Boot/ESP read-only mounts also do not authenticate their bytes.
`VMGuestStateOnly` is not a claim of OS-disk encryption.

After independent gallery replication and successful recovery are established,
remove disposable imports/bridges and detached superseded disks. Deallocate
idle VMs, preserve evidence, and retain final resources until their owner
approves deletion. No original experiment resources are needed.

## Guest and reboot checks

After first provisioning completes, copy `guest-check.sh` to the target and
preserve its full output **outside** the volatile guest:

```bash
sudo bash guest-check.sh write
```

Require `VOLATILE_WRITES_AND_RESOURCE_SMOKE_OK`. It checks the writable overlay,
read-only verity mapper, `/etc` and `/var`, no swap, services and cloud-init,
new/modified/deleted files, an application write, and a bounded 32-MiB workload.

Reboot the **same VM**, verify its regenerated SSH host key through your trusted
management channel, copy the script again, and run:

```bash
sudo bash guest-check.sh reset
```

Require `VOLATILE_REBOOT_RESET_OK`; compare the saved boot IDs, machine IDs and
host-key fingerprints externally. A reset check without the preceding write
run and a real reboot is not reboot evidence.

Azure removes the original provisioning media after first boot. Cloud-init
then falls back to IMDS, returning `degraded done` with a warning that IMDS
cannot restore admin passwords/custom-data. This is an SSH-key-only reference
without those payloads. The reset check accepts **only that exact warning**,
status `done`, datasource IMDS and no errors, and prints
`EXPECTED_IMDS_REPROVISION_WARNING`. Other warnings/errors, and any warning on
first provision, fail. Persistent identity/payload replay needs another design.

For a read-only look at the live layers:

```bash
findmnt -n -o TARGET,SOURCE,FSTYPE,OPTIONS /
sudo veritysetup status root
```

Systemd unmounts the tmpfs backing mount after creating the overlay, retaining
it by reference. After root switch, the lower/upper paths printed in overlay
options are not directly accessible. `findmnt` therefore does not expose all
backing layers, and showing that `/run` is tmpfs is not proof of the upper's
type. Inspect initrd/systemd behavior and measure `Shmem` under the workload.

## Trust and operational limits

- The main UKI's `.cmdline` is empty in this source snapshot; the root hash and
  volatile policy are in its **add-on**. Authenticate required loaders, UKIs
  and add-ons through an authorized firmware/shim trust chain before claiming
  Secure Boot. IC's existing export/sign/`inject-files` flow is the integration
  point; this wrapper does not sign or enroll firmware keys.
- The original base already has `selinux=0`. This recipe did not disable
  SELinux to obtain a boot; enforcing-mode compatibility is untested.
- Verity covers the root data partition, not boot/ESP, other filesystems or
  mutable upper contents. Upper files can shadow protected executables.
  Root-hash/signer attestation, rollback and signed-only runtime execution are
  not implemented.
- All upper state is lost, including agent packages, logs, identities and
  provisioning state. Policy-installed agents may redownload/reinstall on
  every boot. The observed upper limit was about 3.67 GiB with 1,048,576 inodes
  on a roughly 15-GiB guest; agents already consumed about 1.58 GiB.
  Copy-up and retained metadata/data can exhaust that limit while RAM remains.
- Raw guest evidence, baked public keys and image hashes can identify a run;
  keep them in your external run directory, not this repository.

## Local validation

```bash
python3 tests/test_build.py
python3 test-cloud-status.py
bash -n build-image.sh
bash -n inspect-image.sh
bash -n guest-check.sh
```

These tests exercise the build wrapper against local tool doubles and the
narrow cloud-init policy. They do not build an image or create Azure resources.
The original component flow booted on Azure; a new end-to-end run of this
extracted build wrapper is not claimed. See [VALIDATION.md](VALIDATION.md).
