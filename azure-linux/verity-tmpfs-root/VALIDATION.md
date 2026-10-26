# Validation scope

[Configuration and instructions](README.md)

## Original Azure storage experiment

The configuration in `root-volatile.yaml` was exercised with the inputs pinned
in `inputs.json`. The functional target used the generic Azure Linux 3 Gen2
base, a DC4as_v6 ConfidentialVM, vTPM enabled and Secure Boot disabled.

| Gate | Observed result |
| --- | --- |
| Root image | Four GPT partitions; no persistent `/var`; full data/hash verification passed |
| Boot artifacts | Final root hash, partition IDs and volatile argument in UKI add-on; required initrd components present |
| Overlay support | Built into the selected kernel; not a missing initrd module |
| First configuration | Verity/volatile-root activated, but fstab remount made overlay read-only; cloud-init failed |
| Corrected configuration | Guarded overlay remount restored writable `/`; verity mapping stayed read-only |
| First provisioning | Cloud-init `done`, no errors/recoverable errors; SSH/network/waagent active; no failed units |
| Runtime mounts | Writable overlay `/`, `/etc`, `/var`; read-only boot/ESP; no swap |
| Workload | New/modified/deleted files and application writes passed; 32-MiB write increased `Shmem` by about 32 MiB |
| Actual reboot | Writes/modification/whiteout reset; boot ID, machine ID and SSH host keys regenerated |
| Reboot provisioning | IMDS fallback completed without fatal errors but with the explicitly documented warning |
| Live data/hash pair | Full 8-GiB verification passed after Azure transfer and provisioning |
| Offline corruption | Missing hash header rejected; protected-block corruption failed verification and read with EIO; untouched reference still verified |
| Live negative tests | Protected-file corruption caused dm-verity kernel panic; destroyed hash superblock blocked next boot in initrd with no raw-root fallback |
| Recovery | Reimaged the same VM from the independent gallery version after deleting import bridges/staging; healthy write check passed again |
| Rebuild | Protected configuration changes produced new hashes and matching boot arguments; revised images booted |

The implementation used existing IC root verity/UKI functionality. No
production Go changes were needed. Existing root and `/usr` UKI integration
tests, and an added volatile-root fixture/test in the source experiment, passed.
Those source-test changes are not required to build this configuration.

The original upper had 3,937,615,872 bytes total capacity and 1,048,576 inodes,
with 15,381,308 KiB guest RAM and no swap. Policy-installed agent state already
used about 1.58 GiB. These are observations, not capacity guarantees.

## Extracted repository

The complete YAML and inspection/guest checks are packaged here. `build-image.sh`
adds a local wrapper around the component build commands, with caller-provided
base/public key, a new external run directory, pinned source/compiler/container
and package snapshot, and mandatory successful inspection. The wrapper's
version label differs from the original experiment; output hashes are not
expected to be identical.

Local/CI tests cover private-key rejection, repository/existing-output guards,
compiler/source pins, read-only base binding, use of the compiled executable,
build/inspection failures, and the exact IMDS warning policy. Docker/Git/Go are
local doubles in the wrapper tests. No Azure credentials or allocations are used.

**A new end-to-end image build/deployment driven by this packaged wrapper is
not claimed.** Keep your own acquisition, build, boot, workload, reboot,
failure and cleanup evidence outside the checkout. No original subscription,
VM/disk/gallery IDs, SSH material or raw evidence is included.

## Explicit gaps

- No positive Secure Boot boot, authorized signer/firmware enrollment or
  authenticated UKI/add-on chain.
- No demonstrated CVM target-base variant, vendor CVM qualification or SEV-SNP
  attestation. A CVM gallery flag and VM security type are not that proof.
- No enforcing-SELinux compatibility; the base already used `selinux=0`.
- No missing-overlay-support boot-negative image; support is built into this
  kernel. The runtime guard requires an actual overlay instead of reporting
  a raw read-only root as success.
- No persistent users/identities/runtime changes beyond what is baked into
  the protected lower or recreated each boot; no admin-password/custom-data
  replay guarantee.
- No immutable effective-root executable policy, boot/ESP verity, root-hash
  attestation, rollback protection, or encrypted persistent upper.
