# CVM Image Integrity Reference Implementations

Reference configurations for verified root filesystems and writable-state
policies. Each distribution owns its build inputs, boot integration, deployment
instructions, and validation scope; a shared storage layout does not imply a
shared boot trust chain.

## Configurations

| Distribution | Configuration | Boot integration | Validation scope |
| --- | --- | --- | --- |
| Canonical Ubuntu 22.04 CVM | [Verity lower + volatile tmpfs upper](ubuntu/verity-tmpfs-root/README.md) | Custom initrd, signed UKI, Canonical snap-bootstrap manifest | Component flow demonstrated with Secure Boot/vTPM; parameterized controllers have local/CI tests |
| Ubuntu 24.04 CVM | [Dracut verity lower + volatile tmpfs upper](ubuntu/dracut-verity-tmpfs-root/README.md) | Dracut/systemd initramfs; signed UKI embeds root hash and data/hash PARTUUIDs; no snap-bootstrap | Gallery 1.0.4 persisted-TPM first/reboot SSH acceptance and installed native collector passed on Intel TDX; custom-policy MAA token verified for PCRs 0-8,11; PCR12 coverage gap |
| Azure Linux 3 | [Verity lower + volatile tmpfs upper](azure-linux/verity-tmpfs-root/README.md) | Image Customizer root verity/UKI and `systemd.volatile=overlay` | Functional Azure storage/boot repro; Secure Boot off, CVM qualification not established |

See each configuration's `VALIDATION.md` before relying on its guarantees.
Neither entry claims production-complete root-hash attestation, rollback
protection, or immutable effective-root executables.

## Layout

```text
ubuntu/
  verity-tmpfs-root/       # Canonical controllers, guest scripts and tests
  dracut-verity-tmpfs-root/ # Ubuntu 24.04 Dracut build, controllers and SSH checks
azure-linux/
  verity-tmpfs-root/       # IC YAML, pinned build recipe and guest checks
```

Start in the selected configuration directory. The previous root-level
`deploy.sh`, `Deploy.ps1`, `cleanup.sh`, scripts and tests now live under
`ubuntu/verity-tmpfs-root`; their command-line interfaces are unchanged.
There is no implicit default distribution or root-level deployment command.

For the Ubuntu 22.04 Canonical recipe, `deploy.sh` and `Deploy.ps1` **create a temporary Azure builder VM
for you**, then deploy a separate reference CVM. Running the Bash controller on
Linux does not build on that machine. Users with an existing Linux environment
can instead follow the [manual local-builder workflow](ubuntu/verity-tmpfs-root/LOCAL-BUILD.md),
which builds locally and uses just one Azure target VM for acceptance.
The Ubuntu 24.04 Dracut recipe now offers Bash/PowerShell entry points over a
shared Python controller, as well as an independent
[manual Linux workflow](ubuntu/dracut-verity-tmpfs-root/LOCAL-BUILD.md).
Its controllers preserve the distinct Dracut/systemd signed-hash boot chain and
default to Managed Run Command for first/reboot mounted-verity acceptance.
SDK execution is deferred to user-driven authenticated SSH; explicit SSH
validation remains available. A fresh build/publication and recovered managed
acceptance/cleanup passed in Azure; an uninterrupted controller run remains
unqualified. This is separate from the demonstrated manual SSH/MAA flow.

Keep run directories, image artifacts, credentials and raw guest evidence
outside this checkout. Each configuration documents its own resource creation,
retention and cleanup behavior; reading this index creates no Azure resources.
