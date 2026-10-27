# CVM Image Integrity Reference Implementations

Reference configurations for verified root filesystems and writable-state
policies. Each distribution owns its build inputs, boot integration, deployment
instructions, and validation scope; a shared storage layout does not imply a
shared boot trust chain.

## Configurations

| Distribution | Configuration | Boot integration | Validation scope |
| --- | --- | --- | --- |
| Canonical Ubuntu 22.04 CVM | [Verity lower + volatile tmpfs upper](ubuntu/verity-tmpfs-root/README.md) | Custom initrd, signed UKI, Canonical snap-bootstrap manifest | Component flow demonstrated with Secure Boot/vTPM; parameterized controllers have local/CI tests |
| Azure Linux 3 | [Verity lower + volatile tmpfs upper](azure-linux/verity-tmpfs-root/README.md) | Image Customizer root verity/UKI and `systemd.volatile=overlay` | Functional Azure storage/boot repro; Secure Boot off, CVM qualification not established |

See each configuration's `VALIDATION.md` before relying on its guarantees.
Neither entry claims production-complete root-hash attestation, rollback
protection, or immutable effective-root executables.

## Layout

```text
ubuntu/
  verity-tmpfs-root/       # Canonical controllers, guest scripts and tests
azure-linux/
  verity-tmpfs-root/       # IC YAML, pinned build recipe and guest checks
```

Start in the selected configuration directory. The previous root-level
`deploy.sh`, `Deploy.ps1`, `cleanup.sh`, scripts and tests now live under
`ubuntu/verity-tmpfs-root`; their command-line interfaces are unchanged.
There is no implicit default distribution or root-level deployment command.

For Ubuntu, `deploy.sh` and `Deploy.ps1` **create a temporary Azure builder VM
for you**, then deploy a separate reference CVM. Running the Bash controller on
Linux does not build on that machine. Users with an existing Linux environment
can instead follow the [manual local-builder workflow](ubuntu/verity-tmpfs-root/LOCAL-BUILD.md),
which builds locally and uses just one Azure target VM for acceptance.

Keep run directories, image artifacts, credentials and raw guest evidence
outside this checkout. Each configuration documents its own resource creation,
retention and cleanup behavior; reading this index creates no Azure resources.
