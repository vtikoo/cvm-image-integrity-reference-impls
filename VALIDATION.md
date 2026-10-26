# Validation scope

## Demonstrated configuration: Canonical Ubuntu with a tmpfs root

The component scripts from which this recipe was extracted were exercised with
the pinned Ubuntu 22.04 CVM image, kernel, and producer source in the README:

| Gate | Observed result |
| --- | --- |
| Actual stock initrd | Missing verity and overlay modules; stock variant failed to boot |
| Custom initrd | Matching signed dm-bufio, dm-verity and overlay modules included; runnable modprobe |
| Custom UKI | Signature verified; original kernel and all non-initrd sections unchanged |
| Producer | Focused manifest and inclusive-byte-size regression tests passed |
| Protected disk | Full verity verification and fixed-VHD checks passed |
| Corrupted disposable clone | Verification failed; live verity read returned I/O error and status C |
| Gallery | Replication completed; exact public signer/template returned with UefiSettings expansion |
| Actual target | DC4as_v6 ConfidentialVM, Secure Boot/vTPM enabled, VMGuestStateOnly |
| Firmware | Actual UEFI db contained the certificate that signed the deployed UKI |
| Live root | Overlay, read-only ext4 verity lower with status V, tmpfs upper/work, no swap |
| Workload | 128 MiB plus 2,048 small files; 136 MiB and 2,050 inode increase measured |
| Real reboot | Distinct boot IDs; marker/workload/evidence vanished; full lower verification passed |
| Guest usability | Cloud-init had no fatal errors, guest agent active, no failed systemd units |
| Cleanup | Helper/source/upload resources and temporary access removed; reference deallocated |

The original environment had approximately 2.07 GiB of tmpfs already used before
the workload, including provisioned agent state. It had approximately 5.13 GiB
of tmpfs available after the workload. These are observations, not guarantees
for different policies, agents, VM sizes, or applications.

## Extracted repository

Configuration/names, source acquisition, helper identity creation, and the
entry-point orchestration were extracted and parameterized for this repository.
The public producer fork commit contains the same source changes tested in the
original run; its build metadata can produce a different binary checksum.

These results apply to the Canonical Ubuntu/tmpfs configuration only. Additional
distributions or writable-state configurations require their own documented
acceptance evidence; the generic repository name does not imply they are supported.

`tests/Test-Local.ps1` and CI cover local parsing, plan/resource naming,
certificate-profile guards, and the pinned producer's focused tests/build.
They do not allocate Azure resources.

**A new end-to-end run of this parameterized entry point is not claimed.**
Run it in your own dedicated scope and require all acceptance evidence before
calling your deployment successful. No source-run credentials, certificates,
private keys, Azure resource identifiers, or raw evidence are published here.
