# Offline PCR4, PCR7, PCR11, PCR12 and PCR13 predictor design

[Recipe](README.md) | [Invocation and input preparation](LOCAL-BUILD.md#optional-offline-pcr-prediction) | [Qualification evidence](VALIDATION.md#evidence-levels)

## Status and purpose

[predict-pcrs.py](scripts/predict-pcrs.py) calculates expected SHA-256 PCR4
and PCR11 values, optionally PCR7, and emits expected PCR12/13 values for a
**no-external-inputs policy**, without booting the candidate image or reading
its event log. It combines final build artifacts with an explicit boot-phase
path and, for PCR7, an independently approved firmware baseline. It neither changes the
image nor contacts Azure, a TPM or Microsoft Azure Attestation (MAA).

Both profiles model direct firmware launch of one signed x64 systemd-stub 255
UKI:

| Selection | Boot profile | PCR7 / firmware baseline |
| --- | --- | --- |
| Default: Secure Boot enabled | `azure-direct-uki-v1` | Predict PCR7 from an independently approved, pinned baseline and one appended signer. |
| `--disable-secure-boot` | `azure-direct-uki-no-secureboot-v1` | Omit PCR7 and reject baseline inputs; no base `db` is needed for this image policy. |

Artifact-based PCR4/7/11 predictions for the enabled profile matched
retained MAA-signed values for the tested reference. **Obtaining an independently
approved base Secure Boot database remains unresolved.** The qualification
baseline came from a separate controlled reference, not a published or approved
Microsoft factory baseline. Matching those observations validates the model;
it does not establish production trust in that baseline. The disabled profile
reuses the PCR4/11 model; its deployed measurement sequence and end-to-end remote
verification remain unqualified. A successful boot is not attestation approval.

The current baseline and boot profile describe a **specific observed Azure
implementation**, not a stable Azure API contract or a universal Azure default.
No publicly available, approved exact-byte baseline has been identified for
this profile. Relevant Azure implementation changes require requalification:
changed variable contents require a new independently approved baseline, while
changed enrollment serialization, authority selection or measurement sequences
may also require changes to the predictor model. The same UKI can therefore
produce different PCRs after a platform change.

This is a predictor, not a complete remote-attestation verifier or a general
UEFI event-log simulator. Default builds/controllers do not invoke it.

## Inputs, outputs and trust boundaries

```text
Independently retained build             Independently controlled policy
  final signed cvm.efi                     firmware variable baseline + SHA256 pin
  exact public signer.der                 enrollment owner GUID + phase path
                  \                       /
                   -> validate and predict
                   -> expected-pcrs.json
                              |
                   approve/version expected policy
                              |
                   future relying-party verifier
                   compares authenticated, fresh evidence
```

The firmware baseline and enrollment GUID apply only to the enabled profile.
Both profiles require independent UKI approval and an explicit phase path.

| Input | Meaning and trust requirement |
| --- | --- |
| `--uki` | Final signed UKI from the approved build. A guest-retrieved copy must first match independently retained build hashes. |
| `--signer-der` | Required in both modes: exactly one canonical DER certificate. OpenSSL checks its encoding and `sbverify` verifies the UKI against it. This is artifact consistency, not independent policy approval, firmware enrollment or revocation-policy acceptance; disabled mode does not require enrollment. No private key is needed. |
| `--disable-secure-boot` | Select the image-only profile without PCR7 evaluation. It does not configure a VM, authenticate Secure Boot state or prove that Secure Boot is disabled. |
| `--firmware-baseline` | Enabled mode only, required with its pin: schema-version-1 JSON containing `bootProfile`, `signatureOwnerGuid`, `variables` and nonempty `provenance`. Variables are base64-encoded complete values for `SecureBoot`, `PK`, `KEK`, `db` and `dbx`. Rejected in disabled mode. |
| `--firmware-baseline-sha256` | Enabled mode only: lowercase SHA-256 of the exact JSON file bytes, obtained from independently approved policy. Reformatting the file changes the pin. Hashing an untrusted file at invocation time does not approve it. |
| `--phase-path` | Explicit colon-separated ordered PCR11 extensions. `sysinit:ready` matched the retained reference; an empty string requests UKI-only, not boot-complete state. |

For the enabled profile, `signatureOwnerGuid` describes the **new signer enrollment**, while `variables`
describe the baseline **before that signer is appended**. The baseline `db`
must not already contain the supplied certificate. `SecureBoot` must be the
single byte `01`; all other variables must be nonempty EFI signature-list
streams. The parser accepts only X509 and SHA256 list types with zero-length
signature headers. It checks structure, not the trustworthiness of every
baseline certificate. It rejects duplicate/unexpected JSON fields, unsupported
profiles and a baseline file larger than 256 KiB.

The output includes final `pcrs` with string keys `"4"`, `"11"`, `"12"` and
`"13"`, plus `"7"` only in enabled mode, ordered event digests and intermediate PCR values, cumulative
`pcr11Checkpoints`, model identifiers and the SHA-256 hashes of the provided
input files (no baseline hash in disabled mode). `pcr7Policy` is `firmware-baseline`
or `not-evaluated`. Disabled mode omits PCR7 from both `pcrs` and `events`:
it does **not** predict zero, approve arbitrary PCR7 values on behalf of another
policy, or assert an authenticated Secure Boot state. No prediction JSON is
emitted on handled input/signature/dependency failure; the CLI exits with
status 2. Output is not signed or approved by the tool: the relying party must
protect, review and version it as expected policy.

`externalInputPolicy` is `no-external-inputs`: PCR12 and PCR13 are each 32 zero
bytes (64 hexadecimal zeroes), with empty event lists. These expectations assume
no external command-line overrides, addons, credentials or system extensions,
and no other producer extends either PCR. They are policy references, not values
derived from the UKI or proof that companion inputs are disabled. Nonempty
external-input sequences are not modeled; the deployed empty-input sequence
still needs qualification.

## PCR selection: what the image policy needs to establish

For this direct-UKI design, **PCR4 establishes the approved UKI identity**.
The enabled profile additionally uses **PCR7 to establish the approved Secure
Boot policy**; this is not an inherent requirement for exact-image approval
when firmware signature enforcement is outside the relying party's policy.
External boot inputs must be constrained through PCR12/13 or qualified input
disablement. **PCR11 value
verification is optional when the independently approved expected PCR4 is
enforced**; it supports additional component-level or boot-phase policies.
These checks assume an approved platform foundation, the characterized boot
path and coverage of all security-relevant external inputs; they do not alone
establish a trustworthy CVM. **The predictor calculates PCR4/7/11 and emits
zero-valued PCR12/13 expectations for the no-external-inputs policy;
the PCR12/13 signed-coverage gaps remain open.** The current systemd-stub 255
also supports PCR13-measured initrd system extensions; their exclusion or
approval remains an additional condition.

### Secure Boot disabled: measured approval, not execution prevention

Approved firmware still measures the UKI into PCR4 before executing it.
An independently approved PCR4 can therefore identify that UKI without its
certificate being in firmware `db`. PCR11 alone cannot replace this check:
it does not measure the stub code that performs its extensions.

The disabled profile intentionally does not use PK/KEK/db/dbx or PCR7 as image
approval inputs. If a separate policy requires a particular Secure Boot state,
it still needs authenticated evidence of that state; selecting this calculator
mode or trusting a deployment/guest JSON field does not provide it. The
deployment controller's `--disable-secure-boot` is a separate, explicit opt-in:
it requests and locally checks Secure Boot off while keeping vTPM enabled.

With Secure Boot off, systemd-stub 255 accepts ordinary EFI command-line
overrides and measures them into PCR12. The approved UKI's embedded `.cmdline`
is still measured into PCR11, so matching PCR4/11 alone does not establish the
effective command line or enforced verity root. Addons also lose Secure Boot
signature enforcement, and companion credentials/extensions remain relevant.
For this stock stub, the no-external-inputs policy requires authenticated zero
PCR12 **and** PCR13 after qualifying the empty-input sequence and measurement
behavior. Zero values demonstrate no extensions under that trusted model,
not that the input paths were disabled. Alternatively, independently approve
an implementation that disables or constrains all relevant inputs regardless
of Secure Boot state.

The approved hardware/firmware/vTPM foundation, external-driver qualification,
freshness and binding key release to the receiving guest remain mandatory.
Unapproved code may execute with Secure Boot off: withhold secrets until remote
verification succeeds. Neither profile attests the mutable tmpfs upper or
general runtime integrity. The tested MAA tokens omit PCR12/13, so neither the
new predictor mode nor basic guest acceptance completes this verification path.

### Start with the hardware-bound measurement foundation

The [Azure guest-attestation design][azure-attestation-design] assigns UEFI and
the guest paravisor, including its vTPM, to hardware-report coverage. The report
binds runtime claims containing the vTPM attestation public key; the verifier
must validate that binding, the hardware endorsements, the approved platform
identity/security version and the quote signed by that key. A valid signature
alone does not approve the software identity or its configuration. Freshness
and binding key release to the intended receiving endpoint are also required.

Once the launch identity is authenticated **and approved**, the embedded UEFI
and its built-in drivers need not be approved again merely by pinning PCR0/2.
This does not cover separately loaded firmware/drivers or approve every runtime
platform setting. Required settings still need authenticated evidence or an
invariant enforced by the approved implementation. A generic Secure Boot claim
is not a substitute for checking the complete measured Secure Boot policy.

### Image approval, external inputs and optional PCR11 checks

| PCR | Image-approval rationale |
| --- | --- |
| **4: UEFI-measured bootloader/UKI** | UEFI measures EFI bootloaders/applications into PCR4 before transferring control to them. In this direct-UKI design, UEFI measures the UKI itself, whose Authenticode digest covers the systemd-stub code, kernel, initrd and embedded command line, including the dm-verity root hash and enforcement options. Matching an independently approved expected PCR4 value confirms the approved UKI and measured boot sequence, rather than merely confirming that approved UEFI firmware ran. An additional measured bootloader or boot attempt changes PCR4, even if Secure Boot accepts the image. |
| **7: Secure Boot policy (enabled profile only)** | Establishes the measured `SecureBoot`, PK, KEK, `db`, `dbx` and used authority against an approved baseline. An enrolled customer certificate or a successful signature check alone does not establish the rest of the trust store. Appending a customer signer retains the template's other signers; a signer can authorize many images, so PCR7 does not replace exact-image approval. References must account for provisioning generation and persisted variable state. Omitted from the disabled profile, not assumed zero. |
| **11: optional component and boot-phase checks** | Checking the expected PCR11 value is optional when the independently approved expected PCR4 is enforced: PCR4 already covers the kernel, initrd and embedded command line. PCR11 provides separate payload-section measurements and later boot-phase extensions. A validated event log exposes individual component digests, including the `.cmdline` digest that binds the embedded verity root hash and enforcement options. A selected boot-phase checkpoint can be used with systemd service dependencies to require successful attestation before releasing secrets to be sealed to the PCR11 value for that phase. PCR11 does not cover the stub code itself. |
| **12: external boot inputs** | With Secure Boot enabled and an embedded `.cmdline`, systemd-stub 255 ignores ordinary EFI invocation arguments, but still accepts valid signed `.addon.efi` files from the ESP, appends their parameters to the embedded command line and measures those additions into PCR12. A host able to modify the ESP can select or reorder already-signed addons accepted by Secure Boot without modifying the UKI itself. Signature validity does not approve their use or effective parameters for this image; whether appended options override embedded ones depends on the option's parser. PCR12 also covers accepted DeviceTree addons and companion credential archives. Verify an independently approved external-input sequence, or establish that the approved implementation disables or independently constrains those inputs. |
| **13: external system-extension images** | The retained qualified UKI uses stock Ubuntu **systemd-stub `255.4-1ubuntu8.18`**, which collects companion `.raw` system-extension images, packages them into an additional initrd and measures the archive into PCR13. This pickup path is not disabled for confidential VMs. Extensions can supply software outside the verity lower if consumed; collection alone does not prove activation. Approve the extension inputs using PCR13 or establish that this path is disabled or cannot affect the approved boot/root behavior. Neither input approval nor non-consumption is established here. New builds install a wrapper that requests PCR13; a [tmpfs diagnostic requesting it](VALIDATION.md#pcr13-inclusive-tmpfs-diagnostic-2026-11-16) received no signed PCR13 coverage or value from MAA. |

The root hash in the approved `.cmdline` commits to the dm-verity lower's
contents. The approved kernel/initrd must actually establish the intended
read-only mapping and reject corruption; an attacker substituting different
partition contents cannot satisfy the approved root hash without breaking the
hash assumption. Verification occurs on reads, not as a full-disk scan at
attestation time. This chain identifies the protected lower, **not everything
that can execute through the writable tmpfs upper**; the recipe's separate
[runtime-hardening limitations](README.md#testing-components-and-production-hardening)
still apply.

With Secure Boot enabled and an embedded `.cmdline`, systemd-stub 255 ignores
ordinary EFI command-line overrides, but still supports companion addons and
credentials. With Secure Boot disabled, accepted ordinary overrides also belong
to PCR12. Secure Boot approval of an addon is not approval of its use, order
or effective parameters for this image. A no-external-input policy should
require an authenticated PCR12 value matching the qualified empty-input
sequence: normally the initial all-zero SHA-256 value if no producer extends
PCR12. That expected sequence still needs qualification for the deployed image.
Alternatively, approve an exact external-input sequence. Omitting PCR12 is
justified only if the approved implementation demonstrably disables or
independently constrains every relevant input path. Empty ESP directories or
an unmounted ESP after boot do not establish that property.

### Why other PCRs are not fixed image-reference inputs

The [Linux TPM PCR Registry][linux-pcr-registry] describes common roles, not a
universal event sequence. The following rationale concerns this approved
boot/root-integrity design, not arbitrary software behavior or verifier rules
implemented by this predictor. Once an exclusion is justified, the relying
party does not need to parse that PCR's event log merely to look for surprises.
Qualifying the platform/profile is separate from checking every PCR on every
attestation.

| PCR | Treatment and conditions |
| --- | --- |
| **0 / 2** | No duplicate pin is needed for firmware and built-in drivers already covered by the approved launch identity. The recipe installs no additional firmware-volume or EFI-driver stage, but that is not proof that Azure UEFI blocks such stages. The public source does not establish a blanket prohibition; see the qualification gap below. Separately loaded code outside launch coverage must be excluded by an approved invariant or independently approved, using PCR0/2 where applicable. PCR7 signer approval alone is not exact-driver approval. |
| **1** | No separate PCR1 check is needed for boot-entry selection: PCR4 establishes the executed application sequence and binds the UKI payload, including embedded root settings. Choosing different boot code changes PCR4; PCR7 need not change when both images use the same signer. Configuration affecting the accepted UKI must be constrained by the approved implementation or the external-input policy, not inferred from boot variables. This does not claim PCR4 covers external EFI drivers or every runtime input. |
| **3** | No separate PCR3 value or event-log check is needed for this image policy. The inspected [Microsoft UEFI ReadyToBoot path][mu-boot-measurements] contributes a separator, not additional software identity or a security-configuration inventory. With that implementation approved and required settings covered elsewhere, parsing this log adds no independent assurance about the approved boot/root behavior. |
| **5** | No separate GPT/PCR5 check is needed for this recipe's boot/root-integrity claim. Its approved command line disables GPT discovery, fixes the data/hash PARTUUIDs and requires the approved verity root hash; persistent fstab mounts/swap are removed. GPT edits cannot enable disabled discovery or substitute different accepted lower contents. An image that already enables discovery has a different trust argument: GPT edits can introduce extra unverified mounts without changing PCR4/7/11. See the distinction below. |
| **6** | No PCR6 evaluation is required for code identity or protected-root integrity. [Microsoft VM UEFI][mu-vm-measurements] measures a VM UUID and its build architecture (`X64` or `AARCH64`), not an additional authenticated CPU/TEE identity. A host-supplied UUID does not approve software behavior; hardware/platform identity comes from the hardware-attestation foundation, not this event. |
| **8 / 14** | No separate PCR8/14 check is needed to exclude GRUB/shim in this profile. Approved UEFI identity alone does not exclude them; the required direct-UKI PCR4 sequence does. Inserting a measured intermediate bootloader changes that sequence even if Secure Boot accepts its signer. Intentionally supporting shim/GRUB requires a different qualified boot profile and its applicable policy inputs. |
| **9** | No separate PCR9 check is needed when PCR4 approves the embedded initrd and UKI-derived fragments, PCR12 approves external credentials/parameters, and the PCR13 extension condition is resolved. An approved UKI does not imply a single immutable initrd: systemd-stub 255 combines it with additional fragments. Under those input-coverage conditions, a kernel initrd measurement supplies no independent image-approval input; see the fragment sources below. |
| **10** | No PCR10 check is needed to establish this recipe's dm-verity lower identity. IMA policy belongs to the guest kernel/userspace, not an Azure-host or UEFI policy setting: kernel defaults/boot parameters and guest policy loading determine it. Approved boot inputs constrain initial configuration; privileged guest code may load policy where the kernel permits it. Adding an IMA-based runtime claim would require its own approved policy and measurement evidence; this design makes no such claim. |
| **15** | No PCR15 evaluation is required for the approved boot code or read-only lower contents. Filesystem metadata within that lower is already bound by the approved verity root hash. Generated machine IDs and volume-key measurements are not additional software identities, and this recipe does not rely on them for its boot/root-integrity decision. Instance-affinity or local-sealing policies are separate objectives, not implied image-approval requirements. |
| **16-23** | Debug, dynamic-launch and application-support uses do not establish this static UEFI/UKI boot chain. The profile does not perform a DRTM launch, and resettable debug/application registers are not substitutes for boot evidence. A different launch design needs its own policy. |

**External firmware/driver qualification.** The inspected Microsoft UEFI
[media policies][mu-image-policies] deny execution on a Secure Boot security
violation, rather than unconditionally rejecting external images. Its
[verification library][mu-image-verification] distinguishes this from
`NEVER_EXECUTE`, and the pinned [BDS path][mu-driver-options] processes EFI
driver load options. This does not prove an Azure host can populate those
options in a deployed CVM, or that an external driver was observed. It does mean
that neither this recipe's lack of a driver-install step nor the inspected
UEFI identity alone establishes a no-external-driver invariant. Before omitting
PCR0/2 for code outside hardware-launch coverage, qualify the deployed
platform's restrictions or add independent approval evidence.

**GPT cannot turn discovery on, but enabled discovery can consume GPT.**
The generated [command line](scripts/image_policy.py) sets
`rd.systemd.gpt_auto=0 systemd.gpt_auto=0 rd.fstab=0`. Changing partition types,
names or identifiers does not change those authenticated settings. With no
additional unverified mounts in this boot policy, redirecting a fixed PARTUUID
still has to supply data satisfying the approved verity hash or fail. This
does not prevent host-induced boot failure, which is outside the integrity
claim. By contrast, if an approved image leaves automatic discovery enabled,
the host can change GPT to present an additional eligible `/home` or `/srv`
partition without changing the UKI or PCR4/7/11. Discovery being *supported* by
the code is therefore different from discovery being *enabled* by the accepted
configuration. Supporting that alternative requires approval/authentication of
the extra mounts and their contents; PCR5 alone does not authenticate file data.
The same applies to extra mounts introduced through other configuration paths.

**Initrd fragments are not all embedded in the UKI.** In version 255,
[systemd-stub collects `.raw` extensions][stub-255-sysext] and
[combines the embedded initrd with credential, global-credential, system-extension,
PCR-signature and public-key fragments][stub-255-initrds]. UKI-derived fragments
are bound by the approved UKI; accepted external credential inputs belong to
PCR12, and extension images belong to PCR13. This is why PCR9 is redundant only
after those inputs are constrained. Packaging an extension does not by itself
prove that this initrd/userspace consumes it, but the absence of build-generated
extensions does not prove that host-supplied companions cannot be consumed.
That disablement/non-consumption condition needs qualification.

These exclusions concern the stated boot/root-integrity claim. They do not
silently add instance-identity or IMA requirements, and they are not a universal
fixed-register sufficiency claim for arbitrary Azure images or workloads.

### Evidence coverage and related design

For a fixed qualified sequence, comparing authenticated PCRs with independently
approved predictions can enforce that sequence. A log-aware verifier must also
validate event-specific digests and complete replay for the PCRs its policy
relies on, including relevant firmware and userspace logs, against the fresh
quote. This does not require semantic evaluation of otherwise irrelevant PCRs
merely because they were collected. Raw quote verification must still validate
the complete selected-PCR digest and signature correctly. Replay establishes
consistency, not approval; references must not be derived from the evaluated
target itself.
Changed firmware, guest measurement services or quote timing can invalidate the
sequence, including the expected empty PCR12 value.

The wrapper installed by new builds requests exactly `0-8,11,12,13`, while the
tested MAA tokens authenticate only `0-8,11`. Requesting or locally reading
PCR12/13 is not remote verification of them; an omitted claim is neither zero
nor a match. A production policy relying on these PCRs must obtain authenticated
coverage or establish the qualified input-disablement alternative above. A tmpfs
diagnostic requested and quoted both PCR12 and PCR13, but its MAA token omitted
both from signed coverage and values. PCR13 remains an open condition if system
extensions remain possible. Updating the wrapper does not modify retained images
or provide a completed relying-party verifier.

The [AzureStack-Tools CVM Image Builder design][azurestack-integrity] provides
the same useful UKI -> embedded root hash -> dm-verity content chain and
describes build-time PCR4/11 calculations. Its [PCR section][azurestack-pcrs]
masks phase services to stabilize PCR11; this recipe instead retains explicit,
qualified phase paths. That README does not supply a complete PCR7/12 policy
or justify omitting external-input checks. Its SquashFS/selective-tmpfs layout
also differs from this recipe's whole-root writable overlay (ext4 lower by
default, optionally SquashFS), so its
runtime-integrity claims cannot be imported unchanged.

[azure-attestation-design]: https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
[linux-pcr-registry]: https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/
[mu-boot-measurements]: https://github.com/microsoft/mu_basecore/blob/7cff1f44f9da08a001cbd657fa178a72bf130b64/SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.c#L2974-L3007
[mu-vm-measurements]: https://github.com/microsoft/mu_msvm/blob/9aebaaf125ee9a857e7394c7a3142c0ef0f981ce/MsvmPkg/VmMeasurementDxe/VmMeasurementDxe.c#L34-L70
[mu-image-policies]: https://github.com/microsoft/mu_msvm/blob/9aebaaf125ee9a857e7394c7a3142c0ef0f981ce/MsvmPkg/MsvmPkgX64.dsc#L543-L546
[mu-image-verification]: https://github.com/microsoft/mu_msvm/blob/9aebaaf125ee9a857e7394c7a3142c0ef0f981ce/MsvmPkg/Library/DxeImageVerificationLib/DxeImageVerificationLib.c#L1770-L1802
[mu-driver-options]: https://github.com/microsoft/mu_basecore/blob/7cff1f44f9da08a001cbd657fa178a72bf130b64/MdeModulePkg/Universal/BdsDxe/BdsEntry.c#L935-L942
[stub-255-sysext]: https://github.com/systemd/systemd/blob/v255/src/boot/efi/stub.c#L688-L699
[stub-255-initrds]: https://github.com/systemd/systemd/blob/v255/src/boot/efi/stub.c#L776-L795
[azurestack-integrity]: https://github.com/Azure/AzureStack-Tools/blob/0e4a9f32c4677e2ee3b687032e0472b890a772b6/ConfidentialComputing/CvmImageBuilder/README.md#how-integrity-protection-works
[azurestack-pcrs]: https://github.com/Azure/AzureStack-Tools/blob/0e4a9f32c4677e2ee3b687032e0472b890a772b6/ConfidentialComputing/CvmImageBuilder/README.md#tpm-pcr-measurements

Guest-input behavior above follows [systemd-stub 255][stub-255]; GPT discovery
conditions follow [systemd-gpt-auto-generator 255][gpt-auto-255], and guest IMA
policy loading is described by the [kernel IMA policy interface][ima-policy].
Public UEFI source illustrates a particular implementation, not a guarantee of
the firmware deployed on every Azure CVM. Qualify its applicability before
relying on an exclusion.

[stub-255]: https://www.freedesktop.org/software/systemd/man/255/systemd-stub.html
[gpt-auto-255]: https://www.freedesktop.org/software/systemd/man/255/systemd-gpt-auto-generator.html
[ima-policy]: https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/ima_policy

## Measurement model

All modeled PCRs start at 32 zero bytes for the modeled boot. Disabled mode
does not model PCR7. PCR12/13 remain
unchanged under the no-external-inputs policy. Each modeled event extends:

```text
PCR_next = SHA256(PCR_current || event_digest)
```

Event order and exact serialized bytes matter; matching a set of certificate
fingerprints or section hashes is insufficient.

### PCR4: UEFI measurement of the bootloader/UKI

UEFI measures the EFI bootloader/application into PCR4 before executing it.
Here, the UKI is launched directly: systemd-stub is its EFI entry point, rather
than a separate shim or GRUB stage. The firmware's measurement covers the UKI's
stub code and embedded kernel, initrd and `.cmdline`, including the verity root
hash and enforcement options. These embedded inputs are therefore already
bound by an independently approved expected PCR4 value.

The profile models exactly three digests extended by UEFI:

1. SHA256 of ASCII `Calling EFI Application from Boot Option`, without a NUL.
2. SHA256 of four zero bytes (`EV_SEPARATOR`).
3. The final UKI's PE Authenticode SHA256 digest, not its whole-file SHA256.

Authenticode excludes the PE checksum, security-directory entry and certificate
table. It includes raw section padding and any noncertificate overlay. The
parser requires an x64 PE32+ EFI application, contiguous nonoverlapping raw
sections, nonoverlapping virtual sections and exactly one end-of-file PKCS7
signature. These constraints intentionally narrow the supported hash model.

There is no shim, GRUB, other EFI application or separately measured EFI kernel
launch in this sequence. A different boot path needs a new qualified model;
the predictor cannot detect the target's actual boot path from a UKI alone.

### PCR7: Secure Boot variables and authorizing certificate

This section applies only to `azure-direct-uki-v1`. The disabled profile emits
no PCR7 prediction or event list and requires no firmware variable baseline.

Let `C` be the exact signer DER bytes and `O` the enrollment owner GUID in
UEFI little-endian byte representation. The predictor constructs one new
`EFI_SIGNATURE_LIST` and appends it to the complete baseline `db`:

```text
SignatureType       = EFI_CERT_X509_GUID
SignatureListSize   = 44 + len(C)
SignatureHeaderSize = 0
SignatureSize       = 16 + len(C)
entry               = O || C
effective_db        = baseline_db || new_signature_list
```

It extends, in order, `SecureBoot`, `PK`, `KEK`, effective `db`, `dbx`, the
four-zero-byte separator, and exactly one `db` authority event.
Each variable digest hashes this serialized payload:

```text
vendor GUID (16 bytes, little-endian)
|| UnicodeNameLength (uint64 little-endian, UTF16 code-unit count)
|| VariableDataLength (uint64 little-endian, byte count)
|| variable name (UTF16-LE, no terminating NUL)
|| variable value
```

`SecureBoot`, `PK` and `KEK` use `EFI_GLOBAL_VARIABLE` GUID
`8be4df61-93ca-11d2-aa0d-00e098032b8c`; `db` and `dbx` use
`EFI_IMAGE_SECURITY_DATABASE_GUID` `d719b2cb-3d3a-4596-a3bc-dad00e67656f`.
The authority uses the same `db` wrapper, but its value is only `O || C`,
not the complete signature list or a public-key hash.

Consequently, a stable default `db` alone is not enough. PK/KEK/dbx contents,
certificate DER encoding, signature-list boundaries/order, owner GUID and the
authority/event sequence must also match. Firmware selecting another permitted
authority or adding another authority event changes PCR7.

### PCR11: optional component and boot-phase verification

**PCR11 value verification is optional when an independently approved expected
PCR4 value already establishes the exact UKI and measured boot sequence.** Every
static UKI section measured into PCR11 is also covered by PCR4. PCR11 adds
section-level visibility and later boot-phase measurements, not additional
static-content coverage.

A component-level policy can validate the PCR11 event sequence and replay
against authenticated PCR11, then compare individual section digests with
independently approved references. The `.cmdline` content digest commits to the
complete embedded command line, including the verity root hash and enforcement
options; it does not reveal the command-line text or root hash. Such a policy
still needs separate approval of the stub implementation, which PCR11 does not
measure. PCR11 component checks alone are not a replacement for full UKI
approval through PCR4.

For each present, nonempty section in the following **model order**, the
predictor extends SHA256 of the ASCII section name including its terminating
NUL, then SHA256 of the section's `VirtualSize` bytes:

```text
.linux .osrel .cmdline .initrd .splash .dtb .uname .sbat .pcrpkey
```

Raw file padding is excluded; measured section data extending beyond its raw
storage is rejected. `.pcrsig` is deliberately not measured into PCR11;
`.pcrpkey`, when present, is measured. A systemd-stub 255 `.sdmagic` marker is
required, but that marker is not independent proof of the stub implementation:
the UKI must still come from the approved build.

For each requested phase, extend SHA256 of its ASCII name without a NUL.
The output records the UKI-only checkpoint and every successive phase prefix.
The predictor does not inspect service enablement, discover phases, mask
services or prove a phase has occurred on the evaluated guest. If a relying
party chooses to enforce a boot-phase checkpoint, it must compare authenticated
PCR11 evidence with the independently approved reference for that checkpoint.
Phase matching is not general runtime-integrity proof. The predictor continues
to emit PCR11 values even when the relying party does not require that check.

## Base database acquisition: the main open trust input

**No production-approved base `db`, acquisition helper or authoritative Azure
template-to-variable-bytes mapping is shipped here.** The Gallery publication
code requests `MicrosoftUefiCertificateAuthorityTemplate` plus the public signer
and checks exact configuration readback. That API configuration identifies the
requested template/certificate, not all serialized firmware variable bytes.
In particular, the controller does not specify the signature owner GUID in its
additional-signature request; the predictor currently requires that GUID as
an externally established input.

The base `db` means the complete firmware database value before custom signer
enrollment, not a list of downloaded Microsoft certificates. Rebuilding an
apparently equivalent database can change signature owners, list grouping or
ordering, and hence PCR7. The same byte-preservation requirement applies to
PK, KEK and dbx.

Identifying an internal template source does not establish a publicly available,
approved baseline or prove which template revision applies to a deployment.
The current reference-derived bytes and configuration assumptions must remain
scoped to the implementation that was observed; they must not be treated as
permanent defaults.

Two possible acquisition routes need qualification:

| Route | Required evidence | Current gap |
| --- | --- | --- |
| Platform-supplied baseline | An authenticated, versioned provider artifact specifying exact variable bytes, template/firmware applicability and signer-enrollment serialization/owner behavior. | No such artifact or retrieval procedure has been established by this implementation. Do not infer one from the template name or Gallery readback. |
| Organization-approved reference enrollment | Independently authorized reference provisioning with the intended template, controlled firmware state, complete raw-variable capture, measured-event comparison and separate baseline review. | This would be an explicitly governed trust bootstrap, not proof of Microsoft factory defaults. Acquisition, reference authentication and approval are not automated here. |

A proposed controlled-reference workflow is:

1. Define the supported platform scope: firmware/template revision where
   identifiable, VM security type and guest-state persistence mode, plus the
   boot path. Establish how reference identity and capture integrity will be
   authenticated independently of the workload under evaluation.
2. Prefer a reference provisioned with the intended default template and no
   custom signer. Capture all five complete variable values and compare them
   with the values actually measured at boot. Runtime reads alone may describe
   post-measurement state; capture timing and updates must be understood.
3. Qualify custom enrollment separately: establish the appended list's exact
   bytes, owner GUID, placement and the authority selected during direct UKI
   boot. Check that the other variables and event order remain unchanged.
4. Preserve source evidence and capture hashes, template/configuration
   readback, known firmware identifiers, acquisition method and limitations.
   Have the baseline independently reviewed; publish its exact file hash
   through authenticated policy configuration.
5. Test across the intended deployment scope and after relevant platform
   changes. If exact applicability cannot be established, leave the profile
   unsupported rather than broadening acceptance to whatever the target reports.

An approved reference may use firmware events to help characterize the model;
the evaluated target's own event log must never define its acceptance baseline.
Capturing a current variable value requires only the raw value bytes: strip
the four-byte attributes prefix **only for efivarfs input**, and exclude event
GUID/name/length wrappers. Preserve the remaining bytes unchanged.
See the [existing preparation example](LOCAL-BUILD.md#prepare-and-approve-the-firmware-baseline)
for packaging already obtained and approved values; it does not solve acquisition.

For the existing qualification, the base was reconstructed from a separate
retained reference by removing its exact known appended signer list, then
appending the candidate's independently retained signer. Cross-prediction
matched, including ordered event digests. This is useful experimental evidence,
but subtraction does not authenticate the remainder. Do not promote that
reconstruction, an arbitrary guest export or a freshly computed pin into
production policy without the independent approval process above.

## Remaining gaps and production gates

| Gap | Required closure |
| --- | --- |
| Baseline origin and enrollment determinism | Establish one of the acquisition routes above, including the complete variable bytes, owner GUID and authority-selection behavior. A provenance string and hash pin only record an approval decision; they cannot create trust. |
| Baseline lifecycle | Define authenticated distribution, applicability, revocation and rollback policy for firmware/template/PK/KEK/db/dbx changes. When Azure changes the applicable variable bytes, obtain, independently approve and pin a replacement baseline, then regenerate expected PCRs. Persisted guest firmware state can differ from newly provisioned defaults; qualify both initial and subsequent boots. Never auto-approve mismatch-derived baselines. |
| Profile and phase qualification | Requalify changed firmware, enrollment serialization, authority selection, measurement sequences, boot paths, stub implementations or phase services. Updating baseline bytes alone cannot accommodate changed measurement behavior; update and qualify the predictor model/profile where necessary. The current tool neither detects Azure implementation changes nor proves all systemd 255 variants behave identically. |
| External firmware/driver coverage | Establish that separately loaded firmware volumes/EFI drivers outside approved hardware-launch coverage cannot affect the boot, or independently approve them using applicable measurements. The recipe installs none, but the inspected UEFI source does not prove deployed Azure configurations prohibit them. |
| Firmware acceptance | `sbverify` is not a full firmware trust/revocation emulator. Validate actual enrollment and boot behavior; a successful prediction does not guarantee firmware will accept the UKI. |
| Build integration and policy release | Decide where to invoke the predictor after final signing, retain its inputs/output, and approve/version expected values with each image release. Current invocation is manual and opt-in. |
| Relying-party verification | Implement authenticated quote/MAA claim validation, fresh challenge binding, required PCR coverage and comparison to independently approved predictions, with explicit mismatch rejection and rollback protection. Prediction JSON alone performs none of these. |
| PCR12/PCR13 and external inputs | Addons, external credentials and initrd system extensions remain separate policy inputs. The predictor emits zero-valued PCR12/13 references for a no-external-inputs policy; it does not model nonempty input sequences or disable those capabilities. New builds request both PCRs, but tested MAA tokens omit PCR12/13, including the tmpfs diagnostic that requested both. Obtain authenticated coverage and qualify the empty-input sequence, or establish qualified disablement. Matching PCR4/7/11 does not resolve those gaps. |
| Runtime integrity | PCR matching does not establish that the writable tmpfs overlay or retained cloud-init/agent/SSH management paths are hardened. Apply the recipe's separate production-hardening policy. |

The [focused tests](tests/test_pcr_prediction.py) cover serialized-variable
vectors and input sensitivity, Authenticode exclusions/padding/overlay,
section/phase behavior, an independent `systemd-measure` oracle, malformed
inputs and CLI signature-failure behavior. The [validation record](VALIDATION.md#evidence-levels)
distinguishes those offline checks from retained live-reference evidence.
Neither test category closes the baseline approval or full verifier gaps.
