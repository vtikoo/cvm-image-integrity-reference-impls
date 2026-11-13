# Validation scope

[Recipe](README.md) | [Manual workflow](LOCAL-BUILD.md) | [Repository index](../../README.md)

## Deployment entry-point qualification

The Bash and PowerShell entry points share a Python deployment/cleanup engine.
Local tests exercise configuration/plan guards, failure handling, resource
ownership, publication and SSH evidence checks without Azure resources.
The shared engine's 58 tests passed under both Linux and native Windows Python,
including real RSA certificate-profile checks with OpenSSL; no tests were
skipped. Bash argument/failure propagation and actual Windows PowerShell
plan/network-option/failure handling checks passed. The existing 31
recipe, attestation and guest-validation regressions also passed.
The latest focused Linux suite passed 93 tests; native Windows passed the 64
engine/guest-verifier tests. These local tests do not establish Azure behavior.
The Gallery 1.0.4 results below were obtained through the manual workflow; do not
relabel them as controller acceptance. A separate fresh-image managed flow passed
with explicit recovery, as recorded below; an uninterrupted controller run remains
unqualified.

Live controller testing on 2026-11-13 successfully created the private builder
and approved temporary test routing, submitted the large recipe request through
a private JSON file, and completed builder prerequisite installation. It exposed
Azure CLI quota strings, Windows/WSL argument-size limits, byte-literal serial
output and interleaved service messages in SSH boot-key publication. The fixes
have focused local regressions, including rejection of ambiguous host keys;
SSH authentication remains strict. A fresh corrected attempt was then rejected
by the VM SKU availability preflight before resource allocation. Those early
attempts did not complete image build/publication or reference acceptance.

Managed live retries exposed an APT package-index lock race during provisioning
and managed-command configurations being reset to empty. Provisioning now waits
boundedly for package locks and preserves genuine package errors. REST bodies use
private request files regardless of size. A live benign managed-command probe
passed with the legacy controller's policy-tag propagation; this is not a
successful image build or complete deployment. Focused Linux tests cover the
package-lock behavior, and Linux/Windows tests cover request transport and
policy-tag preservation.

The default workflow now uses Managed Run Command for build-artifact retrieval
and first/reboot basic acceptance; installed collector provenance is still
checked, but SDK execution is explicitly deferred to SSH (`NOT_RUN`).
Focused tests cover multi-chunk integrity, unchanged-artifact enforcement,
command removal across reboot, distinct boot IDs, retention gates and a
deallocated-reference handoff without network changes. SSH access now requires
the user to confirm or reconfigure approved networking; no existing NSG profile
is copied and no public reference endpoint is automatically attached. This is
not a user-driven SSH connectivity check. The recovered fresh managed acceptance
below also does not qualify subsequent SSH connectivity.
The earlier preflight incorrectly treated zone-only SKU restrictions as a
regional prohibition; non-zonal requests now accept zone-only restrictions
while continuing to reject location restrictions, with a focused regression.

Guest acceptance now confirms the mounted read-only dm-verity lower, healthy
mapper status and independently expected root hash/data/hash devices without a
full disk scan on either boot. Two focused regressions cover query-only acceptance
and rejection of wrong mapper/hash/devices or a failed mount policy. The default
clean-room build also omits full verification scans and deliberate corruption
tests; the existing qualification script and component tests remain separately
invoked. Verity hash-tree generation, image/signature/format checks and live
mount confirmation remain in the default flow.
Earlier manual results below describe the previous full-scan verifier.

### Fresh image and recovered managed acceptance, 2026-11-13

The controller built a fresh image on a dedicated standard Ubuntu builder,
including the installed patched native collector, and uploaded it directly using
the builder's managed identity. Build took 18 minutes 28 seconds; upload plus full
blob readback took 9 minutes 53 seconds. Gallery version 1.0.0 in the new run's
separate Gallery completed replication with the exact signer/Microsoft template.

The original command stopped after replication because Azure returned the display
region `West US 3`, not `westus3`. Recovery normalized that readback, waited for
stable provisioning, and exposed a second API-shape issue: the VM model omitted
OS-disk size. The controller now reads the actual managed disk when necessary and
accepts Azure CLI's `diskSizeGB`/`diskSizeGb` spellings, while still requiring 64 GiB.
Focused Linux/Windows regressions cover both fixes.

Explicit recovery reused the independently recorded build/published image and
created the Intel TDX reference with Secure Boot, vTPM and `VMGuestStateOnly`.
Managed acceptance passed on first boot and after an Azure-triggered real reboot:
expected kernel/signer, mounted healthy read-only dm-verity lower, expected
root/data/hash identities, tmpfs upper/work, agents/cloud-init and installed
collector provenance. The measured 136 MiB / 2,051-inode workload disappeared
after a distinct boot ID. No full guest disk scan or SDK/MAA request was made.

Ownership-checked cleanup removed the builder, builder NIC/OS disk, source disk,
upload storage and upload permission. Independent final Azure queries confirmed
one retained reference VM, deallocated, with no temporary build/upload resources.
Gallery and private-only reference networking remain for user-confirmed SSH
access. The earlier manually qualified reference remained running and unchanged.

Private evidence retains the original failures and marks the result
`RECOVERED_ACCEPTANCE_COMPLETE` with `uninterruptedControllerRun: false`.
All build/publication/first-reboot acceptance/cleanup stages ran against Azure,
but this must not be presented as an uninterrupted one-command deployment pass.

## Evidence levels

| Surface | Scope |
| --- | --- |
| Marketplace catalog | Read-only Azure queries on 2026-11-12 returned the pinned non-Pro Ubuntu 24.04 CVM version in westus3, x64/Gen2 and `TrustedLaunchAndConfidentialVmSupported` |
| Offline policy tests | 15 tests passed: generalized-source guards, writable-state finalization, pinned input, exact generated boot inputs, private mount-propagation enforcement, temporary resolver permissions/exact restoration, required switch-root dependency, volatile-service override, shared-parent setup and root-policy success/rejection paths |
| Guest-verifier tests | 6 tests passed: completed clean cloud-init, explicit recoverable-warning reporting, fatal/incomplete/malformed-status rejection, installed collector/wrapper/provenance checks, query-only dm-verity mount acceptance and wrong mapper/hash/device/mount-policy rejection |
| Real userspace tests | SHA-256 verity format/verification and corrupted-data/wrong-hash rejection; kernel-less Dracut/systemd initramfs and RSA-signed systemd-stub UKI, exact section checks and changed-command-line rejection |
| Pinned patched attestation SDK | Exact recipe patch application and default RustCrypto release build passed: 34 event-log and 70 guest-attestation tests. Native backend passed those 104 plus 24 client regressions. Genuine retained firmware/userspace logs produced byte-identical supplementation and matched the actual CVM quote. Wrapper/build's 10 tests require `0-8,11,12`, report the PCR12 gap, check paired SDK overrides and pre-hash installation, and reject incomplete evidence/fallback without claiming remote verification |
| Dedicated MAA setup helper | 7 setup tests passed on Linux and native Windows Python; the combined attestation/helper suite passed 17 tests on Linux. Cases cover explicit approval, existing-provider refusal, default-policy drift, exact one-rule modification/readback, restorable default policy, wrong issuer/malformed response and private error retention. Authenticated `2025-06-01` policy GET/decoding passed read-only against the existing test provider. New-provider creation and policy PUT are mocked in these helper tests; a fresh live helper-created provider is not claimed |
| Complete Marketplace conversion | **Passed on 2026-11-12** using an unbooted disk from the exact Marketplace pin on a dedicated Ubuntu 24.04 Azure builder; complete build marker includes fixed-VHD validation |
| Kernel/driver compatibility | Matching signed-module gates passed for original kernel `7.0.0-1016-azure-fde`; source configuration includes `CONFIG_INTEL_TDX_GUEST=y`; this kernel booted the tested Intel TDX `Standard_DC4es_v6` CVM |
| Real live dm-verity corruption | **Passed in the complete image build**: disposable corrupted data rejected both offline verification and live mapper reads, with mapper status `C` |
| Visible volatile-overlay backing | **Passed on the builder and actual CVM**: bind-mounted read-only lower, retained tmpfs upper/work, required initrd guard and runtime guard passed, including after a real reboot |
| Azure signer enrollment / CVM boot | Gallery 1.0.3 replication and exact custom signer/Microsoft template readback passed; `VMGuestStateOnly` booted with Secure Boot enabled and the independently expected signer present in actual firmware db. Initial and corrected-image `NonPersistedTPM` attempts reported Compute `SecureBootClientError` |
| First boot / workload / real reboot | **Passed**: full verity verification and firmware/kernel/hash/device/agent checks on both boots; 136 MiB and 2,051 measured tmpfs inodes; distinct reboot ID and entire workload absent |
| Actual PCR-11 quote / MAA flow | Installed SDK failed on omitted systemd phase events; genuine combined replay matches actual PCR 11. Tmpfs-only supplemented-log diagnostic obtained a real custom-policy MAA token: signature/issuer/lifetime and signed raw values verified for `0-8,11`. PCR 12 was requested but omitted from token coverage. **Installed collector and independent expected-UKI verification remain unqualified** |
| Native patched collector / expanded PCRs | **Passed on 2026-11-13** directly in CVM tmpfs without firmware-log bind mounts: requested exactly `0-8,11,12`; real custom-policy MAA token signature/issuer/lifetime and signed values verified for `0-8,11`; explicit missing-PCR12 warning and incomplete-coverage receipt. Full results retrieved over authenticated SSH with matching SHA256 hashes |
| Complete native-collector image rebuild | **Passed on 2026-11-13** on the retained dedicated builder using the same independently inspected source and signer: 104 SDK tests, pre-hash installed collector/wrapper/provenance gate, signed UKI sections, verity/corruption and fixed-VHD checks passed. Final output hashes and SSH-retrieved evidence archive verified |
| Native-collector Gallery 1.0.4 / SSH acceptance | **Passed on 2026-11-13**: completed replication and exact signer/template readback; actual Intel TDX CVM first/reboot SSH acceptance with installed binary/wrapper/provenance checked on both boots; 136 MiB / 2,051 inode workload absent after distinct boot; installed collector obtained independently verified custom-policy MAA token for PCRs 0-8,11, with the PCR12 gap retained. Reference confirmed deallocated; previous Gallery versions and custom policy retained |
| Fresh clean-room image / recovered managed flow | **Passed with explicit recovery on 2026-11-13**: automatic build/upload/Gallery replication, managed first/reboot mounted-verity acceptance, 136 MiB / 2,051-inode workload loss and cleanup/deallocated retention. No full disk scans/corruption qualification or SDK/MAA run. Uninterrupted one-command deployment remains unqualified |

These tests are not simulated evidence of Azure firmware behavior. A UKI with
a synthetic kernel payload proves packaging/signature/section binding only.
The Dracut userspace test excludes kernel modules explicitly; the real build
requires matching signed source modules and an original kernel payload.

The build's success marker is emitted only after root finalization, matching
driver inspection, initramfs inventory checks, ext4 checks, verity generation,
signature and exact signed-section checks and fixed-VHD geometry/footer checks.
Full-disk verification and deliberate corruption tests are optional qualification,
not part of the current marker. It does not
mean firmware enrollment or Azure acceptance passed.

The actual build exposed two builder-integration issues: a restrictive umask
made the temporary resolver unreadable by APT's sandbox user, and shared mount
propagation leaked a data-root mount into host-service namespaces. The producer
now uses a temporary mode-0644 resolver, restores the original file or symlink
before hashing, fails on package-index download errors, and requires private
build-directory mount propagation. Focused regressions and the subsequent
complete Marketplace build passed with these fixes.

The initial CVM boot also exposed a native systemd overlay-layout mismatch:
systemd overmounted the ext4 root at the same target and detached the tmpfs
backing mount, so the guard could not independently inspect the effective root
and upper/work filesystems. The custom `systemd-volatile-root.service` setup now
relocates the verified lower and retains the backing tmpfs at visible paths. The
real-image builder probe, both actual Dracut/signed-UKI component tests, and a
new complete Marketplace conversion passed with this change. The corrected
image passed signed-section, live-corruption and fixed-VHD gates; version 1.0.1
alone did not establish a successful CVM boot.

The stateless attempt used the same originally published image. Its Azure
Compute VM instance-view reported
`ProvisioningState/failed/SecureBootClientError`, not an MAA token error.
Neither serial nor screenshot diagnostics were available (HTTP 404), so this
does not establish the precise rejected component, failed SKR, or a general
incompatibility between custom UEFI certificates and `NonPersistedTPM`.
The corrected image was published as Gallery version 1.0.1 with the unchanged
public signer and Microsoft template. Independently retained output hashes and
root hash matched the uploaded VHD and verified UKI. A distinct VM using this
version, `NonPersistedTPM`, Secure Boot/vTPM and managed boot diagnostics enabled
at creation reported the same Secure Boot error within about 20 seconds. Both
diagnostic blobs were again unavailable. The failed target was verified
deallocated; stateless boot and its guest/reboot/MAA qualification remain blocked.

The corrected image was subsequently retried with upstream's persisted
`VMGuestStateOnly` mode. Its serial log proves Secure Boot enabled, the expected
embedded root hash and successful verity activation. It then exposed a second
setup issue: PID 1's shared parent mount forbids `mount --move` of `/sysroot`.
The helper now binds the read-only lower at its retained path, unmounts the
original lower and installs the overlay without globally changing mount
propagation. A real-image probe with an explicitly shared parent reproduced
the old move failure and passed the new helper and both root guards; all 15
policy tests and both real userspace component tests passed. The subsequent
complete image 1.0.3 build also passed signed-section, corruption and fixed-VHD
gates. A transient negative-mapper cleanup warning was followed by an explicit
check confirming that the owned negative mapper no longer existed. Azure
first/reboot acceptance subsequently passed for this change, as recorded below.

## Demonstrated persisted-TPM acceptance

Gallery version 1.0.3 booted on an Intel TDX `Standard_DC4es_v6` CVM in westus3,
using `VMGuestStateOnly`, Secure Boot and vTPM. The OS disk was an ordinary
64-GiB managed disk: no ephemeral `diffDiskSettings`, confidential OS-disk
encryption or `DiskWithVMGuestState` was requested.

The independent verifier confirmed the actual firmware signer, exact original
kernel and embedded command line, live data/hash devices and root hash, healthy
read-only verity lower, visible tmpfs backing, no swap and usable guest agent.
It fully verified the data partition on both boots. The first workload consumed
142,610,432 bytes (136 MiB) and 2,051 inodes. The boot ID changed from
`7cba07f7-01c5-42b7-b8af-c97a4927989b` to
`33486c1d-892b-46d9-8cbd-2c4986e1cc5a`, and the entire workload disappeared.
Independently retained private build and guest JSON records support these
results; raw VM-identifying evidence and tokens are not published here.

After reboot, cloud-init completed with exit 2 and an Azure provisioning-media
unavailable / IMDS fallback warning, but no fatal errors. The externally supplied
verifier now explicitly checks JSON status and fatal-error arrays, reports and
retains recoverable warnings, and rejects incomplete or failed provisioning.
The full post-reboot recheck passed without rebuilding the VHD.

## Shared-endpoint MAA investigation: no successful token

The installed pinned SDK submitted genuine CVM evidence to
`https://sharedwus3.wus3.attest.azure.net`. Its initial request quoted SHA-256
PCRs `0,2,4,7,11`; MAA returned HTTP 400 `PcrDoesNotMatchTcg` for PCR 11.
Evidence collection took approximately 128 ms; this was not a long MAA wait.
Full guest disk verification and Azure managed-command scheduling are separate
operations.

The SDK reads only `/sys/kernel/security/tpm0/binary_bios_measurements`.
Systemd additionally extends the actual `sysinit` and `ready` phase strings into
PCR 11 and records their digests in `/run/log/systemd/tpm2-measure.log`.
It does **not** measure journal contents. Read-only TPM PCR reads and replay of
genuine captured records established:

| SHA-256 PCR 11 source | Value |
| --- | --- |
| Firmware log replay only | `edf97efb412cf0d2b128a660dbc686091a5c280c7216ce06f476b2e45e5f7e86` |
| Firmware plus genuine phase events | `c8f073389ac35102792ea15ca251171d9150920a36977ac886adbfd7f2f0605e` |
| Actual TPM read / PCR reported in MAA mismatch | `c8f073389ac35102792ea15ca251171d9150920a36977ac886adbfd7f2f0605e` |

A diagnostic in tmpfs appended the genuine recorded phase digests as TCG2
`EV_IPL` events to unaltered firmware bytes. Every appended digest was checked
against its actual phase string. A private mount namespace supplied this
explicitly supplemented input to the unchanged SDK; the protected image, TPM
and quote generation were unchanged. This is **not** an untouched firmware log.

With PCRs `0,2,4,7,11`, the error advanced to `PcrQuoteHashDoesNotMatch`:
`Pcr index 1 not present in quote`. A second diagnostic quoted all boot PCRs
`0,1,2,3,4,5,6,7,11`, retaining PCR 11. MAA then returned
`PolicyEvaluationError` / `PolicyValidationFailure` with the explicit deny rule:

```text
[type=="x-ms-azurevm-dbvalidated", value==false] => deny();
```

A further real SDK test selected exactly `0,1,2,3,4,5,6,7,8,11,12`,
using a fresh relying-party challenge and the same genuine supplemented log.
It received the same HTTP 400 `PolicyValidationFailure` / `dbvalidated=false`
denial, with no PCR-log or missing-PCR error reported. Adding PCRs 8 and 12 did
not change the observed policy blocker; no token was issued.

This demonstrates a further provider-policy rejection, distinct from firmware
Secure Boot acceptance and the earlier event-log/quote errors. It does not
prove successful token issuance, a general custom-key attestation prohibition,
or an independently authenticated expected-UKI result. No provider policy was
changed, Secure Boot disabled, PCR 11 omitted or synthetic evidence substituted.
The installed collector still uses its original firmware-only input and exact
PCR set; these tmpfs diagnostics are not an integrated SDK fix.

## Custom-policy endpoint: real token issued

A dedicated AAD-trust provider in westus3 was created for this test. Its actual
default `AzureGuest` policy matched the shared provider's retrieved policy.
Only the `[type=="x-ms-azurevm-dbvalidated", value==false] => deny();` rule was
removed. Default-key, debugger, Secure Boot, signing and dbx checks were kept.
Authenticated policy management used API `2025-06-01`; exact policy readback
matched the submitted bytes, SHA-256
`e573d47b3db3f9ce237ee4fa61a74cbf14523b19d6c0d63b8687b9a441c73409`.

The unchanged SDK, in the same private tmpfs mount-namespace diagnostic, used a
fresh relying-party challenge, genuine supplemented event log and PCR selection
`0,1,2,3,4,5,6,7,8,11,12`. The provider issued a real token. Its RS256 signature
was verified against keys obtained over HTTPS from that provider's discovered
JWKS endpoint; expected issuer and current validity interval were checked.
The signed token reports:

- `secureboot=true`, `x-ms-azurevm-dbvalidated=false`;
- default-key, debugger, signing and dbx validation claims remain true;
- `x-ms-azurevm-attested-pcrs` covers `0,1,2,3,4,5,6,7,8,11`;
- `x-ms-azurevm-attested-pcr-values` contains raw base64 SHA-256 digests for
  those PCRs, including PCR 7 and PCR 11; all match the submitted request.

### Known gap: MAA does not return PCR 12 in the tested token

PCR 12 is present in the submitted PCR set and values, with an all-zero digest,
but is **absent from the signed coverage/value claims**. Do not claim complete
coverage of the requested set or infer that a zero PCR alone explains omission:
the token includes PCR 8 with a zero value.

Keep PCR 12 in the required expanded request `0-8,11,12`; do not remove it to
hide the gap. Until the provider returns both its signed coverage and value,
a relying party cannot verify PCR 12 from this token alone. The cause remains
unestablished; this observed gap is not a claim that every MAA configuration
omits PCR 12.

### Verified evidence and remaining limits

The signed PCR 11 value matches the independently replayed genuine measurements
above. The submitted event-log SHA-256 matches the diagnostic's exact normalized
bytes. Full SDK response and stderr were retrieved with independent SHA-256
checks and retained privately. No raw token or VM-identifying evidence is
published here. The custom endpoint and working Gallery image are explicitly
retained per the test owner's instruction.

This is successful custom-policy token issuance, not proof that the installed
collector works without supplementation. Removing default db validation does
not pin our custom signer or expected UKI. Independent AK/quote/TEE and challenge
binding and full expected-UKI identity checks are not implemented by this
diagnostic; no production-complete remote image verifier is claimed.

A further publication experiment explicitly set
`publishingProfile.targetRegions[].encryption.osDiskImage.securityProfile.confidentialVMEncryptionType`
to `NonPersistedTPM`, supported by Gallery API version 2024-03-03. Azure rejected
this regional profile under the existing
`TrustedLaunchAndConfidentialVmSupported` definition, requiring the
`ConfidentialVM` feature. A separate `ConfidentialVM` definition then rejected
custom `securityProfile.uefiSettings`, stating that UEFI customization is only
supported for `TrustedLaunchSupported`, `ConfidentialVmSupported` or
`TrustedLaunchAndConfidentialVmSupported`. No image with this explicit profile
was successfully published. These API results establish the tested
configuration constraints, not a universal claim that every stateless custom-key
boot mechanism is unsupported.

Operational evidence retrieval also exposed stale instance-view output when
managed Run Command names were reused after deletion. The independent upload
hash gate rejected the old build records before publication; they were
quarantined and retrieved again using unique image-scoped command names. Do not
accept a successful PUT or an old execution result as evidence of a new command.

## Native SDK collector: direct tmpfs acceptance

The SDK fix is carried as a patch over the pinned upstream revision, rather
than replacing the firmware path through a private mount namespace. The patched
default RustCrypto CLI and updated expanded-PCR wrapper were staged under
`/run` on the retained Gallery 1.0.3 CVM. No VHD rebuild, replacement, reboot,
Secure Boot change or provider-policy change was needed.

The SDK read 46,764 firmware bytes and 1,424 genuine systemd userspace bytes,
producing a 47,020-byte combined log. The actual transferred event-log bytes have
SHA256 `724d08612131e01c1cf6074a7e1e30288cfb2a2d7e8a1a73f796d764a4a91e12`,
identical to the earlier independently normalized genuine records. The requested
PCR set was exactly `0,1,2,3,4,5,6,7,8,11,12`.

The custom provider issued a real token. Independent verification checked its
RS256 signature against trusted provider JWKS, expected issuer, current lifetime
and signed raw values for PCRs 0-8 and 11 against the complete submitted request.
PCR11 matches the genuine replay above. PCR12 is still absent from both signed
claims; the wrapper explicitly warned and recorded incomplete coverage.
The receipt remains `NOT_VERIFIED`; independent token verification is a separate
test, not a new assertion by the guest wrapper.

Native SDK binary SHA256:
`9b7230a17bcb1a6e5ba9ad4fa88427ca49743fb58bd9ff9be0a97558a6374328`.
Pinned patch SHA256:
`8831ddc355fd5f03e77e5d12eabcdb204239ad11b325518335753f89d455e3bc`.
Guest binary and receipt provenance matched the independent build record.

Managed-command evidence retrieval was slow. SSH subsequently worked through
existing corporate-network access rules, without opening public SSH ingress.
The host key was authenticated against Azure boot diagnostics before login.
The complete SDK response, receipt and stderr were retrieved over SSH and all
file SHA256 hashes matched the guest. Raw tokens and VM-identifying evidence
remain private. The custom endpoint and working Gallery image were freshly
confirmed retained.

Gallery 1.0.3's protected lower still contains the original collector; the tmpfs
test does not update it. Current recipe builds install the patched SDK before
verity generation. The build now checks the installed binary, wrapper and
provenance after package operations and records their hashes in independent
build evidence. Guest acceptance checks those files on both boots when supplied
the new build record; legacy records explicitly leave the collector unchecked.
These gates alone do not establish Azure boot or installed-collector MAA
acceptance; the separate Gallery 1.0.4 tests below supply that evidence.
AK/quote/TEE authentication, fresh challenge-bound quotes and
independent expected-UKI identity remain separate, unimplemented verification
requirements; this test does not claim production remote image verification.

## Rebuilt image with the native collector

On 2026-11-13 the updated recipe completed a new image build on the retained
exclusive Azure builder. The retained raw source was compared byte-for-byte
with the unmounted original source disk before building; the inspected original
kernel `7.0.0-1016-azure-fde`, matching modules and original signer were reused.
The SDK's 34 event-log and 70 guest-attestation tests passed. Its built binary
SHA256 matches the native collector previously tested in CVM tmpfs above.

The installed binary, expanded-PCR wrapper and SDK provenance passed the final
pre-hash gate. The signed UKI, exact sections, full verity verification, real
offline/live corruption rejection and fixed-VHD gates passed, followed by
independent rechecks of all output hashes. Build mounts were released.

- Root hash: `637b0ed40d72ca6938cad5fd6006e067f4017f8c394722f8558f60912bdd6382`.
- Fixed VHD SHA256: `302175eccdfe27a47f282f3fdef6af1fefb8db892a80ca79d742ad8b0eb639dc`.
- Signed UKI SHA256: `e9a3c2c3ea28722052b741cf8d77cbf01b13eacc374b5b12abc17a65fce0659c`.

The complete build evidence was retrieved over authenticated SSH; the archive's
SHA256 matched the builder before extraction and its final build/installation
records agree. The rebuilt image remains on the builder and was subsequently
uploaded through its managed identity to a new private page blob, without
changing previous image blobs or the MAA policy.

### Gallery 1.0.4 publication and installed-collector acceptance

The new version completed replication with the exact original signer and
Microsoft UEFI template read back from Azure. With the test owner's approval,
the existing reference CVM was replaced, retaining its network and all previous
Gallery versions. Its actual control-plane model confirms Gallery 1.0.4,
`Standard_DC4es_v6`, `ConfidentialVM`, Secure Boot/vTPM and `VMGuestStateOnly`.

Both guest checks ran over SSH, not managed Run Command. The initial host key
was authenticated from Azure boot diagnostics containing the independently
expected new root hash. After the real guest-requested reboot, the regenerated
host key was independently authenticated before reconnecting. Both boots passed
full verity, firmware signer, kernel, root/device, tmpfs, installed
collector/wrapper/provenance and agent checks. The first boot allocated
142,610,432 bytes and 2,051 inodes. Distinct boot IDs and disappearance of the
complete workload passed. Cloud-init completed without fatal errors on both
boots; its recoverable post-reboot warning was explicitly retained.

The installed collector, without SDK overrides, log bind mounts or compilation
in the CVM, requested exactly `0-8,11,12` with a fresh relying-party challenge.
The unchanged custom-policy provider issued a token whose RS256 signature,
approved issuer, lifetime, retained validation claims and raw signed PCR values
for `0-8,11` were independently verified against the request. The signed PCR11
value was `34405150ce4b09a900fd40f2d9eab08805a2b312c745e02ee77ccfd18771fe50`.
PCR12 remains absent from signed coverage/values and is not claimed as attested.
The complete private response, request, token, receipt and stderr were retrieved
over authenticated SSH; every transferred SHA256 matched the guest.

The reference was subsequently confirmed deallocated. Gallery 1.0.4, previous
Gallery versions, the builder/signing inputs and custom endpoint remain
retained. This qualifies the installed evidence collector on the tested image,
not independent AK/quote/TEE authentication, fresh quote challenge binding,
expected-UKI remote identity, stateless boot or production-complete attestation.

## Required before claiming a demonstrated configuration

1. Retain acquisition evidence for the exact unbooted source and its module,
   kernel and package versions. Complete the offline build on an exclusive
   builder and retain all checksums and gate evidence.
2. Publish the actual VHD with its actual public UKI signer in Gallery UEFI db;
   require completed replication and exact signer/template API readback.
3. Boot a supported ConfidentialVM with Secure Boot, vTPM and
   `VMGuestStateOnly`; record the actual Azure image/security profile. This
   persists encrypted VMGS but does not request confidential OS-disk encryption.
   Qualify `NonPersistedTPM` separately rather than inheriting these results.
4. Run the guest verifier using independently retained build inputs. Confirm
   firmware db and live kernel/hash/device identities, healthy read-only verity
   lower, writable tmpfs overlay, no swap, usable agents and cloud-init.
   Use authenticated SSH to the launched CVM, with strict host-key checks and
   an approved network path, rather than managed Run Command. For new builds,
   require installed collector/wrapper hashes and provenance to match the
   independent build record.
5. Save first-boot evidence outside the guest, perform a real reboot, and require
   a different boot ID and disappearance of the measured tmpfs workload.
   Independently authenticate the regenerated SSH host key before reconnecting;
   restage the verifier and independent inputs over SSH.
6. Qualify firmware removable-media boot behavior, kernel CVM hardware support,
   failure behavior under corruption and deployment cleanup in that environment.
7. Run the installed `cvm-attest` over SSH with a relying-party challenge and an
   explicit approved MAA endpoint. Retain the quote, PCR values, TEE evidence,
   event log and returned token. Require independent verification of token,
   AK/quote/TEE binding, freshness and expected full UKI measurements before
   calling the expected root hash attested. Retrieve complete private output
   over authenticated SSH and check transferred file hashes; do not reuse stale
   managed-command output as evidence. A PCR-11 coverage index is not its
   digest; the observed signed `x-ms-azurevm-attested-pcr-values` claim provides
   raw values only for the listed PCRs. User-data binds the TEE report, not
   quote `extraData`.

No production-complete root-hash attestation, rollback protection, immutable
effective-root executable policy, OS-disk encryption or general CVM-family
compatibility is claimed. Existing Ubuntu 22.04 or Azure Linux experiments do
not supply missing evidence for this independent Ubuntu 24.04 boot chain.
