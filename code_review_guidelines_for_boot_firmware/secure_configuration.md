## Secure Configuration {#secure-configuration}

For security features, it is not a good idea to use variables to control the behavior because they can be altered by an attacker to bypass protection. The general configuration also includes the system state, memory configuration, different boot mode, etc.

**Previous Vulnerabilities:**

### UEFI Secure Boot {#uefi-secure-boot}

In [CanSecWest 2014](https://cansecwest.com/slides/2014/AllYourBoot_csw14-mitre-final.pdf), MITRE disclosed the vulnerability that the OEM used setup a variable to control the image verification policy. That meant the UEFI secure boot could be easily bypassed.

=====================================

DxeImageVerificationHandler(EFI_EXECUTABLE Image) {

switch (getImageOrigin(image)) {

case IMAGE_FROM_OPTION_ROM:

policy = Setup.LOAD_FROM_OROM;

case IMAGE_FROM_FIXED_DRIVE:

policy = Setup.LOAD_FROM_FIXED;

case IMAGE_FROM_REMOVABLE:

policy = Setup.LOAD_FROM_REMOVABLE;

...

if (policy == ALWAYS_EXECUTE)

return EFI_SUCCESS;

else

return IsImageAllowed(image);

}

=====================================

For any security feature, there should be no way to bypass it in the production. No variable should be used to control it. If a Platform Configuration Database (PCD) is used, the PCD must be statically configured.

### Intel® Boot Guard {#intel-boot-guard}

In [2016](https://github.com/flothrone/bootguard/blob/master/Intel%20BootGuard%20final.pdf) and [DefCon 2017](https://github.com/flothrone/bootguard/blob/master/Intel%20BG%20part2.pdf), Ermolov disclosed how to bypass Intel® Boot Guard.

In [BlackHat 2017](https://www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf) and [BlackHat 2019](http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Matrosov-Modern-Secure-Boot-Attacks.pdf), Mastrov disclosed how to bypass Intel® Boot Guard.

=====================================

EFI_STATUS BootGuardPei (EFI_PEI_SERVICES **PeiServices, VOID *Ppt)

{

...

if (!((BootGuardHashKeySegment1 == 0) {

CalculateSha256 (BootGuardHashKeySegment1);

CalculateSha256 (CurrentBootGuardHashKey1);

if (!MemCmp (BootGuardHashKeySegment1, CurrentBootGuardHashKey1, 32)) {

BootGuardVerifyTransitionPEItoDXEFlag = 1;

} else {

BootGuardVerifyTransitionPEItoDXEFlag = 0;

return EFI_SUCCESS;

}

}

return Status;

}

EFI_STATUS BootGuardDxe (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)

{

...

if (BootGuardVerifyTransitionPEItoDXEFlag == 0) {

BootGuardRegisterCallback();

}

return EFI_SUCCESS;

}

=====================================

The summary of the issue is below:

1.  The Intel® Boot Guard configuration is not set properly.
2.  The verification does not always happen in all boot modes. For example, the verification is done only once every 12 times a device is powered up.
3.  The software logic issue in Intel Boot Guard PEI or DXE that the verification may be bypassed in some cases.

The mitigation is:

1.  Fuse configuration – always verify the fuses are configured for security.
2.  Verification – ensure that verification occurs in all boot modes and boot paths.

### TCG Trusted Boot {#tcg-trusted-boot}

In [BlackHat 2018](https://i.blackhat.com/briefings/asia/2018/asia-18-Seunghun-I_Dont_Want_to_Sleep_Tonight_Subverting_Intel_TXT_with_S3_Sleep.pdf), Han disclosed an issue about TPM measurements in a DRTM environment. This issue was related to the S3 resume path, where TBOOT only measured code and read-only data for the Measured Launch Environment (MLE). However, TBOOT did not measure the required initialized data. This created a condition where an attacker could hijack the control flow and exploit TBOOT.

=====================================

_mle_start = .; /* beginning of MLE pages */

*(.text)

*(.fixup)

*(.gnu.warning)

} :text = 0x9090

.rodata : { *(.rodata) *(.rodata.*) }

. = ALIGN(4096);

_mle_end = .; /* end of MLE pages */

.data : { /* Data */

*(.data)

*(.tboot_shared)

CONSTRUCTORS

}

=====================================

Mitigation occurs when MLE sets up the environment, ensuring that all critical data (code, read-only data, and initialized data) is measured, including the function pointers. This demonstrates the importance of a complete measurement.

In [BlackHat 2019](http://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Seunghun-Finally-I-Can-Sleep-Tonight-Catching-Sleep-Mode-Vulnerabilities-of-the-TPM-with-the-Napper.pdf), Han disclosed an issue using TPM in a static root-of-trust for measurement (SRTM) environment. During the S3 resume path, if the OS does not send Shutdown(STATE) the firmware Startup(STATE) will fail. Some platform firmware only sent Startup(CLEAR) which left all Platform Configuration Registers (PCR) open.

=====================================

PeimEntryMA ()

{

if (BootMode == BOOT_ON_S3_RESUME) {

Status = Tpm2Startup (TPM_SU_STATE);

if (EFI_ERROR (Status) ) {

Status = Tpm2Startup (TPM_SU_CLEAR);

=====================================

The mitigation extends the PCR with an EV_SEPARATOR error, which takes advantage of proper error handling.