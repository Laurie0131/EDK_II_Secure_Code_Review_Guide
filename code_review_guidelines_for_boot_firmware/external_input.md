 <!--- @file
  external-input.md for EDK II Secure Code Review Guide

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  Redistribution and use in source (original document form) and 'compiled'
  forms (converted to PDF, epub, HTML and other formats) with or without
  modification, are permitted provided that the following conditions are met:

  1) Redistributions of source code (original document form) must retain the
     above copyright notice, this list of conditions and the following
     disclaimer as the first lines of this file unmodified.

  2) Redistributions in compiled form (transformed to other DTDs, converted to
     PDF, epub, HTML and other formats) must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS DOCUMENTATION IS PROVIDED BY TIANOCORE PROJECT "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  EVENT SHALL TIANOCORE PROJECT  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-->




## External Input {#external-input}

External input describes data that can be controlled by an attacker. Examples include:

*   UEFI capsule image
*   Boot logo in Bitmap (BMP) or Joint Photographic Experts Group (JPEG) format
*   Contents of file system partitions
*   Read/write variables
*   System Management Mode (SMM) communication buffer
*   Network packets

**Previous Vulnerabilities:**

### Boot Logo Image {#boot-logo-image}

[At BlackHat 2009](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf), Invisible Things Lab demonstrated how to use a buffer overflow in BMP file processing to construct an attack and flash a new firmware. The BMP file is an external input where an attacker may input a large value for `PixelWidth` and `PixelHeight`. This causes `BltBufferSize` to overflow and results in a very small number. This is a typical integer overflow caused by multiplication.

---


```C++
EFI_STATUS ConvertBmpToGopBlt ()
{
 /// ...
  if (BmpHeader->CharB != 'B' || BmpHeader->CharM != 'M') {
    return EFI_UNSUPPORTED;
  }
  BltBufferSize = BmpHeader->PixelWidth * BmpHeader->PixelHeight
                    * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  IsAllocated = FALSE;
  if (*GopBlt == NULL) {
    *GopBltSize = BltBufferSize;
    *GopBlt = EfiLibAllocatePool (*GopBltSize);
```

---


To handle these cases, code should check for integer overflow using division, as shown below:

---
```
if (BmpHeader-&gt;PixelWidth &gt; MAX_UINT / sizeof 
(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) / BmpHeader-&gt;PixelHeight) {
    return EFI_INVALID_PARAMETER;

}
```
---

### SMM Callout {#smm-callout}

At [Black Hat DC 2009](https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf), Invisible Things Lab demonstrated a way to inject code into SMM. The SMM code referenced (`ACPINV` below) a function pointer in Advanced Configuration and Power Interface (ACPI) Non-Volatile Storage (NVS) memory and invoked this function address. An attacker may modify the function pointer address in ACPI NVS so it points to a malicious function.

---


```
mov [ACPINV+x], %rax
call *0x18(%rax)

```
---

A similar issue is also found in [ThinkPad 2016](http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html). The `SmmRuntimeCallHandle` is the pointer in ACPI Reserved memory. As such, the attacker may replace this function pointer with any address. 
This is shown in the line with the statement with `RtServices` below.

---


```
EFI_STATUS
EFIAPI
SmmRuntimeManagementCallback (
  IN EFI_HANDLE             SmmImageHandle,
  IN OUT VOID               *CommunicationBuffer,
  IN OUT UINTN              *SourceSize
  )
{
  SMM_RUNTIME_COMMUNICATION_STRUCTURE *SmmRtStruct;
  EFI_SMM_RT_CALLBACK_SERVICES        *RtServices;

  RtServices  = NULL;

  SmmRtStruct = (SMM_RUNTIME_COMMUNICATION_STRUCTURE *) CommunicationBuffer;
  RtServices  = (EFI_SMM_RT_CALLBACK_SERVICES *) SmmRtStruct->PrivateData.SmmRuntimeCallHandle;

  if (RtServices != NULL) {
    RtServices->CallbackFunction (RtServices->Context, mSmst, (VOID *) &SmmRtStruct->PrivateData);
    SmmRtStruct->PrivateData.SmmRuntimeCallHandle = NULL;
  }

  return EFI_SUCCESS;
}

```


---

It is critical that SMM never reference memory outside System Management RAM (SMRAM) for function pointers.

In the latest Intel processors, the SMM_Code_Access_Chk feature can be used to block code execution outside of the value set by the SMRAM Range Register (SMRR). This feature MUST be enabled if it is supported.

The latest versions of EDK II also enable Executable Disable (XD) for memory addresses outside of SMRAM.

### SMM Communication {#smm-communication}

In [CanSecWest 2015](http://www.c7zero.info/stuff/ANewClassOfVulnInSMIHandlers_csw2015.pdf), a new class of SMM attack was disclosed. The attacker may construct a SMM 
communication buffer that points to memory owned by System Management RAM (SMRAM) or Virtual Machine Monitor (VMM), then pass this address into a System Management Interrupt 
(SMI) handler. This causes the SMI handler to perform the write for the attacker. This typically classified as a “confused deputy” attack. See the lines with `CommBuffer` 
and with the  `CopyMem` statement below.

---


```
SmmVariableHandler ()
//  ...
  SmmVariableFunctionHeader = (SMM_VARIABLE_COMMUNICATE_HEADER *)CommBuffer;
  switch (SmmVariableFunctionHeader->Function) {
  case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    SmmVariableHeader = (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *)
    SmmVariableFunctionHeader->Data;
    Status = VariableServiceGetVariable (
               ...
               (UINT8 *)SmmVariableHeader->Name + SmmVariableHeader->NameSize
               );
}

VariableServiceGetVariable (
  // ...
  OUT VOID *Data
  )
{
 // ...
  CopyMem (Data, GetVariableDataPtr (Variable.CurrPtr), VarDataSize);
}

```
---
