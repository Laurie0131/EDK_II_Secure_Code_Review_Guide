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


```
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

