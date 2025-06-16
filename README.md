Silent Kernel Pool Leak in AFD.sys via SIO_ADDRESS_LIST_QUERY

Abstract

AFD.sys’s central IOCTL dispatcher allocates nonpaged-pool buffers for socket-related IOCTLs but never zeros them before copying out the full allocation to user mode. This “pool-slack” leak allows any unprivileged process to read stale kernel memory—defeating KASLR and exposing sensitive data.

1. Background: AFD and WSAIoctl
   
   AFD.sys is the kernel driver behind Winsock operations.

   All socket IOCTLs (e.g. SIO_ADDRESS_LIST_QUERY) are routed through a single dispatch routine.

   User-mode calls WSAIoctl(..., SIO_ADDRESS_LIST_QUERY, NULL,0, OutBuf, Size, &Returned, NULL, NULL) to enumerate local addresses.

2. IOCTL Dispatch Entry Point

   The decompiled dispatcher (here called FUN_1c0001b10) shares these hallmarks of a classic IOCTL handler:

      32/64-bit check – to validate alignment of user pointers.

      Fetch IoControlCode and buffer pointers from the IRP.

      Parameter checks (size, permissions, handle validation).

      MDL allocation & page-locking for some paths.

      Subroutine calls based on the IOCTL code.

      IofCompleteRequest with the final status.

      Despite all that, there is no zero-initialization of newly allocated output buffers.

3. Vulnerability Flow
   
    1.Pool Allocation Without Zeroing
   
plVar10 = ExAllocatePool3(
    NonPagedPool,
    requestedSize,    // attacker-controlled
    'AdfR',
    &status
);
// NO RtlZeroMemory or ExAllocatePoolZero call here
     
     
    2.Partial Initialization


// Write header + payload only:
*(ULONG*)plVar10           = entryCount;
*(USHORT*)(plVar10 + 4)    = payloadLength;
memcpy(plVar10 + headerOffset, userSrc, payloadLength);

3.Blind Copy-Out


// Driver’s memcpy helper:
FUN_1c001e840(
    plVar10,            // source (kernel pool)
    IRP->UserBuffer,    // dest (user buffer)
    outputLength        // attacker-controlled or = requestedSize
);
Any bytes beyond headerOffset + payloadLength are left uninitialized—leaking stale pool contents.

4.Lookaside Path

Small requests use ExAllocateToLookasideListEx, again without zeroing.

5.MDL-Mapped Path

Some handlers build an MDL, map it into system space, write header+payload, then unmap. The unmapped tail is still uninitialized.

5. Impact
6. 
KASLR Bypass: Leaked kernel pointers let attackers pinpoint kernel base addresses.

Data Disclosure: Slack may contain credentials, tokens, heap metadata, or other sensitive info.

Privilege Escalation: Combined with a write-primitive, this leak can facilitate full SYSTEM compromise.

6. Root Cause

AFD’s IOCTL handlers allocate pool or lookaside buffers for output but never clear them before copying out the entire region. No calls to zeroing routines (RtlZeroMemory, ExAllocatePoolZero, etc.) appear in the dispatch or handlers.

This subtle “pool-slack” leak in AFD.sys exemplifies how an innocent-looking omission—failing to zero freshly allocated memory—can lead to powerful information disclosure. By addressing it, Windows can prevent trivial user-mode leaks of kernel memory in socket-related IOCTLs.





















