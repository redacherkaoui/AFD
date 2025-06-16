Uninitialized Kernel Memory Disclosure in afd.sys via SIO_ADDRESS_LIST_QUERY

A kernel information leak exists in Windows’ AFD (Ancillary Function Driver) subsystem due to uninitialized pool memory being copied to user-mode in response to certain IOCTLs, including SIO_ADDRESS_LIST_QUERY. Any local user can use this to leak portions of kernel memory, including potentially sensitive data, on fully patched Windows 11 systems.

Root Cause

Central IOCTL Dispatcher: All AFD IOCTLs are routed through a central dispatch routine (e.g., FUN_1c0001b10 in decompiled builds), which chooses the appropriate handler for each control code.

Uninitialized Pool Allocations: Handlers allocate nonpaged pool buffers for output (e.g., using ExAllocatePool3 or lookaside lists) but do not zero the buffer.

Partial Buffer Initialization: The handler writes a small header and the actual payload into the buffer, but leaves the rest (“slack space”) uninitialized.

Blind Copy-Out: The handler then copies the entire buffer (including uninitialized slack) back to user-mode, exposing stale kernel memory.

This pattern occurs both for large allocations (pool) and smaller ones (lookaside list), and also appears in handlers that use MDL-mapped buffers.

Reproduction Steps

PoC Code (see below): A simple user-mode program calls WSAIoctl() with SIO_ADDRESS_LIST_QUERY and a large output buffer.

Observe: The returned buffer contains the valid header and payload, followed by uninitialized bytes—0xCC in debug builds, but real, potentially sensitive data in retail builds.

Impact

KASLR Bypass: Kernel pointers may leak, helping attackers defeat address randomization.

Sensitive Data Disclosure: Exposed pool slack can contain credentials, tokens, or other private structures.

Privilege Escalation: When chained with another kernel bug (e.g., write-what-where), this leak can assist in full SYSTEM compromise.

Mitigation & Remediation

Temporary Workaround: Restrict or monitor unprivileged use of SIO_ADDRESS_LIST_QUERY.

Proper Fix: Zero all newly allocated output buffers before populating or copying them back to user-mode (e.g., use RtlZeroMemory() or ExAllocatePoolZero()).

Technical Details

Driver: afd.sys (Ancillary Function Driver for WinSock)

IOCTL Path: All output buffers allocated by handlers for socket queries (e.g., SIO_ADDRESS_LIST_QUERY) are not zeroed.

Observed On: Windows 11 Home (10.0.22631, Build 22631)

Conclusion

This is a classic case of uninitialized kernel pool memory being leaked to user-mode, which can have serious security implications. All kernel output buffers exposed to user-mode should be zeroed or carefully initialized before being copied out.

