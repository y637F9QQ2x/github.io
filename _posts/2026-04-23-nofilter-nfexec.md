---
layout: post
title: "Inside NOFILTER-NFEXEC: A Deep Dive into WFP Implementation and BOF OPSEC Engineering"
date: 2026-04-23 09:00:00 +0900
categories: [Offensive Security, Tool Development]
tags: [havoc-c2, bof-development, privilege-escalation, opsec]
description: "A detailed walkthrough of implementing the DEF CON 31 NoFilter WFP technique as an OPSEC-hardened Havoc C2 BOF, including indirect syscalls, return address spoofing, patchless AMSI/ETW bypass, and lessons learned from Havoc BOF development."
---

## Introduction

This post is a deep dive into [NOFILTER-NFEXEC](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC), a two-stage privilege escalation and command execution toolchain I built for [Havoc C2](https://github.com/HavocFramework/Havoc) as a BOF (Beacon Object File — a small, position-independent C object that runs inside the C2 agent’s process without spawning a new one).

The first stage, NOFILTER, implements a privilege escalation technique originally discovered and presented by **Ron Ben-Yizhak** ([@RonB_Y](https://twitter.com/RonB_Y)) at [DEF CON 31](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Ron%20Ben-Yizhak%20-%20NoFilter%20Abusing%20Windows%20Filtering%20Platform%20for%20privilege%20escalation.pdf) in August 2023. Ron is a security researcher currently at [SafeBreach](https://www.safebreach.com/) (formerly at Deep Instinct, where the NoFilter research was conducted). His work consistently focuses on finding novel abuse paths in Windows internals — beyond NoFilter, he presented [RPC-Racer](https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Ron%20Ben%20Yizhak%20-%20You%20snooze%20you%20lose%20RPC-Racer%20winning%20RPC%20endpoints%20against%20services.pdf) at DEF CON 33 (2025), demonstrating how unprivileged users can win race conditions against system services to hijack RPC (Remote Procedure Call — a mechanism that lets one process call functions in another process, even across the network) endpoints for local privilege escalation. He also discovered CVE-2025-49760, a Windows Storage Service spoofing vulnerability that allows NTLM credential extraction via RPC endpoint manipulation. His research is well worth following if you are interested in Windows privilege escalation techniques.

The NoFilter research demonstrated that the Windows Filtering Platform (WFP — a kernel-mode framework that Windows uses to inspect and filter network traffic) can be abused to duplicate tokens entirely within kernel space, bypassing the user-mode API calls that EDR (Endpoint Detection and Response — security software that monitors process behavior for malicious activity) products typically hook. The [original proof-of-concept](https://github.com/deepinstinct/NoFilter) was a standalone executable, and the [Deep Instinct blog post](https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation) provides an excellent technical breakdown of the WFP internals. Microsoft MSRC was notified and classified this behavior as by-design.

The second stage, NFEXEC, is my own design — a command execution framework that uses the stolen SYSTEM token to run native executables or PowerShell scripts, with a full OPSEC (operational security — measures taken to avoid detection during an engagement) stack including indirect syscalls (a technique where system calls are routed through instructions inside ntdll.dll rather than executed directly from the tool’s own memory, making call-stack analysis harder), return address spoofing, and patchless AMSI/ETW bypass.

This post covers three things. First, how the WFP technique works and the specific implementation decisions I made when porting it to a Havoc BOF. Second, the OPSEC engineering that went into NFEXEC, from PEB-based function resolution to hardware breakpoint AMSI bypass. Third, practical notes from Havoc C2 BOF development — implementation details that are best understood by reading the source code directly.

---

## Part 1: Background

### What Is Havoc C2?

[Havoc](https://github.com/HavocFramework/Havoc) is an open-source command-and-control framework. Its agent, called a Demon, supports BOF execution through a component called CoffeeLdr (a COFF loader that parses the object file, resolves symbols, and calls the `go()` entry point). Havoc provides a set of Beacon-compatible APIs (`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, etc.) and extends them with features like an `NtApi[]` table that automatically routes NT syscalls through indirect syscall stubs when the Demon’s `SysIndirect` setting is enabled.


### Handles, Tokens, and Privileges

Before diving into the technique, three Windows concepts need to be clear.

A **handle** is an integer value that a process uses to refer to a kernel object — a file, a process, a thread, a registry key, or an access token. The kernel maintains a per-process handle table that maps each handle number to the actual kernel object. When you call `NtOpenProcess`, the kernel creates an entry in your handle table pointing to the target process object and returns the handle number. Handles are process-local: handle `0x1A4` in Process A and handle `0x1A4` in Process B refer to completely different objects. To use another process's object, you must **duplicate** the handle — `NtDuplicateObject` copies the handle table entry from the source process into your own table, giving you a new handle number that points to the same underlying kernel object.

An **access token** is a kernel data structure that encodes a security identity: which user account owns the process, which groups the user belongs to, and which privileges are enabled. Every process has a **primary token** that defines its identity. Individual threads can additionally carry an **impersonation token** — a temporary override that makes that specific thread act as a different user. When a thread with an impersonation token accesses a file or opens a process, the kernel checks the impersonation token's permissions, not the process's primary token. This is the mechanism NOFILTER exploits: by attaching a SYSTEM impersonation token to the Demon's thread, all subsequent operations on that thread run with full SYSTEM authority.

A **privilege** is a system-wide permission that goes beyond file/object access. `SeDebugPrivilege`, for example, allows a process to open any other process on the system regardless of its security descriptor (a data structure attached to every Windows object that specifies which users and groups are allowed to access it) — normally, a process can only open processes running under the same user account. Administrator accounts have `SeDebugPrivilege` in their token, but it is **disabled** by default. It must be explicitly enabled with `RtlAdjustPrivilege` before it takes effect. NOFILTER needs this privilege to open the BFE service process and the target SYSTEM process.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/handle-token-concepts.svg" alt="Windows handles and tokens - foundational concepts" style="width:100%;height:auto;display:block">

### What Is the Windows Filtering Platform?

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/wfp-architecture.svg" alt="Windows Filtering Platform architecture - detailed overview" style="width:100%;height:auto;display:block">

The **Windows Filtering Platform (WFP)** is a set of APIs and kernel-mode services that Windows provides for inspecting and filtering network packets. Firewalls, antivirus software, and VPN clients all build on top of WFP. Internally, WFP is implemented primarily in `tcpip.sys`, the kernel driver responsible for the TCP/IP network stack. WFP exposes a device called `\Device\WfpAle` (Application Layer Enforcement) that user-mode services — particularly the **BFE (Base Filtering Engine)** service — communicate with through IOCTL calls (Input/Output Control — a mechanism for user-mode programs to send commands to kernel drivers).

The key insight from Ron Ben-Yizhak’s research is that certain WFP IOCTLs allow inserting and retrieving access tokens in a kernel-managed hash table. These IOCTLs exist for a legitimate purpose: WFP needs to associate network connections with the identity of the user who initiated them, so that per-user firewall rules can be applied. The BFE service uses IOCTL 0x128000 to register a process’s token in the WFP hash table, and IOCTL 0x124008 to retrieve it later. The critical detail is that `tcpip.sys` performs the token duplication internally using kernel-mode APIs — no user-mode `NtDuplicateToken` call is made. Because the duplication happens at the kernel level, it is invisible to user-mode EDR hooks on the standard token manipulation APIs like `NtDuplicateToken` and `DuplicateHandle`.

The diagram above shows how WFP components are connected. The numbered steps below explain the flow that the NoFilter technique exploits:

1. **Normal WFP clients** (firewalls, VPN software, antivirus) communicate with the BFE service through the standard WFP management API. This is the legitimate, intended use of the platform.
2. **BFE holds a handle** to the kernel device `\Device\WfpAle`. This handle is how BFE sends IOCTL commands to `tcpip.sys`. The security descriptor on `\Device\WfpAle` prevents other processes from opening new handles directly — only BFE is supposed to have access.
3. **The attacker’s BOF duplicates BFE’s handle** using `NtDuplicateObject`. This copies the WfpAle handle from BFE’s handle table into the Demon’s handle table. Now the BOF can send IOCTLs to `\Device\WfpAle` as if it were BFE.
4. **BOF sends IOCTL 0x128000** (Token Insert) to `\Device\WfpAle`, specifying the target process PID and token handle value. The kernel receives this command.
5. **tcpip.sys duplicates the token internally** within kernel-mode. It reads the token from the target process, creates a copy, and stores it in the WFP token hash table (`gAleMasterHashTable`). This duplication is entirely invisible to user-mode EDR hooks — no `NtDuplicateToken` is called in user-mode.
6. **BOF sends IOCTL 0x124008** (Token Query) with the LUID received from step 5. The kernel retrieves the duplicated token from the hash table.
7. **Token handle is returned** to the BOF in user-mode. The BOF now holds a handle to a SYSTEM token that was duplicated entirely within the kernel.

### What Is a BOF?

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/bof-explained.svg" alt="Beacon Object File - how BOFs work compared to traditional approach" style="width:100%;height:auto;display:block">

A **Beacon Object File (BOF)** is a compiled C object file (COFF format on Windows) that a C2 framework loads and executes directly inside the agent’s (called a “Demon” in Havoc) process.

The diagram above shows the Demon process’s memory layout during BOF execution. The numbered steps below explain the flow from start to finish:

1. **C2 server sends the .o file.** The compiled BOF (a COFF object file, typically a few KB) is transmitted from the Havoc server to the Demon agent over the encrypted C2 channel.
2. **CoffeeLdr parses the COFF headers.** CoffeeLdr reads the COFF section table (`.text` for code, `.data` for initialized variables), the symbol table (a list of function and variable names the BOF references), and the relocation entries (instructions for fixing up addresses).
3. **CoffeeLdr allocates memory and maps sections.** `VirtualAlloc` is called to allocate memory with read-write-execute (RWX) permissions. The `.text` and `.data` sections from the COFF file are copied into this allocation. **Note:** the `.bss` section (where zero-initialized globals would normally go) is **not** mapped by CoffeeLdr — this is the root cause of the .bss pitfall described in Part 5.
4. **CoffeeLdr resolves DFR symbols.** The symbol table contains entries like `__imp_NTDLL$NtOpenProcess`. CoffeeLdr splits this into the DLL name (`NTDLL`) and the function name (`NtOpenProcess`), then resolves the address. For NT functions, it first checks the NtApi[34] hash table — if the function matches, the call is routed through the indirect syscall stub instead of the normal ntdll export. For non-NT functions (like `MSVCRT$calloc`), it uses `GetProcAddress` to look up the address in the loaded DLL’s export table.
5. **CoffeeLdr performs relocations.** The code in `.text` contains placeholder addresses (since the compiler did not know where the code would be loaded). CoffeeLdr walks the relocation entries and patches each placeholder with the actual runtime address calculated in the previous step.
6. **CoffeeLdr calls `go(args, alen)`.** The entry point function is invoked as a direct function call on the Demon’s **existing thread**. No new process is created. No new thread is created. The BOF executes as if it were a regular function inside the Demon.
7. **BOF executes.** The BOF code calls Win32 APIs (resolved via DFR) and NT APIs (routed through the NtApi[] indirect syscall stub). Output is accumulated in a heap buffer via `BeaconOutput`.
8. **Cleanup.** When `go()` returns, CoffeeLdr frees the allocated RWX memory. The BOF code no longer exists in the process. Output is sent to the C2 server. Unlike traditional post-exploitation modules that spawn a new process, a BOF runs as a function call within the existing process — no new process creation, no new thread visible to the OS. This makes BOFs attractive from an OPSEC perspective but also imposes strict constraints: no C runtime library (all CRT functions must be called through Dynamic Function Resolution, or DFR — a convention where you declare `LIBRARY$Function` and the BOF loader resolves it at runtime), no static initialization, and careful memory management.


---

## Part 2: How NOFILTER Works

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/nofilter-nfexec-overview.svg" alt="NOFILTER-NFEXEC two-stage pipeline overview" style="width:100%;height:auto;display:block">

### The Two-Stage Pipeline

NOFILTER-NFEXEC operates in two stages. The operator runs `nofilter` to escalate to SYSTEM, then runs `nfexec <command>` to execute commands under that elevated context. The separation is deliberate — the token theft and command execution are independent concerns, and keeping them in separate BOFs means the operator can reuse the stolen token across multiple `nfexec` calls without re-running the escalation.

An important detail to understand is how the token persists between the two BOF executions. When NOFILTER attaches an impersonation token to the Demon’s thread via `NtSetInformationThread`, that token remains on the thread until explicitly reverted with `token revert`. Subsequent BOF executions (like `nfexec`) run on the same Demon thread, so they inherit the impersonation context automatically. NFEXEC’s `NtOpenThreadToken` retrieves this persisted token for use in process creation or PowerShell execution. This is why the two-stage design works without any shared state or IPC between the BOFs.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/token-persistence.svg" alt="Token persistence timeline across BOF calls" style="width:100%;height:auto;display:block">

### Stage 1: Kernel-Space Token Duplication

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/nofilter-kernel-flow.svg" alt="NOFILTER kernel-space token duplication flow" style="width:100%;height:auto;display:block">

NOFILTER implements Attack #1 from Ron Ben-Yizhak’s DEF CON 31 presentation. The flow has six phases:

**Phase 1 — Find the BFE service PID.** The BFE (Base Filtering Engine) service is the user-mode counterpart of WFP. It holds an open handle to the `\Device\WfpAle` device, which is needed to issue the IOCTLs. NOFILTER queries the Service Control Manager to find BFE’s process ID.

**Phase 2 — Find a SYSTEM target process.** We need a process running as SYSTEM that has a token handle with `TOKEN_DUPLICATE` access. NOFILTER defaults to `lsass.exe` (Local Security Authority Subsystem — the process responsible for enforcing the security policy on the system) and falls back to `services.exe` if lsass is not found.

**Phase 3 — Enable SeDebugPrivilege.** Administrator tokens include `SeDebugPrivilege` (a Windows privilege that allows opening any process on the system regardless of its security descriptor) but it is disabled by default. `RtlAdjustPrivilege` enables it so that `NtOpenProcess` will succeed on SYSTEM processes. The code also attempts thread-level adjustment as a fallback for impersonation contexts.

**Phase 4 — Scan the system handle table.** Windows maintains a global handle table that tracks every open handle across all processes. `NtQuerySystemInformation` with class 64 (`SystemHandleInformationEx`) dumps this entire table into a caller-supplied buffer. Each entry contains the owning process ID, the handle value, the granted access mask, and an object type index (a numeric identifier that distinguishes File handles from Token handles, Process handles, and so on). The returned buffer can be very large — a typical system has tens of thousands of open handles — so the code allocates progressively larger buffers (starting at 1MB, doubling up to 8 times) until the call succeeds. NOFILTER iterates through this table looking for two specific handles: the `\Device\WfpAle` File handle in the BFE process, and a Token handle in the SYSTEM target process.

An important implementation detail here is the **type index caching optimization**. The first time a File-type handle is identified (via `NtQueryObject(ObjectTypeInformation)`), its type index is cached in `file_type_idx`. For all subsequent handles, the code can skip the `NtQueryObject` call entirely and compare the type index directly — turning an O(n×syscall) operation into an O(n) integer comparison for the vast majority of handles. The same caching is applied for Token handles via `token_type_idx`. This reduces the handle scanning time from minutes to seconds on systems with large handle tables.

Another important implementation detail is the deadlock-safe handle scanning. The original NoFilter PoC used `NtQueryObject(ObjectNameInformation)` to identify handles — but this call can deadlock on named pipes, ALPC ports (Advanced Local Procedure Call — a high-performance IPC mechanism in Windows), and synchronous file objects. NOFILTER avoids this by first querying `ObjectTypeInformation` (which never deadlocks) to confirm a handle is of type “File” before querying its name. This was one of the early fixes I had to make when the BOF would occasionally hang indefinitely during handle enumeration.

**Phase 5 — Kernel IOCTLs.** With the WfpAle device handle duplicated into the BOF’s process, two IOCTLs are issued via `NtDeviceIoControlFile` (a kernel API that sends a control code and an input buffer to a device driver, and receives an output buffer back — think of it as a function call to a kernel driver, where the control code specifies which operation to perform):

- **IOCTL 0x128000** (Token Insert) — Takes a process ID and token handle value as input. The kernel (`tcpip.sys`) internally duplicates the token and stores it in WFP’s hash table, returning a LUID (Locally Unique Identifier — a 64-bit value that uniquely identifies the token within the hash table).
- **IOCTL 0x124008** (Token Query) — Takes the LUID and returns a **primary token** handle. The kernel internally calls `DuplicateToken` with `TOKEN_DUPLICATE` access hardcoded — this access right is not configurable by the caller.

The IOCTL input/output structures are straightforward:

- **IOCTL 0x128000 input**: `{ ULONG_PTR ProcessId; ULONG_PTR TokenHandle; }` — the PID of the process that owns the token, and the handle value (not a duplicated handle — just the raw numeric value from the target process’s handle table). As Ron Ben-Yizhak noted, any PID can be specified by the caller — one process can reference a token in a completely different process. The kernel attaches to the target process’s address space (each process has its own private view of memory — address `0x1000` in Process A and address `0x1000` in Process B refer to different physical memory; the kernel can temporarily “attach” to another process’s view to access its memory), duplicates the token, and inserts the copy into the WFP hash table.
- **IOCTL 0x128000 output**: `{ LUID TokenLuid; }` — the kernel-generated unique identifier for the stored token.
- **IOCTL 0x124008 input**: `{ LUID TokenLuid; }` — the LUID received from the insert call.
- **IOCTL 0x124008 output**: `{ ULONG_PTR TokenHandle; }` — a new handle in the calling process’s handle table, pointing to the duplicated token.

Note that these structures use **natural alignment** (no `#pragma pack`). Getting the alignment wrong would cause the kernel to read garbage from the wrong offsets, resulting in opaque `STATUS_*` error codes with no indication of what went wrong.

This is the core of the technique: the token duplication occurs entirely within kernel space. No user-mode `NtDuplicateToken` or `DuplicateHandle` call is made, so EDR products that hook these functions at the user-mode level do not see the operation.

**Phase 6 — Impersonate.** The retrieved token is duplicated as an impersonation token (using `NtDuplicateToken` with `TokenImpersonation` type and `SecurityImpersonation` level), and applied to the current thread via `NtSetInformationThread(ThreadImpersonationToken)`. The thread now runs as NT AUTHORITY\SYSTEM.

One subtle detail: the original token retrieved from the IOCTL is a primary token (the type associated with a process’s identity), but `NtSetInformationThread` requires an impersonation token (the type that can be attached to individual threads). Passing a primary token fails with `STATUS_BAD_TOKEN_TYPE`. This is why the extra `NtDuplicateToken` step is needed.

A natural question is: why not replace the entire process’s primary token instead of impersonating on a single thread? The answer is a Windows kernel restriction. `NtSetInformationProcess` with the `ProcessAccessToken` information class can only be called on a process that has **no running threads** — typically a process created with `CREATE_SUSPENDED` that has not yet been resumed. The Demon process is already running with active threads, so replacing its primary token is impossible. Thread impersonation via `NtSetInformationThread(ThreadImpersonationToken)` is the only mechanism Windows provides for changing the security context of an already-running process. This is not a limitation of the tool — it is a fundamental Windows design constraint.

There is an additional subtlety related to the access rights. Ron Ben-Yizhak’s research found that `tcpip.sys` hardcodes `TOKEN_DUPLICATE` as the desired access when it internally calls `DuplicateToken` during the query IOCTL (0x124008). This means the returned token handle only has `TOKEN_DUPLICATE` permission — not enough to directly use for impersonation or process creation. The `NtDuplicateToken` call in NOFILTER serves two purposes simultaneously: it converts the token type from Primary to Impersonation, AND it requests `TOKEN_ALL_ACCESS` (0xF01FF) on the new handle, giving it the full permissions needed for `NtSetInformationThread`.

Another subtle detail: after `BeaconUseToken()`, the token handle must not be closed. Havoc stores the raw handle internally for `token revert`. Closing it creates a dangling handle that causes issues on revert.

### OPSEC Properties of NOFILTER

All NT API calls in NOFILTER go through Havoc’s `NtApi[]` table, which means they automatically use indirect syscalls when the Demon’s `SysIndirect` setting is enabled. IOC (Indicator of Compromise — artifacts that security analysts look for to identify malicious activity) strings like `\Device\WfpAle`, `BFE`, `lsass.exe`, `services.exe`, `File`, and `Token` are XOR-encoded with key `0x37` and decoded on the stack at runtime. After use, the decoded strings are zeroed with `memset` to prevent recovery from memory dumps. The COFF symbol table has 20 symbols sanitized via `objcopy` to remove identifiable function names. Error messages use opaque codes (`E01`–`E11`, `S1`–`S9`) with no descriptive text in the binary — the mapping is only in source code comments, visible only to the operator.

---

## Part 3: How NFEXEC Works

NFEXEC has two execution modes, selected automatically based on the command:

### Auto-Detection

The Python handler (`nfexec.py`) maintains a list of approximately 100 native Windows commands — `whoami`, `ipconfig`, `net`, `sc`, `reg`, `netstat`, `tasklist`, `systeminfo`, and others. When the operator types `nfexec whoami /priv`, the handler recognizes `whoami` as a native command and routes to exec mode. Anything not in the list — `Get-Process`, `dir`, `[Environment]::UserName` — goes to PowerShell mode. The operator can override with `-exec` or `-ps` flags.

### Exec Mode (mode=1)

Exec mode launches a native executable under the SYSTEM token. The flow is:

1. **NtOpenThreadToken** — Opens the current thread’s impersonation token (set by NOFILTER). This is an indirect syscall via Havoc’s NtApi[] table.
2. **NtDuplicateToken** — Duplicates it as a primary token (`TokenPrimary`), because `CreateProcessWithTokenW` (a Windows API that creates a new process running under a specified token) requires a primary token. Also indirect syscall.
3. **CreateProcessWithTokenW** — Creates the process. This function is resolved at runtime via PEB walk (traversing the Process Environment Block — a data structure in every Windows process that contains pointers to all loaded DLLs) and FNV-1a hash lookup, eliminating the `ADVAPI32$CreateProcessWithTokenW` DFR import that would appear as a symbol in the COFF file. The process is created with `CREATE_NO_WINDOW` to avoid a visible console window.
4. **Pipe capture** — Output is captured via an anonymous pipe. The pipe buffer is set to 1MB (rather than the default 4KB) to prevent deadlock — more on this in Part 5.
5. **OEM to UTF-8 conversion** — Native Windows commands output text in the system’s OEM codepage (codepage — a mapping between byte values and characters; for example, Japanese Windows uses Shift-JIS as its OEM codepage, English Windows uses CP437). Havoc’s console expects UTF-8. Without conversion, non-ASCII output appears as mojibake (garbled text). The conversion goes OEM → UTF-16 → UTF-8.

### PowerShell Mode (mode=0)

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/ps-mode-flow.svg" alt="NFEXEC PowerShell mode - inline CLR hosting pipeline" style="width:100%;height:auto;display:block">

PowerShell mode uses inline CLR (Common Language Runtime — the .NET execution engine) hosting to run PowerShell within the BOF thread, without spawning `powershell.exe` or `pwsh.exe`. The reason for this complexity (rather than simply calling `CreateProcessWithTokenW` with `powershell.exe` as the executable) is OPSEC: spawning `powershell.exe` creates a new process that EDR immediately subjects to enhanced monitoring — script block logging, AMSI scanning, and command-line argument inspection. By hosting the CLR inside the existing Demon process, the PowerShell engine runs as a library call within an already-running process, which is significantly harder for EDR to detect. The tradeoff is implementation complexity: inline CLR hosting requires manually walking COM vtables, managing AppDomains, and handling the many quirks of the .NET runtime. The flow is:

1. **Syscall infrastructure init** — `ScInit()` performs a PEB walk to find `ntdll.dll`’s base address, resolves the SSN (System Service Number — the index that identifies a specific kernel syscall; for example, `NtDelayExecution` might be SSN 0x34 on a given Windows build) via Halo’s Gate (a technique that, if the target function’s prologue has been overwritten by an EDR hook, walks neighboring syscall stubs at 32-byte intervals (in ntdll, each Nt* function’s stub is exactly 32 bytes long and they are laid out consecutively, so moving 32 bytes forward or backward lands exactly at the next or previous function’s stub) to find an unhooked one. Once an unhooked neighbor is found, the target’s SSN is calculated by simple arithmetic: if the neighbor 3 positions away has SSN 0x50, then the target’s SSN is 0x50 ± 3), and locates a `syscall;ret` gadget (`0F 05 C3` — these are raw CPU opcodes: `0F 05` is the machine code for the `syscall` instruction, and `C3` is `ret`) in ntdll’s `.text` section (the section of the DLL that contains executable code).
2. **HWBP setup** — After CLR `Start()` loads `amsi.dll`, hardware breakpoints (explained in Part 4) are set on `AmsiScanBuffer` and `EtwEventWrite` — before any AMSI scanning occurs.
3. **CLR hosting** — `CLRCreateInstance` → `GetRuntime("v4.0.30319")` → `IsLoadable` check → `GetInterface(ICorRuntimeHost)` → `Start()`. A randomized AppDomain name (generated via LCG with the pipe handle as seed) is used for each execution to avoid IOC patterns.
4. **Assembly loading** — A pre-compiled .NET assembly (`PowershellRunner.h`, from the [HavocFramework/Modules](https://github.com/HavocFramework/Modules) PowerPick project, licensed under GPLv3) is loaded via `AppDomain.Load_3`. Its entry point is invoked with the PowerShell script as a BSTR argument.
5. **Token forwarding** — CLR Runspace threads do not inherit the BOF thread’s impersonation token. To ensure PowerShell runs as SYSTEM, the thread token handle is passed into the PowerShell wrapper script, which calls `WindowsIdentity.Impersonate()` inside the Runspace thread.
6. **Pipe output capture** — PowerShell’s `Console.Out` cannot be used for output because the Demon is a GUI process (not a console process), so `Console.Out` points to a `NullStreamWriter` — anything written to it is silently discarded. Instead, the BOF creates an anonymous pipe, passes the write handle as a raw `IntPtr` into the PowerShell script, and the script constructs a `FileStream` → `StreamWriter` chain from it. This is also why `Console.SetOut()` is avoided: it affects all threads in the process, which could interfere with other Demon operations. After `Invoke_3` returns, the BOF waits 100ms (via `NtDelayExecution` with return address spoofing) and reads the pipe.

---

## Part 4: OPSEC Engineering

### Indirect Syscall Infrastructure

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/indirect-syscall.svg" alt="Indirect syscall infrastructure with return address spoofing" style="width:100%;height:auto;display:block">

To understand indirect syscalls, it helps to know what a syscall is at the CPU level. User-mode code (applications, BOFs, even the Demon process) runs in a restricted CPU mode that cannot directly access kernel memory or call kernel functions. To request a kernel operation — opening a file, querying process information, duplicating a token — user-mode code must execute the `syscall` CPU instruction, which switches the CPU from user-mode to kernel-mode. The kernel looks at the value in the `EAX` register (the SSN — System Service Number) to determine which kernel function to run.

In normal operation, applications never execute `syscall` directly. Instead, they call functions in `ntdll.dll` (a DLL — Dynamic Link Library — is a shared code file that Windows loads into processes). `ntdll.dll` specifically is a thin wrapper library that the OS loads into every process. Each `ntdll` function (like `NtOpenProcess`, `NtDuplicateToken`) is a tiny stub that does three things: put the SSN in `EAX` (a register — a tiny, fast storage slot built directly into the CPU; the CPU has about 16 general-purpose registers, each holding one 64-bit value, and specific registers have specific roles), put the first argument in `R10`, and execute `syscall`. EDR products exploit this by **hooking** these stubs — overwriting the first few bytes of each function with a `JMP` instruction that redirects execution to the EDR’s own monitoring code. The EDR inspects the arguments, logs the call, and then either allows or blocks it.

Indirect syscalls bypass this by executing the `syscall` instruction from a different location — not from the hooked stub, but from elsewhere in ntdll’s code — so the EDR’s `JMP` hook is never hit.

NFEXEC uses two layers of indirect syscalls:

**Layer 1: Havoc NtApi[] auto-routing.** Six NT functions (`NtOpenThreadToken`, `NtDuplicateToken`, `NtWaitForSingleObject`, `NtGetContextThread`, `NtSetContextThread`, `NtClose`) are declared via DFR as `NTDLL$NtXxx`. Havoc’s CoffeeLdr detects these declarations, matches them against its `NtApi[]` hash table (34 pre-registered functions in `ObjectApi.c` lines 91–126), and routes them through its `SysNtXxx` indirect syscall stub automatically.

**Layer 2: Manual PEB-based resolution.** Functions NOT in Havoc’s `NtApi[]` table — `NtDelayExecution`, `LdrLoadDll`, `RtlAddVectoredExceptionHandler`, `RtlRemoveVectoredExceptionHandler` — are resolved entirely at runtime via PEB walk and PE (Portable Executable — the binary file format that Windows uses for `.exe` and `.dll` files) export table parsing. No DFR, no IAT entries. Function names never appear as strings in the binary; they are resolved by FNV-1a hash constants (for example, `NtDelayExecution` is `0xD856E554`).

For the manually resolved NT syscalls (currently just `NtDelayExecution`), NFEXEC builds its own indirect syscall stub:

1. **PEB Walk** — `GS:0x60` → PEB → Ldr → `InMemoryOrderModuleList` → second entry = ntdll base. Zero API calls.
2. **FNV-1a hash resolution** — Walk ntdll’s PE export table, hash each export name, compare against the target hash.
3. **SSN extraction (Halo’s Gate)** — Read the function prologue. Unhooked pattern: `4C 8B D1 B8 XX XX 00 00` (`mov r10, rcx; mov eax, SSN`). If hooked (EDR has overwritten the prologue with a JMP detour), scan neighboring stubs at ±32-byte intervals until an unhooked one is found, then calculate the target SSN by offset.
4. **Gadget search** — Scan ntdll’s executable code for the byte sequence `0F 05 C3` (the `syscall` instruction immediately followed by `ret`). This three-byte sequence is the indirect syscall target. This is the indirect syscall target — the actual `syscall` instruction executes from ntdll’s code, not from the BOF’s memory.

### Return Address Spoofing

To follow the return address spoofing mechanism, a brief recap of how function calls work at the CPU level is needed. When the CPU executes a `CALL` instruction, it pushes the address of the instruction immediately after the `CALL` onto the **stack** (a region of memory that grows downward, tracked by the `RSP` register — the Register Stack Pointer, which always points to the top of the stack). This pushed address is the **return address** — where execution should continue after the called function finishes. When the called function executes `RET`, the CPU pops the value at `[RSP]` (the top of the stack), loads it into `RIP` (the Register Instruction Pointer — which controls what the CPU executes next), and continues from there. EDR stack-walking works by reading these return addresses from the stack to reconstruct the chain of callers — if a return address points to memory that does not belong to any known DLL, the call is flagged as suspicious.

The `ScStub` function implements return address spoofing for the manually resolved syscalls. During a syscall, EDR stack-walking examines `[RSP]` (the return address on the stack) to identify which code triggered the syscall. Without spoofing, `[RSP]` points to the BOF’s memory — a suspicious, non-module-backed address. With spoofing, `ScStub` pushes an additional stack frame:

- `sub rsp, 8` — Makes room for one extra return address.
- `[RSP]` = ntdll `ret` gadget (the `C3` byte at offset +2 from the `syscall;ret` gadget).
- `[RSP+8]` = real BOF caller return address.

The return chain becomes: `syscall;ret` → pops ntdll `ret` gadget → executes `ret` in ntdll → pops real caller address → returns to BOF. EDR sees the stack pointing back into ntdll, which looks like a legitimate call.

There is a limitation: `sub rsp, 8` shifts all stack-based arguments by 8 bytes. This is safe for functions with 4 or fewer arguments (which use registers `RCX`, `RDX`, `R8`, `R9` under the x64 calling convention — these arguments live in registers, not on the stack, so shifting the stack does not affect them). For functions with 5+ arguments, the stack offset would corrupt argument passing. In NFEXEC, only `NtDelayExecution` (2 arguments) uses this stub, so the limitation does not apply.

### Patchless AMSI and ETW Bypass

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/hwbp-amsi-bypass.svg" alt="HWBP patchless AMSI and ETW bypass mechanism" style="width:100%;height:auto;display:block">

Traditional AMSI/ETW bypasses patch the target function’s code in memory — for example, writing `xor eax, eax; ret` (return zero immediately) at the start of `AmsiScanBuffer`. This works but leaves modified `.text` section pages that integrity scanners (software that compares in-memory code against the on-disk original to detect tampering) can detect.

NFEXEC uses **hardware breakpoints (HWBP)** — a CPU feature where debug registers (`DR0`–`DR3`) can be programmed with addresses that trigger an `EXCEPTION_SINGLE_STEP` exception when executed. No memory is modified.

**AMSI bypass (DR0):** When `AmsiScanBuffer` (a function that AMSI calls to scan PowerShell scripts, .NET assemblies, and other content for malicious patterns) is called by the CLR, the hardware breakpoint fires. When this happens, the CPU immediately stops executing, saves the entire register state (every general-purpose register, the instruction pointer `RIP`, the stack pointer `RSP`, the flags register, and the debug registers themselves) into a `CONTEXT` structure, and calls registered exception handlers. The VEH (Vectored Exception Handler — a mechanism that lets code register a callback that receives this `CONTEXT` structure before the standard exception handling chain runs) inspects the stack, sets `*result = AMSI_RESULT_CLEAN` (writing 0 to the result pointer, which tells the caller the scan found nothing malicious), sets `RAX = S_OK` (0), and sets `RIP` to the return address (popped from `[RSP]`), effectively making the CPU skip the entire function body and resume at the caller as if the function had already returned. The function never executes. The DR0 enable bit is re-armed in the handler because some CPUs clear it after a single-step exception.

An important OPSEC detail: the VEH does NOT return `E_INVALIDARG` as some public implementations do. Returning `E_INVALIDARG` is itself a known IOC that EDR products flag. Returning `S_OK` with `AMSI_RESULT_CLEAN` makes the call appear as a normal scan that found nothing.

**ETW bypass (DR1):** The same mechanism is applied to `EtwEventWrite` (the function that .NET and PowerShell use to emit telemetry events that EDR can consume). The VEH sets `RAX = 0` and skips the function, suppressing all ETW events from the CLR.

Both target functions are resolved via PEB walk and PE export table hash lookup — `AmsiScanBuffer` from `amsi.dll` (loaded via `LdrLoadDll`, itself resolved from the PEB), and `EtwEventWrite` from ntdll. The bypass setup happens **after** CLR `Start()`, not before — because `amsi.dll` is loaded during CLR initialization, and the breakpoint address cannot be resolved until the DLL is in memory. This is safe because `Start()` itself does not trigger AMSI scanning; scanning only occurs later during `CreateDomain`, assembly loading (`Load_3`), and script invocation (`Invoke_3`). By the time any scanning happens, the hardware breakpoints are already in place.

After execution, all debug registers are cleared and the VEH is removed. No artifacts remain.

### Additional OPSEC Measures

**Zero ADVAPI32 imports in NFEXEC.** `CreateProcessWithTokenW` is resolved at runtime via PEB walk + FNV-1a hash. This eliminates the `__imp_ADVAPI32$CreateProcessWithTokenW` symbol from the COFF file, which would be an obvious indicator in the object’s symbol table (a list of function and variable names embedded in the compiled binary — security analysts can read these names with tools like `strings` or `objdump` to identify what the binary does).

**XOR-encoded function names.** Strings like `amsi.dll` are XOR-encoded in the binary. The sentinel-terminated encoding (`d[i] ^= 0x41` until `d[i] == KEY`) means the decoder is a simple loop with no separate length constant. Decoded strings are zeroed on the stack after use via `memset`.

**FNV-1a hash-only resolution.** For PEB-resolved functions, no function name strings exist in the binary at all. Each function is identified by a 32-bit hash constant (`H_AmsiScanBuffer = 0xF76951A4`, etc.). Even with the binary in hand, an analyst would need to brute-force or rainbow-table the hashes to determine which functions are being called.

**Symbol sanitization.** `objcopy --strip-symbol` removes 34 symbols from the NFEXEC COFF file (20 from NOFILTER). Global variable names like `g_bp0` and `g_bp1` are already opaque — they were originally named `g_pAmsiScanBuffer` and `g_pEtwEventWrite`, which would be instantly identifiable.

**Memory scrubbing.** `ScScrub()` zeroes the ntdll base address, gadget pointers, and last SSN from globals at the end of `go()`. `STARTUPINFO`, command line buffers (both narrow and wide), and pipe output buffers are all zeroed before being freed. This makes post-execution memory forensics significantly harder.

**No .bss section.** All global and static variables use `__attribute__((section(".data")))` to force placement in the `.data` section. The reason is explained in Part 5.

---

## Part 5: Lessons from Havoc BOF Development

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/havoc-bof-pitfalls.svg" alt="Havoc C2 BOF development pitfalls and fixes" style="width:100%;height:auto;display:block">

Havoc is an actively developed open-source framework, and like any large project, some implementation details are not yet reflected in the documentation. Below are the behaviors I encountered while building NOFILTER-NFEXEC, along with the solutions I used. All of these were resolved by reading Havoc’s source code directly, which is one of the great advantages of working with an open-source framework.

### BeaconFormatAlloc Argument Order

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-beaconformat.svg" alt="BeaconFormatAlloc argument order - problem and solution" style="width:100%;height:auto;display:block">


The `BeaconFormat*` family of functions — `BeaconFormatAlloc`, `BeaconFormatPrintf`, `BeaconFormatToString`, and others — is designed for building formatted output buffers. However, `BeaconFormatAlloc` in `ObjectApi.c` (line 348) calls `LocalAlloc(maxsz, 1)` with the arguments in a different order than `LocalAlloc` expects. `LocalAlloc` takes `(flags, size)`, but the current implementation passes `(size, 1)`, resulting in a 1-byte allocation regardless of the requested size. Functions that depend on `BeaconFormatAlloc` (`BeaconFormatPrintf`, `BeaconFormatAppend`, `BeaconFormatToString`, `BeaconFormatInt`, etc.) are affected by this.

To understand why this matters: in a BOF, you cannot use `printf` or `sprintf` directly because the C runtime is not available. You need Havoc’s provided functions to build output text and send it back to the operator’s console. `BeaconFormatAlloc` is supposed to allocate a buffer for this purpose, and `BeaconFormatPrintf` is supposed to write formatted text into it — similar to how you’d use `malloc` + `sprintf` in normal C. But because the allocation always produces a 1-byte buffer, any formatted text immediately writes past the end of the buffer (a buffer overflow), corrupting adjacent memory. The symptoms range from garbled output to a silent Demon crash with no error message.

The fix is straightforward: avoid the entire `BeaconFormat*` API. Use `MSVCRT$calloc` (the C runtime’s memory allocation function, called via DFR) to allocate a buffer, `MSVCRT$vsnprintf` to format text into it, and `BeaconOutput` (which works correctly as a standalone function, as confirmed in `ObjectApi.c` line 305) for a single output call at the end. This is what NOFILTER does: `out_init()` allocates an 8KB buffer at the start, `out_printf()` appends formatted text to it throughout execution, and `out_flush()` sends it all in one `BeaconOutput` call at the end.

### The .bss Section Behavior

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-bss.svg" alt=".bss section behavior - problem and solution" style="width:100%;height:auto;display:block">


To understand this pitfall, a brief explanation of how compiled C code is organized is needed. When you compile a C file, the compiler divides the data into sections. Code (the actual CPU instructions) goes into the `.text` section. Variables that are initialized with a value (like `int x = 42;`) go into the `.data` section. Variables that are initialized to zero or left uninitialized (like `int y = 0;` or `static int z;`) go into the `.bss` section. The `.bss` section is special: it does not take up space in the file, because the OS is expected to allocate zero-filled memory for it when the program starts. This optimization saves file size.

CoffeeLdr, Havoc’s COFF loader (the component that reads the compiled BOF file and sets up its memory), does not process the `.bss` section. In C, global and static variables initialized to zero (or left uninitialized) are placed in `.bss` by default. Since CoffeeLdr does not map this section, any access to a `.bss` variable hits unmapped memory and results in an access violation — the Demon exits without an error message, which makes the root cause difficult to identify.

The solution is to force every global/static variable into `.data` (the section of a compiled binary that holds initialized variables — as opposed to `.bss`, which holds uninitialized ones) by giving it a non-zero initializer and using the section attribute:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">__attribute__((section(".data"))) static char *g_ob = (char*)(ULONG_PTR)1;</pre></div>

For pointer variables where you would normally initialize to `NULL` (which is zero), use a sentinel value (a special marker value that means “not yet initialized” — distinct from the actual data the variable will hold) like `(PVOID)1`. The code must then check for the sentinel before dereferencing. After building, verify with `objdump -h` that `.bss Size=00000000`.

### Pipe Buffer Sizing

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-pipe.svg" alt="Pipe buffer sizing - deadlock prevention" style="width:100%;height:auto;display:block">


This was one of the most time-consuming bugs to track down, because the symptom — the Demon simply stops responding with no error message — gives no indication of what went wrong. There is no crash, no stack trace, no log entry. The operator sees the command hang forever. When running commands that produce more than 4KB of output (such as `ipconfig /all` on a system with multiple network adapters), the Demon would hang indefinitely. No crash, no error — just silence.

A **pipe** is a communication channel between two processes (or between a process and itself). One end writes data, the other end reads it. Think of it like a tube: data goes in one end and comes out the other. The pipe has a fixed-size internal buffer — if the writer fills the buffer and the reader hasn’t consumed any data, the writer blocks (pauses) until the reader drains some data.

The root cause is a classic pipe deadlock. `CreatePipe` with a buffer size of `0` defaults to 4KB. In exec mode, the BOF calls `NtWaitForSingleObject` to wait for the child process to exit, then reads the pipe. But if the child’s output exceeds 4KB, the child’s `WriteFile` blocks because the pipe buffer is full. The BOF is blocked waiting for the child to exit. The child is blocked waiting for the pipe to drain. Neither can proceed.

In PowerShell mode, the same problem manifests differently: `Invoke_3` (the COM method that runs the PowerShell script) blocks the BOF thread. If the PowerShell wrapper’s `$_w.Write()` fills the pipe buffer, `WriteFile` blocks inside the Runspace thread, and `Invoke_3` never returns.

The fix is to specify a 1MB pipe buffer: `CreatePipe(&hR, &hW, &sa, 1048576)`. This is large enough for any practical command output without wasting significant memory.

### OEM Codepage and Mojibake

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-oem.svg" alt="OEM codepage conversion - problem and solution" style="width:100%;height:auto;display:block">


This behavior only appears on non-English Windows systems, which is why many developers never encounter it during testing. On non-English Windows systems, native executables like `ipconfig` and `systeminfo` produce output in the system’s OEM codepage — Shift-JIS on Japanese Windows, CP437 on English Windows, and so on. Havoc’s operator console expects UTF-8. Without conversion, non-ASCII characters in the output appear as mojibake.

The fix requires a two-step conversion: OEM codepage → UTF-16 (via `MultiByteToWideChar` with `CP_OEMCP`), then UTF-16 → UTF-8 (via `WideCharToMultiByte` with `CP_UTF8`). There is no direct OEM-to-UTF-8 conversion in the Windows API.

### COM Vtable Slot Counting

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-vtable.svg" alt="COM vtable slot counting - problem and solution" style="width:100%;height:auto;display:block">


This section requires understanding one concept: how COM method calls work. In normal C code, you call a function by name: `DoSomething()`. But COM interfaces use a **vtable** — an array of function pointers, where each function is identified by its position (index) in the array rather than by name. To call `Load_3` on an `AppDomain` interface, the code looks up position 45 in the vtable and calls whatever function pointer is stored there. If you count wrong and look up position 44 instead, you call a completely different function — the CPU has no way to know you made a mistake, it just calls whatever is at that address, which almost always causes an immediate crash.

Inline CLR hosting requires calling methods on COM (Component Object Model — a Microsoft standard for binary-level interoperability between software components; the .NET runtime exposes its functionality through COM interfaces) interfaces (`ICLRMetaHost`, `ICLRRuntimeInfo`, `ICorRuntimeHost`, `AppDomain`, `Assembly`, `MethodInfo`) through vtable pointers (a vtable is a table of function pointers that C++ and COM use to implement polymorphism — calling the wrong slot means calling the wrong function). Getting the slot number wrong means calling the wrong method — which usually means an immediate crash with no useful error information.

The correct counts, verified against the actual COM interfaces:

- **AppDomain**: 3 (IUnknown) + 4 (IDispatch) + 4 + 2 + 1 + 14 (event handlers — **not 10**, the 7 event pairs each have add/remove = 14 slots) + 9 + 6 + 2 = 45 → `Load_3` is slot 45 (zero-indexed)
- **Assembly**: 3 + 4 + 4 + 5 = 16 → `EntryPoint` is slot 16
- **MethodInfo**: 3 + 4 + 4 + 4 + 3 + 1 + 4 + 1 + 4 + 4 + 4 + 1 = 37 → `Invoke_3` is slot 37

The most common mistake is the AppDomain event handler count. There are 7 events (`DomainUnload`, `AssemblyLoad`, `ProcessExit`, `TypeResolve`, `ResourceResolve`, `AssemblyResolve`, `UnhandledException`), and each has both `add_` and `remove_` methods, for a total of 14 slots — not 10 as you might count if you only consider the event names.

### RegisterCommand Signature

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-registercommand.svg" alt="RegisterCommand signature" style="width:100%;height:auto;display:block">


The `RegisterCommand` function takes 7 arguments, with the 5th being an integer. Note that some older documentation may reference 8 arguments with the 5th as a string, but the current implementation uses this signature:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">PYTHON</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">RegisterCommand(callback, "", "nfexec", "Execute command as SYSTEM", 0, "nfexec &lt;command&gt;", "nfexec whoami")</pre></div>

Using 8 arguments or passing a string as the 5th argument will not produce an obvious error — the command registers but may behave incorrectly in subtle ways.

### __file__ in Havoc’s Embedded Python

Havoc’s embedded Python environment does not set the `__file__` variable, which is normally defined by the standard Python interpreter. Using it in a script (for example, to resolve the path to a BOF file relative to the script’s location) raises a `NameError`. The solution is to use a configuration variable or hardcode the BOF path based on the extension’s known install location.

### ConsoleWrite Output Behavior

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-consolewrite.svg" alt="ConsoleWrite output behavior" style="width:100%;height:auto;display:block">


`demon.ConsoleWrite(type, msg)` appears to support multiple calls per command handler, but only the last call’s output is actually displayed. If you call `ConsoleWrite` three times with different messages, only the third one appears. For multi-line output, combine everything into a single call, or use the BeaconOutput echo technique (send text as mode=2 from the Python handler, and have the BOF call `BeaconOutput(CALLBACK_OUTPUT, data, dataLen)` which preserves newlines).

### Preventing Garbage Collection of GUI Callbacks

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-gc.svg" alt="GUI callback GC prevention" style="width:100%;height:auto;display:block">


When using Havoc’s GUI widget API (`havocui.Widget`), callback closures (a closure is an inner function that captures variables from its enclosing scope — in Python, `def cb(): ...` defined inside another function is a closure) passed to `addButton` and `addCheckbox` need to be explicitly kept alive by the caller. Without an explicit reference, Python’s garbage collector may collect the closure, leaving a dangling pointer (a pointer that still refers to memory that has already been freed — using it causes a crash or worse) in the C++ lambda. The next button click dereferences freed memory and crashes with a segfault.

The practical impact: you write a GUI extension for Havoc, add a button that runs a BOF. It works perfectly the first time. But after a few minutes of idle time (during which Python’s garbage collector runs), clicking the same button crashes the entire Havoc client with a segfault. The crash has no stack trace pointing to your code — it happens inside Qt’s event loop, making it extremely difficult to diagnose.

The fix is to keep a module-level list that holds references to all callback closures:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">PYTHON</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">_prevent_gc = []&#10;&#10;def _make_cb(name):&#10;    def cb():&#10;        # handler logic&#10;        pass&#10;    _prevent_gc.append(cb)  # prevent GC&#10;    return cb</pre></div>

### The NtQueryObject Deadlock

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-ntqueryobject.svg" alt="NtQueryObject deadlock-safe scanning" style="width:100%;height:auto;display:block">


This is not a Havoc-specific issue, but it is worth mentioning because it caused the BOF to hang during development. `NtQueryObject` with `ObjectNameInformation` can deadlock when called on certain handle types — particularly named pipes, ALPC ports, and synchronous file objects. The deadlock happens inside the kernel, so the BOF thread hangs indefinitely with no way to recover.

The solution used in NOFILTER’s handle scanning is to always query `ObjectTypeInformation` first (which never deadlocks), confirm the handle type is “File”, and only then query `ObjectNameInformation` on confirmed File handles.

### DFR Declaration Rules

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/lesson-dfr.svg" alt="DFR declaration decorator rules" style="width:100%;height:auto;display:block">


Every Win32 API call in a BOF must use Dynamic Function Resolution (DFR) — declaring the function as `LIBRARY$Function`. But the function signature decorations must be exact, or the calling convention will be wrong and the stack will be silently corrupted. The three key decorators are:

- `DECLSPEC_IMPORT` — Required on every DFR declaration. Without it, the linker (the tool that combines compiled code and resolves external references into a final binary) treats the symbol as a local function rather than an import.
- `WINAPI` (= `__stdcall`) — Used for almost all Win32 and NT API functions. The callee cleans the stack.
- `__cdecl` — Used for C runtime functions (`MSVCRT$vsnprintf`, `MSVCRT$calloc`, etc.). The caller cleans the stack.

For example, this is a correct DFR declaration for an NT API function:

`DECLSPEC_IMPORT LONG WINAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, PVOID, PVOID);`

And this is correct for a C runtime function (note `__cdecl` instead of `WINAPI`):

`DECLSPEC_IMPORT void * __cdecl MSVCRT$calloc(size_t, size_t);`

Using `WINAPI` where `__cdecl` is needed (or vice versa) does not produce a compiler error — the code compiles and links successfully. But at runtime, the stack is offset by the number of arguments × 8 bytes, causing a crash that may not occur until much later in the execution flow, making it extremely difficult to debug.

The DLL name in the DFR declaration must also be exact. For example, `InetNtopW` lives in `WS2_32`, not `WSOCK32`. Using `WSOCK32$InetNtopW` compiles and links without error, but at runtime the symbol resolution fails and the Demon crashes — with no error message indicating which symbol failed.

### The NtApi[] Table: What Gets Indirect Syscall and What Does Not

Havoc’s CoffeeLdr maintains a hardcoded table of 34 NT API functions in `ObjectApi.c` (lines 91–126) that are eligible for automatic indirect syscall routing. When a BOF declares `NTDLL$NtXxx` via DFR, CoffeeLdr hashes the function name and checks it against this table. If it matches, the call is routed through Havoc’s `SysNtXxx` indirect syscall stub. If it does not match, the call goes through the normal ntdll export — a direct call that EDR can hook.

The 34 functions in the table are: `NtOpenThread`, `NtOpenProcess`, `NtTerminateProcess`, `NtOpenThreadToken`, `NtOpenProcessToken`, `NtDuplicateToken`, `NtQueueApcThread`, `NtSuspendThread`, `NtResumeThread`, `NtCreateEvent`, `NtCreateThreadEx`, `NtDuplicateObject`, `NtGetContextThread`, `NtSetContextThread`, `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtWaitForSingleObject`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtFreeVirtualMemory`, `NtUnmapViewOfSection`, `NtProtectVirtualMemory`, `NtReadVirtualMemory`, `NtTerminateThread`, `NtAlertResumeThread`, `NtSignalAndWaitForSingleObject`, `NtQueryVirtualMemory`, `NtQueryInformationToken`, `NtQueryInformationThread`, `NtQueryObject`, `NtClose`, `NtSetInformationThread`, `NtSetInformationVirtualMemory`, and `NtGetNextThread`.

Functions **not** in this table — notably `NtDeviceIoControlFile` (used for the WFP IOCTLs), `NtOpenKey`, `NtQueryValueKey`, `NtDelayExecution`, and `NtQuerySystemTime` — will go through normal ntdll exports even when declared as `NTDLL$NtXxx`. This is why NFEXEC implements its own PEB-based indirect syscall infrastructure for `NtDelayExecution`: the Havoc NtApi[] table does not cover it.

### CLR Loading Is Irreversible

Once the CLR is loaded into a process via `CLRCreateInstance` + `Start()`, it cannot be unloaded — it remains in the process until the process exits. Individual AppDomains can be unloaded (and NFEXEC does this after each execution via `UnloadDomain`), but the CLR runtime itself stays resident. This means the first `nfexec` PowerShell command permanently loads the CLR into the Demon process. This is a standard tradeoff that all inline CLR hosting tools accept.

### CommandLineToArgvW Must Never Be Used for Script Passing

Windows’s `CommandLineToArgvW` function parses command-line strings according to the C runtime’s argument splitting rules, which mangle quotation marks and backslashes. PowerShell scripts frequently contain both. Passing a script through `CommandLineToArgvW` will silently corrupt the script text — closing quotes get removed, backslash-quote sequences get transformed, and the resulting script may be syntactically valid but semantically different from the original.

NFEXEC avoids this entirely by using `Packer.addstr()` (Python) → `BeaconDataExtract()` (BOF) to transmit the raw script bytes, then `MSVCRT$memcpy` to concatenate the prefix/suffix wrappers, and `SysAllocString` to convert the result to a BSTR for the CLR. The script text passes through the entire pipeline without any argument parsing or quote processing.

### The Packer and BeaconData Protocol

Havoc’s Python-side `Packer` class (available globally, no import needed) serializes arguments for BOF consumption. `Packer.getbuffer()` prepends a 4-byte little-endian size header (`pack("<L", size)`) to the data. On the BOF side, `BeaconDataParse` expects this header and automatically skips it. The `datap` structure used by `BeaconDataParse` must exactly match Havoc’s internal layout: `{ char *original; char *buffer; int length; int size; }`. Ensuring this structure matches is important for correct data extraction.

### Build Verification Checklist

After compiling a BOF with `x86_64-w64-mingw32-gcc -c source.c -o output.x64.o -w`, the following checks should be performed before loading it into Havoc:

- `file output.x64.o` — Verify it is `COFF x86-64 object` format
- `objdump -t output.x64.o | grep go` — Verify the `go` entry point is exported
- `objdump -h output.x64.o | grep bss` — Verify `.bss Size=00000000` (no uninitialized globals)
- `objdump -t output.x64.o | grep BeaconFormat` — Verify no `BeaconFormat*` symbols (see note above)
- `objdump -t output.x64.o | grep WSOCK32` — Verify no incorrect DLL references
- `strings output.x64.o | grep -iE "amsi|etw|mimikatz|powershell"` — Verify no OPSEC-sensitive strings remain in plaintext
- `objdump -t output.x64.o | grep -iE "amsi|etw|hwbp"` — Verify no OPSEC-sensitive symbol names

Skipping these checks means bugs that would take 5 seconds to catch with `objdump` instead take hours of runtime debugging with no error messages.

---

## Conclusion

Building NOFILTER-NFEXEC involved three distinct challenges. First, correctly implementing a well-documented kernel technique (Ron Ben-Yizhak’s NoFilter) while handling the edge cases that a PoC does not need to worry about — deadlock-safe handle scanning, proper token type conversion, handle lifetime management. Second, designing an OPSEC stack that avoids detection not just at one layer but across the entire execution path — from function resolution to syscall invocation to memory cleanup. Third, working with a framework where reading the source code (rather than relying solely on documentation) is essential for understanding the precise behavior of each API.

The source code is available at [https://github.com/y637F9QQ2x/NOFILTER-NFEXEC](https://github.com/y637F9QQ2x/NOFILTER-NFEXEC). It is intended for authorized penetration testing and red team operations only.

---

## References

- Ron Ben-Yizhak, [#NoFilter: Abusing Windows Filtering Platform for Privilege Escalation](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Ron%20Ben-Yizhak%20-%20NoFilter%20Abusing%20Windows%20Filtering%20Platform%20for%20privilege%20escalation.pdf), DEF CON 31, August 2023
- Deep Instinct, [NoFilter — Abusing Windows Filtering Platform for Privilege Escalation](https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation) (blog post)
- [deepinstinct/NoFilter](https://github.com/deepinstinct/NoFilter) — Original proof-of-concept
- [HavocFramework/Havoc](https://github.com/HavocFramework/Havoc) — Havoc C2 framework
- [HavocFramework/Modules](https://github.com/HavocFramework/Modules) — PowerPick (PowershellRunner.h source, GPLv3)
