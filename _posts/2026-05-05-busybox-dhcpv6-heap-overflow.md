---
layout: post
title: "Same Workflow, New Target: AI-Assisted Discovery of CVE-2026-29004 in BusyBox"
date: 2026-05-05 21:00:00 +0900
categories: [Security Research, Vulnerability Discovery]
tags: [cve, heap-overflow, busybox, vulnerability-research]
description: "How the same AI analysis workflow that found a zero-day in strongSwan discovered a 9-year-old heap buffer overflow in BusyBox's DHCPv6 client — plus a full walkthrough of the proof-of-concept development process."
---

## Introduction

This post documents **CVE-2026-29004**, a heap buffer overflow (a bug where a program writes more data into a dynamically allocated memory block than it can hold, spilling into adjacent memory) I discovered in [BusyBox](https://busybox.net/)'s DHCPv6 client (`udhcpc6`). The bug had been present in the codebase for approximately 9 years — introduced in March 2017 and patched in March 2026.

The vulnerability was found using the same structured, multi-pass AI analysis workflow that I described in detail in [my previous post on CVE-2026-25075 (strongSwan)](https://y637f9qq2x.com/posts/cve-2026-25075/). Rather than repeating the methodology here, this post focuses on the vulnerability itself — what it is and why it exists. For the full methodology, including the instruction document, session prompts, and false-positive elimination flow, see that earlier post.

This is the second zero-day discovered using the same workflow. The first (CVE-2026-25075) was an integer underflow in strongSwan's EAP-TTLS parser that had been present for over 15 years. This one is a different class of bug — a heap buffer overflow caused by an incorrect allocation formula — in a completely different codebase. The point is not the individual findings but the consistency: the same structured process, applied to a different target, produced a second confirmed vulnerability with a CVE assignment.

In addition to the vulnerability analysis, this post documents the full proof-of-concept development process — building a vulnerable BusyBox binary with AddressSanitizer (a compiler tool that detects memory errors at runtime), writing a fake DHCPv6 server, and triggering the crash in an isolated network. That process, including the dead ends and workarounds, is covered in Part 3.

---

## Part 1: Background

### What Is BusyBox?

**BusyBox** is an open-source software project that combines stripped-down versions of over 300 common Unix command-line tools — `ls`, `grep`, `cp`, `wget`, `awk`, and many others — into a single small executable, typically under 1 MB. It is sometimes called "The Swiss Army Knife of Embedded Linux" because it packs so many tools into one compact binary.

BusyBox exists because embedded systems — routers, IoT devices (Internet of Things — network-connected devices like sensors, cameras, and smart appliances), industrial controllers, set-top boxes — have limited storage and memory. A typical Linux desktop includes hundreds of separate executable files for its command-line tools, totaling tens of megabytes. On a device with only a few megabytes of flash storage for its entire operating system, that is not feasible. BusyBox solves this by implementing all those tools inside a single binary, where they share common code (string handling, file I/O, error reporting) rather than each carrying its own copy. The result is a drastic reduction in total size.

BusyBox is a foundational component of embedded Linux. It is used by OpenWrt (a widely deployed Linux distribution for routers and network devices), Alpine Linux, Buildroot, the Yocto Project, and many commercial products including routers, network-attached storage devices, and smart TVs. It is also included in Android. When you interact with a home router's command line or an embedded device's shell, there is a good chance BusyBox is what is running behind the scenes.

### What Is DHCP?

**DHCP (Dynamic Host Configuration Protocol)** is the mechanism by which devices automatically get their network settings — most importantly an IP address — when they connect to a network. When you plug in an Ethernet cable or join a Wi-Fi network, your device does not have an IP address yet. It broadcasts a request onto the local network saying "I need network settings." A DHCP server (usually built into your router) responds with an IP address, a subnet mask, a default gateway, and the addresses of DNS servers (servers that translate domain names like `example.com` into IP addresses). This exchange happens automatically, without any user intervention.

### What Is DHCPv6?

**DHCPv6** is the version of DHCP designed for IPv6 networks. IPv6 (Internet Protocol version 6) is the successor to IPv4, the protocol that assigns the familiar four-number addresses like `192.168.1.1`. IPv6 uses much longer 128-bit addresses, written in hexadecimal notation as eight groups of four hex digits separated by colons — for example, `2001:0db8:85a3:0000:0000:8a2e:0370:7334`.

DHCPv6 operates over UDP (User Datagram Protocol — a simple transport protocol that sends individual packets without establishing a connection first) on specific ports: port 546 for the client and port 547 for the server. Communication happens via link-local multicast (a message sent not to a single device but to a group of devices simultaneously) — meaning the client sends its requests to a special multicast address (`ff02::1:2`) that reaches all DHCPv6 servers on the same network segment. **Critically, DHCPv6 has no built-in authentication or encryption.** Any device on the same Layer 2 network segment (the local network — the set of devices that can communicate directly without going through a router) can send DHCPv6 responses. This means a malicious device on the same local network can impersonate a DHCPv6 server and send crafted responses to any client.

### What Is udhcpc6?

**udhcpc6** is BusyBox's built-in DHCPv6 client. It is the component that sends DHCPv6 requests and processes the server's responses to configure the device's IPv6 network settings. When an embedded Linux device running BusyBox needs to obtain an IPv6 address, DNS servers, or other network configuration via DHCPv6, udhcpc6 handles that process. It parses the response from the server, extracts the relevant options (IP addresses, DNS servers, domain search lists, etc.), and passes them to a configuration script via environment variables (name-value pairs that are passed to child processes — for example, `dns=2001:db8::1`).

### How DHCPv6 Options Work

DHCPv6 responses carry configuration data as a list of **options** — structured fields, each containing a specific piece of information. Every option has a 4-byte header followed by a variable-length payload:

| Offset | Size | Field |
|:------:|:----:|:------|
| 0–1 | 2 bytes | Option Code (identifies what type of data this is) |
| 2–3 | 2 bytes | Option Length (number of bytes in the payload that follows) |
| 4+ | variable | Option Data (the actual content) |

The option relevant to this vulnerability is **D6_OPT_DNS_SERVERS** (option code 23, written in hexadecimal as `0x0017`). This option carries a list of IPv6 DNS server addresses. Each IPv6 address is 16 bytes, so the Option Length should always be a multiple of 16 — for example, 16 for one DNS server, 32 for two, 48 for three, and so on. A length of 0 would mean zero DNS server addresses.

When udhcpc6 receives a DHCPv6 response, it walks through the list of options and processes each one. For the DNS_SERVERS option, the handler computes how many server addresses are present, allocates a heap buffer (a block of memory dynamically requested from the operating system at runtime, as opposed to stack memory which is automatically managed), formats the addresses as human-readable strings, and stores the result as an environment variable (`dns=...`) that gets passed to the configuration script.

---

## Part 2: The Vulnerability

The following diagram shows the end-to-end attack flow: a malicious device on the same local network sends a crafted DHCPv6 response, which is parsed by the target device's `udhcpc6` client, triggering a heap buffer overflow.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/busybox-dhcpv6-heap-overflow/attack-flow.svg"
     alt="CVE-2026-29004 attack flow — crafted DHCPv6 response triggers heap buffer overflow in udhcpc6"
     style="width:100%;height:auto;display:block">

### The Allocation Formula

The bug is in the DNS_SERVERS option handler within the `option_to_env()` function in `networking/udhcp/d6_dhcpc.c`. The relevant code (before the fix) looks like this:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">C</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">addrs = option[3] &gt;&gt; 4;&#10;&#10;*new_env() = dlist = xmalloc(4 + addrs * 40 - 1);&#10;dlist = stpcpy(dlist, "dns=");&#10;&#10;while (addrs--) {&#10;    sprint_nip6(dlist, option + 4 + option_offset);&#10;    dlist += 39;&#10;    option_offset += 16;&#10;    if (addrs)&#10;        *dlist++ = ' ';&#10;}</pre></div>

Here is what each line does:

**Line 1:** `addrs = option[3] >> 4` — The code computes the number of DNS server addresses. `option[3]` is the low byte of the 2-byte Option Length field. The high byte (`option[2]`) is already verified to be 0 by the outer parsing loop before this handler is reached, so the low byte alone contains the full length value. The `>> 4` operation is a **right bit-shift** — it divides the value by 16 (since each IPv6 address is 16 bytes long). For example, if the Option Length is 32 (two addresses × 16 bytes each), `32 >> 4` gives 2.

**Line 2:** `xmalloc(4 + addrs * 40 - 1)` — The code allocates a heap buffer to hold the formatted output string. The formula is supposed to account for: a 4-character prefix (`dns=`), plus 40 characters per address (39 characters for the formatted IPv6 address in `xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx` notation, plus 1 character for the space separator between addresses), minus 1 because the last address has no trailing space. For a concrete example with 2 addresses, the intended output is `dns=xxxx:...:xxxx xxxx:...:xxxx` — that is 4 + 39 + 1 + 39 = 83 characters, and the formula gives 4 + 2×40 − 1 = 83. **This formula is wrong.** It does not account for the NUL terminator (a zero byte that C uses to mark the end of a string — every C string must end with this byte, and any function that writes a string automatically appends it). The actual space needed for 2 addresses is 84 bytes (83 characters + 1 NUL). The correct formula is `4 + addrs * 40 + 1`.

**Line 3:** `stpcpy(dlist, "dns=")` — Copies the 4-character prefix `dns=` plus a NUL terminator into the buffer — 5 bytes total. `stpcpy` is a standard C library function that copies a string and returns a pointer to the NUL byte it wrote at the end — unlike `strcpy`, which returns a pointer to the start of the destination. After this call, `dlist` points to the NUL byte at index 4 (the position immediately after `=`). When `addrs` is 1 or more, the next `sprint_nip6()` call will write starting at this position, overwriting the NUL with the first character of the formatted IPv6 address. When `addrs` is 0, the loop does not execute and those 5 bytes are the only thing written — which is where the 2-byte overflow occurs, as detailed in Scenario 1 below.

**Line 4:** `sprint_nip6(dlist, ...)` — Formats a 16-byte raw IPv6 address into a human-readable string. Internally, this function uses `sprintf()` to produce 8 groups of 4 hexadecimal characters separated by colons — for example, `fe80:0000:0000:0000:0001:0002:0003:0004`. That is 8 × 4 = 32 hex characters plus 7 colons = 39 characters total, plus the NUL terminator that `sprintf()` automatically appends = 40 bytes written.

### What Is a Heap Buffer Overflow?

A **heap buffer overflow** (CWE-122 — a standardized identifier from MITRE's Common Weakness Enumeration catalog) occurs when a program writes more data into a heap-allocated memory block than the block can hold. The excess bytes spill over into adjacent memory — memory that belongs to other allocations, heap metadata (bookkeeping data that the memory allocator uses to track which blocks are free and which are in use), or other internal structures.

On a desktop system with modern heap protections — guard pages, canary values (small known patterns placed between allocations that the allocator checks for corruption), and address space layout randomization (ASLR — a technique that randomizes where memory regions are placed, making it harder for attackers to predict addresses) — a heap overflow typically causes the program to crash with an error. On embedded systems running BusyBox, these protections are often absent. Embedded devices frequently use minimal C libraries (like uClibc or musl) and run without ASLR, without stack canaries, and without heap integrity checks. In these environments, a heap overflow can silently corrupt adjacent data or heap metadata without any immediate crash, potentially allowing an attacker to manipulate program behavior or achieve code execution.

### The Two Overflow Scenarios

The incorrect formula `4 + addrs * 40 - 1` produces a buffer that is too small in every case — but the severity differs depending on whether `addrs` is zero or non-zero.

**Scenario 1: Zero addresses (addrs = 0)**

When the Option Length is 0 (no DNS server addresses), `option[3] >> 4` evaluates to 0. The preceding validation check — `(option[3] & 0x0f) != 0` — is designed to reject payloads whose length is not a multiple of 16. But when the length is 0, this check evaluates to `(0 & 0x0f) != 0`, which is `0 != 0`, which is `false`. The check does not reject the zero-length payload.

The allocation then computes `xmalloc(4 + 0 × 40 − 1)` = `xmalloc(3)`, which allocates **3 bytes**. The subsequent `stpcpy(dlist, "dns=")` writes 5 bytes: the characters `d`, `n`, `s`, `=`, and a NUL terminator. That is 5 bytes into a 3-byte buffer — a **2-byte heap overflow**. The overflowed bytes are `=` (0x3D) at offset 3 and NUL (0x00) at offset 4.

The `while (addrs--)` loop does not execute in this case: `addrs--` evaluates to 0 (the value before decrement), which is false, so the loop body is skipped.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/busybox-dhcpv6-heap-overflow/heap-overflow-layout.svg"
     alt="Heap buffer overflow memory layout — xmalloc(3) with stpcpy writing 5 bytes, overflowing indices 3 and 4"
     style="width:100%;height:auto;display:block">

**Scenario 2: One or more addresses (addrs ≥ 1)**

When `addrs` is 1 or greater, the overflow is a single byte — but it occurs for every possible value of `addrs`, making it a consistent off-by-one error. The issue is that `sprint_nip6()` writes 39 visible characters plus a NUL terminator. The NUL terminator is what overflows.

For `addrs = 1`: the allocation computes `xmalloc(4 + 1 × 40 − 1)` = `xmalloc(43)`, which allocates 43 bytes. After `stpcpy(dlist, "dns=")` writes 4 bytes of text (at indices 0–3), `sprint_nip6()` writes 39 characters (at indices 4–42) plus a NUL terminator at index 43. Index 43 is one byte past the end of the 43-byte allocation (valid indices 0–42). This is a **1-byte NUL overflow**.

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">Plaintext</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">Allocation:  xmalloc(43)  →  buffer has valid indices [0 .. 42]&#10;&#10;stpcpy writes:   d  n  s  =&#10;At indices:      0  1  2  3&#10;&#10;sprint_nip6 writes:   f  e  8  0  :  0  0  0  0  :  ...  :  0  0  0  4  \0&#10;At indices:           4  5  6  7  8  9  ...                          42  43&#10;                                                                         ^^^&#10;                                                              overflow: 1 byte (NUL)</pre></div>

For every value of `addrs ≥ 1`, the same pattern holds: the NUL terminator written by the last `sprint_nip6()` call always falls exactly 1 byte past the allocation boundary.

### The Fix

The patch (commit `42202bfb1e`) changes three things:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">DIFF</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">- *new_env() = dlist = xmalloc(4 + addrs * 40 - 1);&#10;+ *new_env() = dlist = xmalloc(4 + addrs * 40 + 1);&#10;&#10;- while (addrs--) {&#10;+ while (addrs-- != 0) {&#10;&#10;-     if (addrs)&#10;+     if (addrs != 0)</pre></div>

The allocation formula changes from `- 1` to `+ 1`, adding 2 bytes to the buffer. This provides space for the NUL terminator in all cases:

| addrs | Old formula | New formula | Bytes needed | Old: overflow? | New: overflow? |
|:-----:|:-----------:|:-----------:|:------------:|:--------------:|:--------------:|
| 0 | 3 | 5 | 5 | Yes (2 bytes) | No |
| 1 | 43 | 45 | 44 | Yes (1 byte) | No |
| 2 | 83 | 85 | 84 | Yes (1 byte) | No |
| 3 | 123 | 125 | 124 | Yes (1 byte) | No |

The `while (addrs--)` to `while (addrs-- != 0)` change is functionally identical in C — both evaluate the pre-decrement value and test whether it is non-zero — but makes the intent clearer and avoids relying on implicit integer-to-boolean conversion.

### Concrete Attack Payload

A malicious DHCPv6 server on the same local network sends a response containing the following 4-byte option:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">Plaintext</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">Byte offset:   0     1     2     3&#10;Hex value:    00    17    00    00&#10;Meaning:      Option Code    Option Length&#10;              (0x0017 =      (0 bytes =&#10;               DNS_SERVERS)   zero addresses)</pre></div>

When `udhcpc6` processes this option:

1. The outer loop validation passes — the declared option length fits within the remaining packet buffer, so the option is accepted for processing.
2. The `option[1] == 0x17` match routes to the DNS_SERVERS handler.
3. The modulo-16 check `(option[3] & 0x0f) != 0` evaluates to `(0 & 0x0f) != 0`, which is false — so the handler does not reject the option. This check is designed to reject payloads whose length is not a multiple of 16 (since each IPv6 address is 16 bytes), but 0 is a multiple of 16 in the mathematical sense, so it passes. There is no separate check to reject the zero-length case.
4. `addrs = 0 >> 4 = 0`.
5. `xmalloc(4 + 0 − 1)` = `xmalloc(3)` allocates 3 bytes.
6. `stpcpy(dlist, "dns=")` writes 5 bytes into the 3-byte buffer — a 2-byte heap overflow.

### Reach Path

An attacker must be on the same Layer 2 network segment as the target device. DHCPv6 operates over link-local multicast with no authentication, so any device on the local network can send spoofed DHCPv6 responses. This is not an internet-facing vulnerability — the attacker cannot reach the target from across the internet. They must be on the same physical or virtual LAN (for example, the same Wi-Fi network, the same Ethernet switch, or the same VLAN). This is sometimes described as an **adjacent-network** attack (requiring the attacker to be on the same local network, not reachable from the general internet).

The vulnerability is client-side only: the malicious payload is a DHCPv6 server response processed by the client (`udhcpc6`). The attacker sends the crafted response; the client parses it.

### Impact

On embedded systems without heap hardening (which is common for BusyBox deployments), the 2-byte overflow can corrupt heap metadata or adjacent allocations. The practical impact ranges from denial of service (crashing `udhcpc6`, which disrupts network configuration) to potential code execution, depending on the heap allocator implementation and memory layout of the specific target device.

The 1-byte NUL overflow (addrs ≥ 1 case) is less severe but still constitutes a heap buffer overflow. Writing a single NUL byte past the end of an allocation can corrupt the size or flags field of the next heap chunk on some allocators, potentially leading to heap corruption on subsequent allocation or free operations.

### Proof of Concept

The following recording demonstrates the vulnerability being triggered. A vulnerable version of BusyBox is compiled with AddressSanitizer (a compiler-level memory error detector) in a Linux environment, and a malicious DHCPv6 server on the same virtual network sends a crafted response containing the zero-length DNS_SERVERS option (`00 17 00 00`). When `udhcpc6` processes the response, AddressSanitizer detects the heap buffer overflow and terminates the process. The complete environment setup — including the ASAN build configuration, the fake DHCPv6 server, and the network namespace topology — is documented in Part 3.

<img src="{{ site.url }}{{ site.baseurl }}/assets/img/busybox/CVE-2026-29004_PoC.gif"
     alt="CVE-2026-29004 Proof of Concept — AddressSanitizer detecting heap-buffer-overflow in udhcpc6"
     style="width:100%;height:auto;display:block">

### History

The incorrect allocation formula was introduced in commit `64d58aa80` on **March 27, 2017**, in a commit titled "udhcp6: fix problems found running against dnsmasq." The formula `malloc(4 + olen * 40 - 1)` was part of a handler refactoring that itself was fixing earlier problems. A later commit (`234b82ca1`, "udhcpc6: add support for timezones") carried the formula forward unchanged. No subsequent commit modified this allocation formula until the fix, meaning the bug survived approximately **9 years** of active development and deployment.

---

## Part 3: Building and Running the Proof of Concept

Finding a vulnerability in source code is one thing. Proving that it actually triggers at runtime — that the bug is not just a theoretical concern but a real, observable memory corruption — is what turns a code review finding into a confirmed CVE. This section documents the full process of building a working proof of concept for CVE-2026-29004: the environment setup, the problems encountered, the workarounds, and the final crash.

The entire PoC development process was driven by **Claude Code** — Anthropic's command-line AI coding agent — running inside a WSL (Windows Subsystem for Linux — a compatibility layer that lets you run a Linux environment directly on Windows) terminal. The workflow was iterative: describe what needs to happen, let the agent write code and run commands, observe the results, feed errors back in, and repeat until the crash is confirmed. This is documented in detail because the trial-and-error process itself is instructive — it shows the kinds of obstacles that come up in real vulnerability verification work, and how to get past them.

### The Goal

The objective was straightforward: compile a vulnerable version of BusyBox with **AddressSanitizer** (ASAN — a compiler feature that inserts runtime checks around every memory access, detecting out-of-bounds reads and writes the moment they happen rather than letting them silently corrupt memory), then send a crafted DHCPv6 response to the built-in `udhcpc6` client and observe the ASAN-reported heap buffer overflow.

ASAN is the standard tool for this kind of verification. Without it, a 2-byte heap overflow might not cause an immediate crash — the overwritten bytes might land in heap padding or an unused allocation, and the program would continue running as if nothing happened. ASAN eliminates this ambiguity: it places inaccessible "red zones" around every heap allocation, so even a 1-byte overflow is caught and reported with a full stack trace showing exactly where the write occurred and where the memory was originally allocated.

### The Initial Plan: Docker

The first approach was to build everything inside a Docker container — an isolated environment with its own filesystem and network stack, commonly used for reproducible security testing. The plan was:

1. Start from a clean `ubuntu:22.04` base image
2. Install build tools (`build-essential`, `git`, `gcc`)
3. Clone the BusyBox source code from the GitHub mirror at a commit known to be vulnerable (before the fix in commit `42202bf`)
4. Compile with ASAN flags
5. Run the PoC inside the container using a virtual network

A Dockerfile and supporting scripts were generated, and `docker build` was launched. This is where the problems started.

### Problem 1: Docker Cannot Reach the Internet

The Docker build hung at the `apt-get update` step — the container could not download any packages. The build log showed errors like:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">LOG</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">Err:107 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 dirmngr&#10;  Could not connect to archive.ubuntu.com:80 (91.189.92.24)&#10;  - connect (111: Connection refused)</pre></div>

The container could resolve DNS names (the IP addresses are visible in the log), but TCP connections to port 80 were being refused. This is a known issue with **Docker Desktop on WSL2**: the Hyper-V virtual machine that WSL2 runs inside has a firewall that blocks outbound connections from Docker containers by default. The host machine's browser and WSL itself can reach the internet, but containers cannot — the traffic gets blocked at the Hyper-V network boundary.

### Attempted Fix: --network=host and Japanese Mirrors

Two workarounds were tried in sequence:

**First**, the `--network=host` flag was added to `docker build`. This flag tells Docker to bypass its virtual network and use the host's network stack directly. The build progressed slightly further — the Ubuntu image was pulled successfully — but `apt-get` still timed out, managing only about one package per minute.

**Second**, the Dockerfile was modified to use a geographically closer package mirror (`jp.archive.ubuntu.com` instead of the default `archive.ubuntu.com`). This made no difference — the underlying network path from inside Docker was still broken.

After roughly 40 minutes of waiting and iterating on Docker networking configurations, the Docker approach was abandoned entirely.

### The Pivot: Building Directly on WSL

The WSL host itself had no network problems — it was running Claude Code, downloading packages, and cloning Git repositories without any issues. The only thing Docker provided was isolation, which is not strictly necessary for a PoC that just needs to compile BusyBox and crash it in a controlled way.

The revised plan:

1. Install build dependencies directly on the WSL host
2. Clone and build BusyBox with ASAN directly on the host filesystem
3. Use Linux **network namespaces** (a kernel feature that creates isolated network environments within the same machine — each namespace has its own interfaces, routing table, and firewall rules, without needing a container) to isolate the PoC network traffic
4. Run the fake DHCPv6 server and `udhcpc6` client in connected namespaces

This approach worked on the first attempt. The `apt-get install` completed in seconds, the `git clone` took under a minute, and the ASAN build finished in a few minutes. No network issues, no Hyper-V firewall, no container overhead.

### Building BusyBox with AddressSanitizer

BusyBox uses a Kconfig-based build system (the same configuration system used by the Linux kernel). The build process is:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">BASH</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">git clone https://github.com/mirror/busybox.git&#10;cd busybox&#10;make defconfig</pre></div>

`make defconfig` generates a default `.config` file with all standard applets enabled. Two configuration options must be verified:

- `CONFIG_UDHCPC6=y` — enables the DHCPv6 client applet
- `CONFIG_FEATURE_UDHCPC6_RFC3646=y` — enables the DNS_SERVERS option handler (the code containing the vulnerability)

Both are enabled by default in standard configurations. One option must be **changed**: `CONFIG_STATIC` must be set to `n` (disabled). BusyBox defaults to static linking — it bundles all library code into the binary itself. ASAN cannot work with static linking. Here is why: ASAN's runtime library (`libasan`) needs to replace the standard memory allocation functions (`malloc`, `free`, `memcpy`, etc.) with its own instrumented versions — versions that track every allocation's size and boundaries. It achieves this through a mechanism called **symbol interposition**: when multiple shared libraries define the same function name, the dynamic linker calls the one that was loaded first. By loading `libasan` before the standard C library, ASAN's instrumented `malloc` gets called instead of the normal one. In a statically linked binary, the standard library functions are compiled directly into the executable and cannot be replaced at load time, so this interception does not work.

The ASAN-enabled build command:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">BASH</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">make CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer -w" \&#10;     LDFLAGS="-fsanitize=address" \&#10;     -j$(nproc)</pre></div>

The flags serve specific purposes: `-fsanitize=address` enables ASAN instrumentation on every memory access, `-g` includes debug symbols so stack traces show source file names and line numbers instead of raw addresses, `-O0` disables compiler optimizations that would rearrange or eliminate code (making the binary match the source line-for-line), `-fno-omit-frame-pointer` preserves the frame pointer register so stack unwinding produces accurate call traces, and `-w` suppresses compiler warnings (BusyBox generates many benign warnings that clutter the build output).

### The Fake DHCPv6 Server

The PoC requires a malicious DHCPv6 server that sends a crafted response to `udhcpc6`. This was implemented as a Python script (`dhcpv6_poc.py`) that does the following:

1. Opens a UDP socket on port 547 (the standard DHCPv6 server port)
2. Joins the `ff02::1:2` multicast group — this is the "All DHCPv6 Relay Agents and Servers" multicast address that DHCPv6 clients send their Solicit messages to
3. Waits for an incoming Solicit message from `udhcpc6`
4. Extracts the **transaction ID** (a 3-byte random value that the client generates to match requests with responses — the client ignores any response whose transaction ID does not match) and the **Client Identifier** (a unique identifier for the client device that must be echoed back in the server's response)
5. Constructs a DHCPv6 Advertise message containing: a Server Identifier option, the echoed Client Identifier, an IA_NA option with a valid IPv6 address assignment (so the client accepts the response as legitimate), and the **poisoned DNS_SERVERS option** — `00 17 00 00` — with a length of zero
6. Sends the response back to the client

The key insight is that the poisoned option must be embedded in an otherwise valid DHCPv6 response. If the response is missing required options (like the Server Identifier or IA_NA), the client will reject the entire message before ever reaching the DNS_SERVERS handler. The malformed option rides inside a structurally valid response.

### Network Setup with Namespaces

To create an isolated network where the fake server and the client can communicate without affecting the host's real network, the PoC uses Linux network namespaces and **veth pairs** (virtual Ethernet pairs — two virtual network interfaces connected back-to-back, like a virtual crossover cable; anything sent into one end comes out the other):

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">BASH</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent"># Create a network namespace for the client&#10;sudo ip netns add poc_client&#10;&#10;# Create a virtual Ethernet pair: srv0 &lt;--&gt; cli0&#10;sudo ip link add srv0 type veth peer name cli0&#10;&#10;# Move one end into the client namespace&#10;sudo ip link set cli0 netns poc_client&#10;&#10;# Configure the server side (stays in the default namespace)&#10;sudo ip -6 addr add fe80::1/64 dev srv0&#10;sudo ip link set srv0 up&#10;&#10;# Configure the client side (inside the namespace)&#10;sudo ip netns exec poc_client ip link set lo up&#10;sudo ip netns exec poc_client ip -6 addr add fe80::2/64 dev cli0&#10;sudo ip netns exec poc_client ip link set cli0 up</pre></div>

After this setup, the fake DHCPv6 server runs in the default namespace on `srv0`, and `udhcpc6` runs inside the `poc_client` namespace on `cli0`. The veth pair connects them. When `udhcpc6` sends a DHCPv6 Solicit to the multicast address `ff02::1:2` on `cli0`, the packet arrives at `srv0` where the Python server is listening.

A brief wait (2–3 seconds) after bringing up the interfaces is necessary to allow **DAD (Duplicate Address Detection)** to complete — this is an IPv6 mechanism where each device checks that its chosen address is not already in use by broadcasting a probe and waiting for conflicts. If `udhcpc6` starts before DAD finishes, the interface may not have a usable IPv6 address yet, and the Solicit message will not be sent.

### Triggering the Crash

With the network in place, the server is started in one terminal:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">BASH</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">sudo python3 dhcpv6_poc.py srv0</pre></div>

And `udhcpc6` is launched in the client namespace in a second terminal:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">BASH</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">sudo ip netns exec poc_client \&#10;  env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_legend=0" \&#10;  ./busybox/busybox udhcpc6 -f -n -i cli0 -s /tmp/dhcpv6_evt.sh</pre></div>

The `ASAN_OPTIONS` environment variable configures ASAN's behavior: `detect_leaks=0` disables memory leak detection (not relevant here — we only care about the overflow), `abort_on_error=1` forces the process to terminate immediately on the first error (so the crash is clean and unambiguous), and `print_legend=0` suppresses the explanatory footer that ASAN normally appends.

Within seconds, the DHCPv6 handshake completes. Unlike DHCPv4's simple two-step exchange, DHCPv6 uses a four-message sequence: **Solicit** (client asks "are there any servers?"), **Advertise** (server says "I'm here, here's what I can offer"), **Request** (client says "I accept your offer"), and **Reply** (server confirms and sends the final configuration). The Reply carries the poisoned DNS_SERVERS option. When `udhcpc6` processes this option in `option_to_env()`, ASAN detects the overflow and terminates the process.

### Reading the ASAN Output

The crash output from AddressSanitizer tells the complete story:

<div style="background:#282a36;border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08);background:#21222c"><span style="font-size:.73rem;color:rgba(248,248,242,.55);font-family:monospace;letter-spacing:.05em">ASAN OUTPUT</span><button onclick="var p=this.parentElement.nextElementSibling;if(p){navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})}" style="background:rgba(248,248,242,.08);border:1px solid rgba(248,248,242,.25);color:#f8f8f2;cursor:pointer;font-size:.7rem;padding:.18rem .55rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:#f8f8f2;font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">==8143==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000113&#10;WRITE of size 5 at 0x502000000113 thread T0&#10;    #0 0x7526162fb302 in memcpy&#10;    #1 0x59c03cac6e36 in option_to_env networking/udhcp/d6_dhcpc.c:354&#10;    #2 0x59c03cac75d6 in fill_envp networking/udhcp/d6_dhcpc.c:437&#10;    #3 0x59c03cac774b in d6_run_script networking/udhcp/d6_dhcpc.c:453&#10;    #4 0x59c03cace015 in udhcpc6_main networking/udhcp/d6_dhcpc.c:1840&#10;&#10;0x502000000113 is located 0 bytes after 3-byte region [0x502000000110,0x502000000113)&#10;allocated by thread T0 here:&#10;    #0 0x7526162fd9c7 in malloc&#10;    #1 0x59c03c9935a3 in xmalloc libbb/xfuncs_printf.c:50&#10;    #2 0x59c03cac6de2 in option_to_env networking/udhcp/d6_dhcpc.c:354</pre></div>

Here is what each part means:

**`WRITE of size 5 at ... 3-byte region`** — ASAN detected a write of 5 bytes into a memory region that is only 3 bytes long. The 5 bytes are the `stpcpy(dlist, "dns=")` call writing `d`, `n`, `s`, `=`, and a NUL terminator. The 3-byte region is the `xmalloc(3)` allocation from the formula `4 + 0*40 - 1`.

**`#1 in option_to_env networking/udhcp/d6_dhcpc.c:354`** — The overflow happened at line 354 of `d6_dhcpc.c`, inside the `option_to_env()` function. This is exactly the line containing the vulnerable `xmalloc` and `stpcpy` sequence.

**`0x502000000113 is located 0 bytes after 3-byte region`** — The first overflowed byte is immediately adjacent to the end of the allocation. "0 bytes after" means there is no gap — the overflow starts at the very first byte past the allocated region.

**`allocated by ... xmalloc libbb/xfuncs_printf.c:50`** — The allocation that was overflowed came from `xmalloc()` (BusyBox's wrapper around `malloc` that aborts on allocation failure), called from `option_to_env()` at the same line 354. This confirms that the allocation and the overflow happen in the same function, on the same line — exactly matching the vulnerability described in Part 2.

The call chain `udhcpc6_main → d6_run_script → fill_envp → option_to_env` confirms the complete path: the main DHCPv6 client loop receives a response, triggers the configuration script, which populates environment variables, which calls the DNS_SERVERS option handler where the overflow occurs.

### Lessons from the Process

The Docker detour added roughly an hour of wasted time. In hindsight, building directly on WSL should have been the first choice — Docker provides isolation, but isolation is not necessary when the goal is simply to compile a binary and crash it in a controlled network. Network namespaces provide sufficient isolation for PoC work, without the complexity of Docker networking (which, on WSL2 with Docker Desktop, introduces an additional Hyper-V network layer that creates more problems than it solves).

The key takeaway for anyone reproducing vulnerability PoCs: **start simple**. A direct build on the host (or in WSL) with `ip netns` for network isolation is faster, more debuggable, and has fewer moving parts than a Docker-based setup. Docker is valuable when you need reproducibility across machines or a pristine environment, but for initial PoC development where you are iterating rapidly, the overhead is rarely justified.

---

## Part 4: Key Takeaways

### On the Vulnerability

- **All BusyBox builds with `FEATURE_UDHCPC6_RFC3646` enabled** (the compile-time flag that adds DNS option support to the DHCPv6 client) are affected. This flag is **enabled by default** in standard BusyBox configurations. The fix is in commit `42202bfb1e6ac51fa995beda8be4d7b654aeee2a`.
- If your embedded devices do not use DHCPv6 (many embedded deployments use only IPv4), the vulnerable code is never reached.
- The attack requires Layer 2 adjacency — the attacker must be on the same local network segment. It is not exploitable from the internet.

### On the Methodology

This is the second zero-day found with the same structured, multi-pass AI analysis workflow described in [the strongSwan post](https://y637f9qq2x.com/posts/cve-2026-25075/). The workflow is unchanged: the same instruction document, the same multi-pass structure (initial analysis → false-positive elimination → bias-free re-analysis in a separate session), and the same verification steps. The target was different, the bug class was different, and the result was a confirmed CVE — again.

Two data points are not a trend, but they are evidence that the workflow is not a one-off. The core insight remains the same as before: **structure is the primary variable.** An unstructured prompt asking an AI to "find vulnerabilities in this code" produces noise. A well-specified instruction document — one that defines what to look for, how to verify it, and how to eliminate false positives — produces actionable results.

---

## References

- [CVE-2026-29004](https://www.vulncheck.com/advisories/busybox-dhcpv6-client-heap-buffer-overflow-via-dns-servers) — VulnCheck advisory
- [Fix commit (42202bfb1e)](https://github.com/vda-linux/busybox_mirror/commit/42202bfb1e6ac51fa995beda8be4d7b654aeee2a) — "udhcpc6: fix buffer overflow"
- [BusyBox project](https://busybox.net/)
- [AI-Assisted Vulnerability Analysis Methodology](https://y637f9qq2x.com/posts/cve-2026-25075/) — Full methodology documentation (strongSwan post)
