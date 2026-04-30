---
layout: post
title: "Beneath the Perimeter: Structural Memory Safety Issues in Embedded Protocol Stacks"
date: 2026-04-19 12:00:00 +0900
categories: [Security Research, Vulnerability Discovery]
tags: [cve, out-of-bounds-read, bluetooth, iot, vulnerability-research]
description: "BTstack, libcoap, and miniupnpd are three entirely different protocol stacks — Bluetooth, CoAP, and UPnP — with nothing obvious in common. Yet systematic analysis surfaces the same class of memory safety failure across all three. This post examines the structural reasons why adjacent-network protocol implementations — those reachable only from the same local network or Bluetooth range — are a consistent source of these issues."
---

## Introduction

Most security attention goes to software that faces the internet directly — web applications, VPNs, firewalls. Less scrutiny falls on the layer beneath: the **protocol stacks** that run inside embedded systems, home routers, IoT devices (Internet of Things — devices like smart speakers, sensors, and routers), Bluetooth headsets, and industrial controllers. A protocol stack is a layered software library that implements a communication protocol — it handles the low-level details of parsing messages, managing connections, and enforcing protocol rules on behalf of the application above it.

These libraries are written in C or C++, have been around for years, and are deployed in tens of millions of devices — but they are rarely audited with the same rigour as web-facing code. The central concern is **memory safety** — the property that a program only reads and writes memory it is permitted to access. When memory safety breaks, an attacker can observe or corrupt data the program was not supposed to touch.

The same AI-assisted analysis pipeline that surfaces structural issues in one codebase scales naturally to other implementations in the same domain. A single methodology applied to three unrelated libraries produced five CVEs sharing the same class of root cause — unsafe handling of network-supplied values in C. For background on the methodology itself, see the earlier post on [CVE-2026-25075 in strongSwan](https://y637f9qq2x.com/posts/cve-2026-25075/).

This post covers five CVEs found across three such libraries:

- **BTstack** (Bluetooth Classic / AVRCP): CVE-2026-28526, CVE-2026-28527, CVE-2026-28528
- **libcoap** (CoAP / OSCORE): CVE-2026-29013
- **miniupnpd** (UPnP / SOAP): CVE-2026-5720

All five were found using the same AI-assisted analysis methodology. All five involve memory safety issues triggerable from the local network — no internet access required.

The post is structured as follows: we first introduce each protocol and its library, then walk through the five CVEs grouped by library — BTstack, libcoap, miniupnpd — and close with the common patterns across all five findings and practical takeaways.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/embedded-proto-overview.svg" alt="Overview of the three affected protocol stacks" style="width:100%;height:auto;display:block">

Every finding in this post is classified as **Adjacent Network** — meaning the attacker must be on the same local network as the target, or within Bluetooth range. The attacker does not need to reach the device from the internet. For the Bluetooth findings specifically, the requirement is stricter: the attacker's device must have already completed Bluetooth **pairing** with the target (a process that typically requires user confirmation or a shared PIN). In practice, "adjacent network" describes scenarios like: a shared Wi-Fi network at a café or office, a Bluetooth device within 10 metres, a compromised device already on a home network, or any internal network segment.

---

## Background: What Are These Protocols?

### Bluetooth AVRCP and BTstack

**AVRCP (Audio/Video Remote Control Profile)** is a Bluetooth Classic profile — a standardised specification that defines how Bluetooth is used for a particular purpose, such as file transfer, audio streaming, or in this case media remote control — for controlling playback between devices. When you press pause on a Bluetooth headset and your phone pauses, that is AVRCP. AVRCP also includes a **Browsing** sub-profile: when a car stereo browses your phone's music library over Bluetooth — listing folders, albums, and tracks — that is AVRCP Browsing. The Browsing sub-profile is separate from basic remote control and has its own set of command handlers. (This distinction matters because the vulnerabilities below affect both the standard AVRCP command handlers and the Browsing handlers — CVE-2026-28528 specifically targets the Browsing side.)

All AVRCP data travels over **L2CAP** (Logical Link Control and Adaptation Protocol) — the transport layer in Bluetooth Classic that segments data into packets and delivers each packet's payload to the appropriate profile handler, such as AVRCP.

**BTstack** is an open-source Bluetooth protocol stack by BlueKitchen GmbH, designed for resource-constrained embedded systems — microcontrollers and IoT devices where a full Linux Bluetooth stack would be impractical. It is used in a wide variety of commercial products.

### CoAP and libcoap

**CoAP (Constrained Application Protocol)**, defined in RFC 7252 (a formal protocol specification published by the Internet Engineering Task Force), is HTTP designed for resource-constrained devices — microcontrollers, sensors, smart meters. It uses UDP (a lightweight transport protocol that sends messages without establishing a persistent connection) instead of TCP (the connection-oriented transport used by HTTP), has a much smaller message format, and targets environments with limited memory, bandwidth, and power.

**OSCORE (Object Security for Constrained RESTful Environments)** is a security layer for CoAP, providing end-to-end encryption and authentication at the application layer — similar in concept to TLS but designed for very constrained environments.

**libcoap** is the reference C library implementing CoAP and OSCORE, used in IoT devices, routers, and industrial control systems.

### UPnP and miniupnpd

**UPnP (Universal Plug and Play)** allows devices on a local network to automatically discover and configure each other. The most familiar use case is automatic port forwarding: a game or torrent client asks the router to open a port without requiring the user to log in and configure it manually.

**miniupnpd** is a widely used open-source UPnP Internet Gateway Device (IGD) daemon. It runs on home routers and embedded Linux systems, handling UPnP requests from devices on the local network over a SOAP-based HTTP interface.

---

## BTstack (Bluetooth AVRCP) — CVE-2026-28526, CVE-2026-28527, CVE-2026-28528

### What Is an Out-of-Bounds Read?

When a function processes a network packet, it is given a **buffer** — a block of memory containing the packet's bytes — and a **length** indicating how many valid bytes that buffer holds.

An out-of-bounds read happens when code reads bytes beyond the end of that buffer. The consequences range from a crash (if the accessed memory is unmapped) to information disclosure (the attacker receives memory contents from outside the packet, potentially including data from other buffers or internal data structures).

These three vulnerabilities were found in the same codebase, in the same component, sharing the same root-cause pattern. This is the most direct illustration of why finding one vulnerability in a protocol handler is a signal to examine the surrounding handlers: if the bug is structural, it tends to repeat.

### The Shared Root Cause

AVRCP responses often include a "count" field: a single byte indicating how many attributes or items follow in the same packet. The expected handling pattern is:

1. Read the count from the first byte of the payload
2. **Verify** that `count × (bytes per item)` bytes remain in the packet
3. Loop `count` times, reading each item

The vulnerability is the missing step 2. Without that check, an attacker with a paired Bluetooth Classic connection can send a crafted AVRCP response with a count value exceeding the actual packet data. The handler reads the count, starts looping, and immediately reads bytes that do not belong to the packet.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/btstack-avrcp-oob.svg" alt="BTstack AVRCP out-of-bounds read pattern — all three CVEs share this structure" style="width:100%;height:auto;display:block">

**Impact (all three CVEs):** All three vulnerabilities require a paired Bluetooth Classic connection — an attacker must have previously completed the Bluetooth pairing process with the target device. The impact is an out-of-bounds read from the L2CAP receive buffer: depending on memory layout, this may crash the device (denial of service) or leak a small number of bytes from adjacent memory.

### CVE-2026-28526 — LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES and _VALUES

**Affected:** BTstack &lt; 1.8.1 | **CWE:** 125 | **CVSS 4.0:** 2.1 (Low) | **Date:** 2026-03-30

The AVRCP Controller handles `LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES` and `LIST_PLAYER_APPLICATION_SETTING_VALUES` responses. These commands ask the target device to enumerate what audio settings (equaliser mode, repeat mode, etc.) it supports and what values each setting can take.

The handler reads `num_attributes` from the first byte of the payload, then iterates that many times reading one byte per attribute — without verifying that those bytes exist in the packet. The code does clamp the count using `btstack_min()` to a maximum of 5 (via the constant `AVRCP_PLAYER_APPLICATION_SETTING_ATTRIBUTE_ID_RFU`, where RFU stands for "Reserved for Future Use" — there are only 4 defined attribute IDs in the AVRCP specification, so 5 is the first reserved value). However, clamping to 5 is **not** the fix: if the packet body contains zero attribute bytes, the loop still reads 5 bytes beyond the end of the buffer. The actual fix requires checking that those bytes exist in the packet before reading them.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Vulnerable: missing boundary check before loop (BTstack < 1.8.1)</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// Simplified — BTstack before v1.8.1&#10;// Handler processes LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES response.&#10;// First byte of payload = number of attributes that follow.&#10;&#10;uint8_t num_attributes = (uint8_t)btstack_min(packet[pos++],&#10;                              AVRCP_PLAYER_APPLICATION_SETTING_ATTRIBUTE_ID_RFU);&#10;&#10;// AVRCP_PLAYER_APPLICATION_SETTING_ATTRIBUTE_ID_RFU == 5&#10;// (valid attribute IDs: Equalizer=1, Repeat=2, Shuffle=3, Scan=4)&#10;// btstack_min() caps num_attributes at 5 — but that is NOT the fix.&#10;//&#10;// BUG: even after clamping to 5, no check that 5 bytes remain in the packet.&#10;// Attacker sends any count byte (clamped to 5) with zero attribute payload.&#10;// The loop reads 5 bytes beyond the end of the packet buffer.&#10;for (i = 0; i &lt; num_attributes; i++){&#10;    uint8_t attr_id = packet[pos++]; // reads up to 5 bytes BEYOND the buffer&#10;    event[offset++] = attr_id;&#10;}</pre></div>

An attacker paired with a Bluetooth device can send a `LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES` response where the count byte is set to any value (e.g., 200), but the packet body contains zero attribute bytes. The `btstack_min()` call clamps the count to 5, but since the packet has no attribute payload at all, the loop still reads 5 bytes beyond the end of the L2CAP receive buffer (L2CAP is the data transport layer in Bluetooth Classic that delivers packet payloads to the AVRCP handler). The clamping limits the over-read to 5 bytes rather than 200, but does not prevent it — the actual fix requires checking that those 5 bytes exist in the packet before reading them.

### CVE-2026-28527 — GET_PLAYER_APPLICATION_SETTING_ATTRIBUTE_TEXT and _VALUE_TEXT

**Affected:** BTstack &lt; 1.8.1 | **CWE:** 125 | **CVSS 4.0:** 2.1 (Low) | **Date:** 2026-03-30

These commands retrieve the human-readable text descriptions of player application settings — for example, the strings "Off", "Single", "All" for the repeat mode setting. Each entry in the response has a 4-byte fixed header (attribute ID and character set ID) plus a variable-length string.

The handler reads the count of entries, then loops over each one reading the string length and copying that many bytes — without verifying that the packet actually contains those bytes before reading them. An attacker sends a crafted AVRCP response with a count value exceeding the packet's actual content, triggering reads from beyond the packet boundary.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Vulnerable: per-entry reads without boundary checks (BTstack < 1.8.1)</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// Simplified — BTstack before v1.8.1&#10;// GET_PLAYER_APPLICATION_SETTING_ATTRIBUTE_TEXT response handler.&#10;// Returns human-readable names for each setting (e.g., 'Repeat Mode').&#10;// Each entry: 1 byte attr ID + 2 bytes charset ID + 1 byte str len + N bytes string.&#10;&#10;uint8_t num_attributes = (uint8_t)btstack_min(packet[pos++],&#10;                              AVRCP_PLAYER_APPLICATION_SETTING_ATTRIBUTE_ID_RFU); // max 5&#10;&#10;for (i = 0; i &lt; num_attributes; i++){&#10;    event[offset++] = packet[pos++];          // attr ID       (1 byte)&#10;    memcpy(&amp;event[offset], &amp;packet[pos], 2);  // charset ID    (2 bytes)&#10;    pos += 2; offset += 2;&#10;    uint8_t value_len = (uint8_t)btstack_min(packet[pos++], MAX_STRING_SIZE);&#10;    memcpy(&amp;event[offset], &amp;packet[pos], value_len); // string (N bytes)&#10;    pos += value_len;&#10;    // BUG: no boundary check at any step above.&#10;    // Attacker sends count=5 with zero payload bytes — first iteration&#10;    // reads 1+2+1+N bytes past the end of the packet buffer.&#10;}</pre></div>

### CVE-2026-28528 — GET_FOLDER_ITEMS (AVRCP Browsing Target)

**Affected:** BTstack &lt; 1.8.1 | **CWE:** 125, 758 | **CVSS 4.0:** 2.1 (Low) | **Date:** 2026-03-30

This CVE affects the **AVRCP Browsing** sub-profile mentioned in the Background section — the separate set of command handlers that let a controller (e.g., a car stereo) browse a target device's media library. The `GET_FOLDER_ITEMS` command lets the controller request specific attributes of items in a folder.

This handler has two separate issues:

**Issue 1 — Missing boundary check:** `attr_count × 4` bytes are consumed in a loop without first checking that those bytes exist in the packet.

**Issue 2 — Undefined behaviour on shift:** Each `attr_id` value from the packet is used as a bit-shift amount: `1 << attr_id`. A **left shift** (`<<`) moves the bit pattern of a number to the left by N positions, which is equivalent to multiplying by 2^N — so `1 << 3` equals 8 and `1 << 7` equals 128. Here the result is OR'd into `attr_bitmap` — a **bitmask** (a data structure where each bit represents whether a particular attribute ID is present).

The problem is that in C, shifting a 32-bit integer by 32 or more bits triggers **undefined behaviour** — a state where the C standard places no requirements on what happens. The program might crash, silently corrupt memory, or behave differently on different compilers and CPUs. An attacker sending `attr_id = 40` triggers exactly this. On x86/x86-64 processors (commonly used for development and testing, and also present in some embedded platforms), the processor applies the shift amount modulo 32, so `1 << 40` executes as `1 << 8 = 256`, silently setting bit 8 rather than bit 40 — corrupting the attribute bitmap and causing incorrect tracking of subsequent AVRCP state. On ARM and other architectures commonly found in BTstack's embedded targets, the result may differ.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Vulnerable: two issues in GET_FOLDER_ITEMS (BTstack < 1.8.1)</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// CVE-2026-28528 — GET_FOLDER_ITEMS handler (Browsing Target)&#10;// Two separate issues in the same function:&#10;&#10;// Issue 1: attr_count * 4 bytes consumed without any boundary check&#10;uint8_t attr_count = packet[pos++];&#10;while (attr_count){&#10;    uint32_t attr_id = big_endian_read_32(packet, pos); // reads 4 bytes big-endian (most significant byte first); no bounds check&#10;    pos += 4;&#10;    // Issue 2: if attr_id &gt;= 32, left-shift is undefined behaviour in C&#10;    browsing_connection-&gt;attr_bitmap |= (1 &lt;&lt; attr_id);&#10;    attr_count--;&#10;}</pre></div>

### The Fix in v1.8.1

BlueKitchen fixed all three CVEs in BTstack v1.8.1 by introducing a `have_bytes()` helper and inserting boundary checks at every point where a count or length field is read from the packet.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — New helper function (v1.8.1)</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// New helper function added in v1.8.1&#10;// Returns true only if 'bytes_needed' bytes exist between pos and end.&#10;static bool avrcp_controller_have_bytes(uint16_t pos, uint16_t end,&#10;                                         uint16_t bytes_needed){&#10;    // (uint16_t) cast prevents implicit promotion to signed int during subtraction&#10;    return (pos &lt;= end) &amp;&amp; (bytes_needed &lt;= (uint16_t)(end - pos));&#10;}</pre></div>

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Fixed handler pattern: boundary check before loop</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// Fixed handler (v1.8.1) — same pattern applied to all affected handlers&#10;uint8_t num_attributes_raw;&#10;&#10;// Step 1: verify that at least 1 byte exists before reading the count field&#10;if (!avrcp_controller_have_bytes(pos, payload_end, 1u)) return;&#10;num_attributes_raw = packet[pos++];&#10;&#10;// Step 2: verify that 'num_attributes_raw' bytes exist BEFORE looping&#10;if (!avrcp_controller_have_bytes(pos, payload_end, num_attributes_raw)) return;&#10;&#10;// Now safe to iterate — data is confirmed present&#10;uint8_t num_attributes = (uint8_t)btstack_min(num_attributes_raw,&#10;                              AVRCP_PLAYER_APPLICATION_SETTING_ATTRIBUTE_ID_RFU);&#10;for (i = 0; i &lt; num_attributes; i++){&#10;    uint8_t attr_id = packet[pos++]; // guaranteed within bounds&#10;    event[offset++] = attr_id;&#10;}</pre></div>

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Fixed GET_FOLDER_ITEMS: boundary check + range guard on shift</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// v1.8.1 fix — GET_FOLDER_ITEMS&#10;// The Browsing Target side gets its own identical helper:&#10;// avrcp_browsing_target_have_bytes() — same logic as avrcp_controller_have_bytes()&#10;// Verify attr_count * 4 bytes exist BEFORE reading any of them&#10;if (!avrcp_browsing_target_have_bytes(pos, payload_end,&#10;                                       (uint16_t)(4u * attr_count))){&#10;    avrcp_browsing_target_response_general_reject(browsing_connection,&#10;                                                  AVRCP_STATUS_INVALID_COMMAND);&#10;    break;&#10;}&#10;while (attr_count){&#10;    uint32_t attr_id = big_endian_read_32(packet, pos);&#10;    pos += 4;&#10;    // Guard: only allow shift amounts 0..31 (C requires shift &lt; type width)&#10;    if (attr_id &lt; 32) {&#10;        browsing_connection-&gt;attr_bitmap |= (1 &lt;&lt; attr_id);&#10;    }&#10;    attr_count--;&#10;}</pre></div>

The defensive pattern is consistent: for every count or length field arriving from the network, verify that the corresponding data exists in the packet before trusting the value.

---

## libcoap (CoAP / OSCORE) — CVE-2026-29013

**Affected:** libcoap &lt; v4.3.5b | **CWE:** 125 | **CVSS:** 8.8 (High) | **Date:** 2026-04-17

This finding has a different character from the BTstack cases. The bug is not a missing bounds check in a loop — it is a bounds check that exists, but only works in debug builds.

### The assert() Problem in C

In C and C++, `assert()` is a debugging macro. When a program is compiled in **debug mode**, `assert(condition)` evaluates the condition at runtime. If the condition is false, the program crashes with an error message — which is very useful during development because it surfaces bugs immediately.

When a program is compiled for **production**, it is typically built with the `-DNDEBUG` preprocessor flag. The **preprocessor** is a step that runs before the actual compiler, scanning the source code and performing text substitutions based on definitions — `-DNDEBUG` tells it to define the symbol `NDEBUG`, which `assert.h` uses as a signal to strip out all `assert()` calls. When `NDEBUG` is defined, the C standard requires that every `assert()` in the entire program be replaced by a no-op (an instruction that does nothing) and completely removed. The stated rationale is performance: no runtime overhead in production. The consequence is that any code that relied solely on `assert()` for a safety check now has **no safety check at all** in the version that ships to users.

<img src="{{ site.url }}{{ site.baseurl }}/assets/svg/libcoap-assert-ndebug.svg" alt="assert() behaviour in debug vs release builds — same source code, completely different runtime behaviour" style="width:100%;height:auto;display:block">

### The Specific Issue in libcoap

Before explaining the internal mechanics, here is the high-level attack path: an attacker can send crafted CoAP requests with malformed OSCORE options over the network. OSCORE option parsing runs as part of incoming message processing **before** a full security context is established — meaning a remote peer can trigger this code path without having completed authenticated key exchange. No authentication is required.

Internally, the function `coap_insert_option()` in `src/coap_pdu.c` walks the option list to find the correct insertion position. The internal bookkeeping field `max_opt` tracks the highest option number currently stored in the PDU (Protocol Data Unit — the structured object representing a CoAP message in memory). If `max_opt` is inconsistent with the actual option list, the walk terminates without finding the insertion point, and the variable `option` remains NULL (a special value in C meaning "this pointer points nowhere", used to represent the absence of a valid address).

This inconsistent state can occur when `coap_pdu_resize()` is called to reduce the PDU's allocated size below the amount already used — a condition that an attacker can induce via the malformed OSCORE option fields described above, which cause the PDU to be resized to a smaller allocation than its current content requires.

Before the patch, the only safety check at this point was:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Vulnerable: assert() as the sole bounds check, removed by NDEBUG in release builds</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// coap_insert_option() in src/coap_pdu.c — before the fix&#10;// The function walks the option list to find the insertion point ('option').&#10;// If 'option' is NULL, the bookkeeping field max_opt is inconsistent.&#10;&#10;// THE ONLY SAFETY CHECK — only works in debug builds:&#10;assert(option != NULL);&#10;&#10;// When compiled with -DNDEBUG (standard for release/production builds),&#10;// the preprocessor removes this line entirely. Execution falls through&#10;// to code that reads from the NULL pointer, causing an OOB memory access.</pre></div>

In a debug build, the assert fires when `option` is NULL, the program terminates, and the developer investigates. In a release build compiled with `-DNDEBUG` — standard for shipping firmware and software — the assert line does not exist. Execution continues past the check, and the code below passes the NULL `option` pointer to `coap_opt_encode_size()`. On most platforms, dereferencing a NULL pointer causes an immediate crash, but here the pointer is not dereferenced directly — it is first used in offset arithmetic that produces a non-NULL but invalid address, which the function then reads from. The result is an out-of-bounds memory access rather than a clean crash — exactly the condition the assert was meant to prevent.

### The Fix

The patch replaces `assert()` with an explicit runtime check that works in all build configurations:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Fixed: explicit if/return that works in debug and release builds</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// After the fix — coap_insert_option() in src/coap_pdu.c&#10;// Explicit runtime check works in ALL build configurations,&#10;// including release builds compiled with -DNDEBUG.&#10;&#10;if (option == NULL) {&#10;    /* Code is broken somewhere — max_opt is inconsistent */&#10;    coap_log_warn("coap_insert_option: Broken max_opt\n");&#10;    return 0;  // return safely; caller handles the error&#10;}&#10;// Only reached if option is valid — safe to continue</pre></div>

### A Note on Analysis Methodology

This vulnerability illustrates a rule for C/C++ security analysis: **`assert()` calls are not bounds checks.** Any security property that depends on `assert()` is absent in the release build. When reviewing a codebase, any `assert()` that validates externally-supplied data — packet lengths, array indices derived from network input, pointer values set from parsed data — should be flagged for replacement with proper runtime error handling.

---

## miniupnpd (UPnP) — CVE-2026-5720

**Affected:** miniupnpd &lt; 2.3.10 | **CWE:** 191 (Integer Underflow) | **CVSS 4.0:** 8.3 (High) | **Date:** 2026-04-17

### What Is Integer Underflow?

Numbers in computers are stored in a fixed number of bits. An **unsigned** integer (one that cannot be negative) on a 32-bit system holds values from 0 to 4,294,967,295. If you subtract 1 from 0 using unsigned arithmetic, the result does not become −1 — unsigned types cannot hold negative values. Instead, the result **wraps around** to 4,294,967,295. This is called **integer underflow** (CWE-191).

The danger is that the resulting very large value is then used as a buffer size, memory allocation size, or loop count — treating a logical error as a legitimately large quantity, causing reads or writes far beyond any intended boundary.

Readers familiar with CVE-2026-25075 (the strongSwan IKEv2 integer underflow covered in [an earlier post](https://y637f9qq2x.github.io/github.io/posts/cve-2026-25075/)) will recognise the same pattern: an attacker-controlled value enters arithmetic that underflows to a large unsigned number, which is then used to access memory well beyond a valid buffer.

### The Vulnerability in miniupnpd

UPnP devices communicate with the router using SOAP (Simple Object Access Protocol — a standard way to call remote functions by sending XML messages over HTTP) over HTTP. A SOAP request includes a `SOAPAction` header identifying which action is being requested. A well-formed value looks like:

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">HTTP</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"</pre></div>

The value is enclosed in double quotes. The `ParseHttpHeaders()` function processes this header by finding the opening and closing quotes, then computing the content length between them.

The bug involves two steps. First, understanding **pointer arithmetic** in C: when you subtract one pointer from another, the result is the number of bytes between them. So `p_end - p_start` gives the length of the string between the two pointers.

Now, the problem: if the input contains only one double quote (a malformed or deliberately crafted request), there is no closing quote to find. The C function `strchr()` — which scans a string for a specific character and returns a pointer to the first match, or NULL if not found — returns NULL for the closing quote. Subtracting a valid pointer from NULL is technically **undefined behaviour** in C (the language standard places no requirements on what happens). In practice on most platforms, NULL is treated as address zero, and the subtraction wraps around — producing a value close to the maximum of `size_t` (the C type used to represent memory sizes and lengths as an unsigned integer — on a 32-bit system, its maximum value is approximately 4.3 billion).

The following code block also uses `memchr(ptr, c, n)`, a companion to `strchr()` that does the same character search but over exactly `n` bytes of raw memory rather than a null-terminated string. It takes three arguments: a start address, the character to search for, and the maximum number of bytes to scan. In this bug, that third argument receives the underflowed value — telling `memchr()` to scan billions of bytes.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Integer underflow in ParseHttpHeaders() SOAPAction parsing</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// Conceptual illustration of the integer underflow in miniupnpd&#10;//&#10;// A well-formed SOAPAction value looks like (enclosed in double quotes):&#10;//   "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"&#10;//&#10;// ParseHttpHeaders() finds the opening and closing quotes:&#10;&#10;const char *p_start = strchr(value, '"');       // finds opening quote: OK&#10;const char *p_end   = strchr(p_start + 1, '"'); // finds closing quote&#10;&#10;// If input has only ONE quote, p_end is NULL.&#10;// Pointer arithmetic involving NULL is undefined behaviour in C.&#10;// On most platforms in practice, it wraps to a value close to SIZE_MAX (~4 billion on 32-bit):&#10;&#10;size_t action_len = (size_t)(p_end - p_start - 1);&#10;// e.g. p_start=0x7fff1000, p_end=NULL(0x0):&#10;// action_len = (size_t)(0 - 0x7fff1000 - 1) ≈ 0x80000000  (~2 GB on a 32-bit system)&#10;&#10;// This enormous value is passed directly to memchr():&#10;char *hash = memchr(value, '#', action_len);&#10;// memchr() scans ~2 GB of memory — far beyond the allocated buffer.</pre></div>

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">HTTP — Malformed request that triggers the bug (single quote, no closing quote)</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">POST /control HTTP/1.1&#10;Host: 192.168.1.1:1900&#10;Content-Type: text/xml; charset="utf-8"&#10;SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping&#10;Content-Length: 0&#10;&#10;(Note: the SOAPAction line opens with a double-quote but has no closing quote.&#10; ParseHttpHeaders() receives a string with exactly one double-quote character.)</pre></div>

### Impact

The enormous underflowed value is passed to `memchr()`, which scans memory far beyond the allocated HTTP request buffer — specifically, it calls `memchr(value, '#', action_len)` looking for the `#` character that separates the service name from the action name. The primary impact is denial of service: miniupnpd crashes and UPnP port mapping becomes unavailable until the daemon is restarted. Whether any memory contents are observable to the attacker depends on the memory layout of the specific build and platform — information disclosure is conceivable in principle but is not reliably reproducible.

### Fix

The fix validates that a closing double-quote actually exists before performing the pointer subtraction. If `strchr()` returns NULL for the closing quote, the function rejects the header rather than proceeding with an invalid length computation.

<div style="background:var(--highlight-bg-color,#282a36);border-radius:.375rem;margin:.9rem 0;overflow:hidden"><div style="display:flex;align-items:center;justify-content:space-between;padding:.35rem .9rem;border-bottom:1px solid rgba(255,255,255,.08)"><span style="font-size:.73rem;color:rgba(255,255,255,.45);font-family:monospace;letter-spacing:.05em">C — Fixed: NULL check before pointer subtraction</span><button onclick="var p=this.closest('div').querySelector('pre');navigator.clipboard.writeText(p.innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',2000)})" style="background:none;border:1px solid rgba(255,255,255,.3);color:rgba(255,255,255,.6);cursor:pointer;font-size:.7rem;padding:.15rem .45rem;border-radius:.2rem;font-family:sans-serif">Copy</button></div><pre style="margin:0;padding:1rem 1.5rem;color:var(--highlighter-rouge-color,#f8f8f2);font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;font-size:.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:transparent">// After the fix — ParseHttpHeaders() in miniupnpd&#10;// Check that the closing quote actually exists before computing length.&#10;&#10;const char *p_start = strchr(value, '"');&#10;if (p_start == NULL) return;  // no opening quote — reject&#10;&#10;const char *p_end = strchr(p_start + 1, '"');&#10;if (p_end == NULL) return;    // no closing quote — reject (prevents underflow)&#10;&#10;// Only reached if both quotes exist — subtraction is now safe&#10;size_t action_len = (size_t)(p_end - p_start - 1);</pre></div>

---

## What These Five Findings Have in Common

**Adjacent-only attack surface.** None of these vulnerabilities can be triggered from the internet directly. They all require the attacker to be on the local network or within Bluetooth range. This is narrower than internet-facing vulnerabilities, but it is realistic in many scenarios: corporate internal networks, shared Wi-Fi, compromised devices already inside the network, or physical Bluetooth proximity.

**C/C++ with unsafe arithmetic on network-supplied values.** All three libraries are implemented in C. In BTstack and miniupnpd, the failure is the absence of validation: values arriving from the network — count fields, length fields, index values — are used in arithmetic or as loop bounds without verifying that the derived quantity stays within a valid buffer. In libcoap, the validation exists but only in debug builds: an `assert()` check is stripped out by the preprocessor in production, leaving the same unprotected code path. The common thread is that network-supplied values reach memory operations without a runtime safety check in the code that actually ships.

**Limited security auditing relative to deployment footprint.** IoT and embedded protocol stacks reach tens of millions of devices, but receive significantly less security review than web-facing software. Many predate modern secure coding tools and practices. The same analysis methodology that works on high-profile targets tends to produce more findings on this class of software because the audit density is lower.

**One finding leads to adjacent findings.** The three BTstack CVEs came from applying the same question to each handler in the AVRCP component in turn: does this handler verify packet boundaries before trusting count or length fields from the packet? When the answer was no in one place, asking the same question about surrounding code immediately identified two more.

---

## Key Takeaways

**Check every count and length field before trusting it.** When a binary protocol handler reads a count or length from a packet, the next operation should verify that `count × item_size` bytes remain in the packet at the current position. This check must happen before any loop, before any indexing, and before any memory operation based on that count.

**`assert()` is not a bounds check — it does not exist in production.** Any `assert()` that validates externally-supplied data is absent in any build compiled with `-DNDEBUG`. Replace it with an explicit `if` check that returns an error code or logs and exits the function safely — rather than proceeding with invalid data. This applies to any C or C++ codebase that processes network input.

**Integer underflow on unsigned types wraps to a very large value.** When computing lengths or offsets from untrusted input, a subtraction that logically produces a negative result will, with unsigned types, produce a very large positive value instead. Any such value used as a buffer length, `memchr()` argument, or loop count causes reads far outside the intended memory region. The fix is explicit bounds checking before the subtraction.

**Adjacent-network attack surfaces deserve more attention.** The assumption that "it is only locally reachable, so it is lower risk" underestimates these vulnerabilities. Embedded and IoT protocol stacks run in routers, automotive infotainment, industrial controllers, and medical equipment. Getting within range of any of these devices — or onto any network they connect to — is a realistic step in many attack scenarios, not a theoretical edge case.

---

## References

[1] VulnCheck Advisory — CVE-2026-28526: https://www.vulncheck.com/advisories/bluekitchen-btstack-avrcp-controller-list-player-application-setting-handlers-oob-read

[2] VulnCheck Advisory — CVE-2026-28527: https://www.vulncheck.com/advisories/bluekitchen-btstack-avrcp-controller-get-player-application-setting-text-handlers-oob-read

[3] VulnCheck Advisory — CVE-2026-28528: https://www.vulncheck.com/advisories/bluekitchen-btstack-avrcp-browsing-target-get-folder-items-handler-oob-read-undefined-behavior

[4] VulnCheck Advisory — CVE-2026-29013: https://www.vulncheck.com/advisories/libcoap-out-of-bounds-read-in-oscore-cbor-unwrap-handling

[5] VulnCheck Advisory — CVE-2026-5720: https://www.vulncheck.com/advisories/miniupnpd-integer-underflow-soapaction-header-parsing

[6] BTstack v1.8.1 Release: https://github.com/bluekitchen/btstack/releases/tag/v1.8.1

[7] libcoap patch commit (CVE-2026-29013): https://github.com/obgm/libcoap/commit/b7847c4dbb0dbee7c90b09a673d4cae256f03718

[8] CWE-125: Out-of-bounds Read: https://cwe.mitre.org/data/definitions/125.html

[9] CWE-191: Integer Underflow (Wrap or Wraparound): https://cwe.mitre.org/data/definitions/191.html

---

If any part of this analysis is useful as a reference for your own work, that is the intended outcome.
