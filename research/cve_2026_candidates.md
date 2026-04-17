# CVE-2026 Candidates for Naptrace Benchmark Corpus

Research compiled: 2026-04-17

This document catalogs CVEs published in 2026 (January-April) with public patches,
known variant relationships, and suitability for Naptrace variant analysis benchmarks.

---

## 1. Django SQL Injection in RasterField Lookups

- **CVE ID:** CVE-2026-1207
- **Project:** Django
- **Repo:** https://github.com/django/django
- **Language:** Python
- **Bug class:** SQL injection (CWE-89)
- **Severity:** High
- **Published:** 2026-02-03
- **Description:** Remote attackers can inject SQL via the band index parameter in
  RasterField lookups on PostGIS. The flaw resides in how Django processes the band
  index parameter during raster lookups, allowing SQL injection when user-controlled
  input is passed without proper sanitization.
- **Patch commits:**
  - Main: `81aa5292967cd09319c45fe2c1a525ce7b6684d8`
  - [6.0.x]: `8f77e7301174834573614ae90e1826fdf27f8a24`
  - [5.2.x]: `17a1d64a58ef24c0c3b78d66d86f5415075f18f0`
  - [4.2.x]: `a14363102d98fa29b8cced578eb3a0fadaa5bcb7`
- **Variant relationship:** Structural twin of CVE-2026-1287 (same Django release,
  same bug class, same researcher). CVE-2026-1287 is SQL injection via control
  characters in FilteredRelation column aliases. Both are parameterization failures
  in the Django ORM. Excellent variant pair.
- **Naptrace suitability:** EXCELLENT -- Two related SQLi CVEs in the same codebase
  from the same release date. Feed one as seed, hunt for the other.

---

## 2. Django SQL Injection in Column Aliases

- **CVE ID:** CVE-2026-1287
- **Project:** Django
- **Repo:** https://github.com/django/django
- **Language:** Python
- **Bug class:** SQL injection (CWE-89)
- **Severity:** High
- **Published:** 2026-02-03
- **Description:** Control characters in FilteredRelation column aliases could be
  used for SQL injection in QuerySet.annotate(), aggregate(), extra(), values(),
  values_list(), and alias() when using dictionary expansion with **kwargs.
- **Patch commits:**
  - Main: `e891a84c7ef9962bfcc3b4685690219542f86a22`
  - [6.0.x]: `0c0f5c2178c01ada5410cd53b4b207bf7858b952`
  - [5.2.x]: `3e68ccdc11c127758745ddf0b4954990b14892bc`
  - [4.2.x]: `f75f8f3597e1ce351d5ac08b6ba7ebd9dadd9b5d`
- **Variant relationship:** Variant of CVE-2026-1207 (same Django release, same
  insufficient parameterization pattern). Both are in the Django ORM query
  construction layer.
- **Naptrace suitability:** EXCELLENT -- Natural variant pair with CVE-2026-1207.

---

## 3. OpenSSL CMS AuthEnvelopedData Stack Buffer Overflow

- **CVE ID:** CVE-2025-15467
- **Project:** OpenSSL
- **Repo:** https://github.com/openssl/openssl
- **Language:** C
- **Bug class:** Stack buffer overflow (CWE-121)
- **Severity:** Critical (CVSS 9.8)
- **Published:** 2026-01-27
- **Description:** Stack buffer overflow in CMS AuthEnvelopedData parsing where
  the initialization vector (IV) is copied into a fixed-size stack buffer without
  proper length validation when processing AEAD ciphers like AES-GCM. First RCE-
  severity OpenSSL CVE since CVE-2022-3602.
- **Patch commits:**
  - `2c8f0e5fa9b6ee5508a0349e4572ddb74db5a703`
  - `5f26d4202f5b89664c5c3f3c62086276026ba9a9`
  - `6ced0fe6b10faa560e410e3ee8d6c82f06c65ea3`
  - `ce39170276daec87f55c39dad1f629b56344429e`
  - `d0071a0799f20cc8101730145349ed4487c268dc`
- **Variant relationship:** Part of a family of 12 OpenSSL vulnerabilities all
  discovered by AISLE's autonomous analyzer and disclosed in the same January 2026
  coordinated release. CVE-2025-11187 (PKCS#12 PBMAC1 buffer overflow) is a
  structural twin -- same bug class (buffer overflow during crypto message parsing),
  same codebase area (CMS/PKCS handling). Additional low-severity variants:
  CVE-2025-15468, CVE-2025-15469, CVE-2026-22795, CVE-2026-22796.
- **Naptrace suitability:** EXCELLENT -- 12 related vulns in the same codebase,
  multiple are structural variants of each other. C code, memory safety bugs.
  Perfect for Naptrace CPG analysis.

---

## 4. Linux Kernel ksmbd Use-After-Free (SMB3 Multi-Channel)

- **CVE ID:** CVE-2026-23226
- **Project:** Linux kernel (ksmbd)
- **Repo:** https://git.kernel.org/ (also mirrored at github.com/torvalds/linux)
- **Language:** C
- **Bug class:** Use-after-free (CWE-416)
- **Severity:** High (CVSS 8.8)
- **Published:** 2026-02-16
- **Description:** Missing synchronization lock in ksmbd multi-channel session
  management. The ksmbd_chann_list xarray is accessed without locking, creating a
  race condition between lookup_chann_list() (retrieves channel pointer) and
  ksmbd_chann_del() (removes and frees channel object). Authenticated network
  attacker can trigger memory corruption for code execution or kernel panic.
- **Patch:** Committed by Greg KH on 2026-02-16. Fix adds rw_semaphore
  (chann_lock) to struct ksmbd_session protecting all xarray accesses.
- **Variant relationship:** Part of a family of ksmbd vulnerabilities.
  CVE-2026-23228 (connection accounting leak) is a related ksmbd bug from the
  same disclosure window. Historical variants: CVE-2023-32256 (ksmbd race
  condition), CVE-2025-21945 (ksmbd UAF). All share the pattern of missing
  synchronization in ksmbd session/connection handling.
- **Naptrace suitability:** EXCELLENT -- Multiple historical variants in the same
  subsystem. Classic UAF via race condition pattern. C kernel code with CPG-
  amenable interprocedural flows.

---

## 5. Linux Kernel Netfilter Vulnerability Family (5+ CVEs)

- **CVE IDs:**
  - CVE-2026-31414 (conntrack expectations helper lookup)
  - CVE-2026-31407 (conntrack netlink validation, OOB access)
  - CVE-2026-31416 (nfnetlink_log message loss)
  - CVE-2026-31418 (ipset bucket cleanup, privilege escalation)
  - CVE-2026-31424 (NULL pointer deref in ARP filtering / nft_compat)
  - CVE-2026-23457 (netfilter, resolved in kernel)
- **Project:** Linux kernel (netfilter subsystem)
- **Repo:** https://git.kernel.org/
- **Language:** C
- **Bug class:** Mixed -- NULL deref, OOB access, improper validation, UAF
- **Severity:** High (CVE-2026-31414 CVSS 7.0, others similar)
- **Published:** March-April 2026
- **Description:** A cluster of netfilter vulnerabilities disclosed in 2026 affecting
  connection tracking, ipset, nfnetlink_log, and compat layers. CVE-2026-31414 fixes
  unsafe helper lookup in nf_conntrack_expect. CVE-2026-31407 exposes OOB memory
  access via SCTP and ctnetlink handling. CVE-2026-31424 crashes systems via NULL
  pointer deref when handling ARP filtering rules.
- **Patch:** Kernel versions 6.1-6.10 affected; patches backported to stable branches.
- **Variant relationship:** These are structural variants of each other -- all in the
  netfilter subsystem, all involving insufficient validation or missing
  synchronization in connection tracking or packet filtering code. The netfilter
  subsystem has been a persistent source of kernel CVEs for years (see also
  CVE-2022-25636, CVE-2023-0179, CVE-2024-1086 historically).
- **Naptrace suitability:** EXCELLENT -- Large family of related bugs in the same
  kernel subsystem. Ideal for demonstrating variant hunting at scale.

---

## 6. Chrome Dawn (WebGPU) Use-After-Free Family

- **CVE IDs:**
  - CVE-2026-5281 (Dawn UAF, actively exploited zero-day)
  - CVE-2026-4676 (Dawn UAF, sandbox escape)
  - CVE-2026-5284 (Dawn UAF)
  - CVE-2026-4675 (WebGL heap buffer overflow)
  - CVE-2026-5860 (WebRTC UAF)
  - CVE-2026-5861 (V8 UAF)
- **Project:** Chromium / Google Chrome
- **Repo:** https://chromium.googlesource.com/chromium/src
- **Language:** C++
- **Bug class:** Use-after-free (CWE-416), heap buffer overflow (CWE-122)
- **Severity:** High (CVSS 8.8 for most)
- **Published:** March-April 2026
- **Description:** A cluster of UAF vulnerabilities in Chrome's Dawn WebGPU
  implementation, all reported by the same pseudonymous researcher. CVE-2026-5281
  was actively exploited in the wild and added to CISA KEV catalog. Three Dawn
  UAFs in a single release indicates systematic lifetime mishandling in the
  WebGPU object model. CVE-2026-4676 allows sandbox escape.
- **Patch:** Chrome 146.0.7680.165 (CVE-2026-4676), Chrome 146.0.7680.178
  (CVE-2026-5281, CVE-2026-5284)
- **Variant relationship:** All three Dawn UAFs are structural variants -- same
  component, same bug class, same root cause pattern (object lifetime
  mismanagement in Dawn's GPU command buffer/resource handling). The WebRTC
  and V8 UAFs (CVE-2026-5860, CVE-2026-5861) are UAFs in different Chrome
  components -- broader variant family for the UAF pattern.
- **Naptrace suitability:** HIGH -- Strong variant family but Chromium's build
  system complexity makes CPG generation challenging. Still excellent for
  demonstrating the concept.

---

## 7. AppArmor "CrackArmor" Privilege Escalation Family (9 CVEs)

- **CVE IDs:** CVE-2026-23268, CVE-2026-23269, CVE-2026-23403 through
  CVE-2026-23411 (11 patches for 9 vulnerabilities)
- **Project:** Linux kernel (AppArmor LSM)
- **Repo:** https://git.kernel.org/
- **Language:** C
- **Bug class:** Confused deputy / privilege escalation (CWE-441), use-after-free
  (CWE-416), information leak (CWE-200)
- **Severity:** Critical (root escalation), affects 12.6M+ systems
- **Published:** 2026-03-12 (Qualys disclosure)
- **Description:** Nine confused deputy vulnerabilities in AppArmor that allow
  unprivileged local users to bypass kernel protections, escalate to root, and
  break container isolation. CVE-2026-23268: privileged control files writable
  without permission checks. CVE-2026-23269: crafted file matching expressions
  leak up to 64KiB of kernel memory including KASLR addresses. Flaw has existed
  since 2017 (kernel v4.11).
- **Patch:** Linux kernels 6.8.x, 6.6.x LTS, 6.1.x LTS, 5.15.x LTS patched in
  March 2026.
- **Variant relationship:** All nine CVEs are structural variants of each other --
  all exploit the same confused deputy pattern in AppArmor's securityfs interface.
  The pattern: an unprivileged actor manipulates a privileged process to perform
  actions on their behalf through AppArmor's policy management interface.
- **Naptrace suitability:** EXCELLENT -- Nine variants of the same fundamental
  bug class in one subsystem, discovered by Qualys TRU. Perfect for Naptrace
  benchmarking.

---

## 8. Composer Command Injection (Perforce VCS Driver)

- **CVE IDs:**
  - CVE-2026-40176 (command injection via malicious perforce repository, CVSS 7.8)
  - CVE-2026-40261 (command injection via malicious perforce reference, CVSS 8.8)
- **Project:** Composer (PHP dependency manager)
- **Repo:** https://github.com/composer/composer
- **Language:** PHP
- **Bug class:** Command injection (CWE-78)
- **Severity:** High to Critical
- **Published:** April 2026
- **Description:** CVE-2026-40176: Perforce::generateP4Command() interpolates
  user-supplied Perforce connection parameters (port, user, client) into shell
  commands without proper escaping. CVE-2026-40261: insufficient escaping allows
  command injection via crafted source references containing shell metacharacters.
- **Patch:** Fixed in Composer 2.9.6 (mainline) and 2.2.27 (LTS). See
  https://github.com/composer/composer/releases/tag/2.9.6
- **Variant relationship:** CVE-2026-40176 and CVE-2026-40261 are structural
  twins -- both are command injection via the same Perforce VCS driver, both
  caused by insufficient input escaping, but in different code paths
  (generateP4Command vs source reference handling). Historical variant:
  CVE-2024-35241 (Composer command injection in source download).
- **Naptrace suitability:** EXCELLENT -- Two structural twins in the same
  component, same bug class. PHP code is well-supported by tree-sitter.

---

## 9. n8n RCE via Arbitrary File Write

- **CVE ID:** CVE-2026-21877
- **Project:** n8n (workflow automation)
- **Repo:** https://github.com/n8n-io/n8n
- **Language:** TypeScript / JavaScript
- **Bug class:** Arbitrary file write leading to RCE (CWE-22, CWE-94)
- **Severity:** Critical (CVSS 10.0)
- **Published:** 2026 (exact date varies by source)
- **Description:** The Git node fails to properly validate file paths and content,
  enabling authenticated users to write arbitrary files to any location accessible
  by the n8n service. Combined with how n8n processes workflows and nodes, this
  allows attacker-controlled code to be written and later executed.
- **Patch:** Fixed in n8n v1.121.3. Repository path validation added.
  Advisory: GHSA-v364-rw7m-3263
- **Variant relationship:** Path traversal + code execution is a common pattern
  in workflow automation tools. Similar bugs have been found in other automation
  platforms (Jenkins, GitLab CI, GitHub Actions).
- **Naptrace suitability:** GOOD -- Single CVE but the path traversal + code
  execution pattern is generalizable across similar tools. TypeScript/JS support
  needed.

---

## 10. Node.js TLS + HTTP Vulnerabilities

- **CVE IDs:**
  - CVE-2026-21637 (TLS SNICallback exception handling, High)
  - CVE-2026-21710 (HTTP __proto__ header prototype pollution DoS, High)
- **Project:** Node.js
- **Repo:** https://github.com/nodejs/node
- **Language:** C++ / JavaScript
- **Bug class:** Exception handling failure (CWE-755), prototype pollution (CWE-1321)
- **Severity:** High
- **Published:** 2026-03-24
- **Description:** CVE-2026-21637: SNICallback throws synchronously on unexpected
  input, exception bypasses TLS error handlers, crashes process. CVE-2026-21710:
  HTTP request with __proto__ header causes uncaught TypeError when accessing
  req.headersDistinct, crashing the process.
- **Patch commits:**
  - CVE-2026-21637: `df8fbfb93d` (tls: wrap SNICallback in try/catch)
  - CVE-2026-21710: `380ea72eef` (http: use null prototype for headersDistinct)
- **Release:** v24.14.1 (2026-03-24), also v20.20.2, v22.x, v25.x
- **Variant relationship:** Part of a batch of 8 CVEs patched in the March 2026
  Node.js security release. Both are DoS via uncaught exceptions -- structural
  variants of the "missing error handling leads to process crash" pattern.
- **Naptrace suitability:** GOOD -- Two related DoS patterns in the same release.
  Node.js is C++/JS mixed codebase.

---

## 11. snapd Local Privilege Escalation (TOCTOU Race)

- **CVE ID:** CVE-2026-3888
- **Project:** snapd
- **Repo:** https://github.com/canonical/snapd (and snap-confine)
- **Language:** Go / C
- **Bug class:** TOCTOU race condition (CWE-367), privilege escalation
- **Severity:** Important
- **Published:** 2026-03-17 (Qualys disclosure)
- **Description:** Exploits a TOCTOU race condition between snap-confine and
  systemd-tmpfiles. After systemd-tmpfiles cleans up snap's private /tmp
  directory, an attacker recreates it and tricks snap-confine into bind-mounting
  malicious files into the snap sandbox. Requires 10-30 day timing window.
- **Patch:** Ubuntu snapd 2.73+ubuntu24.04.2 and later.
  Advisory: GHSA-grpw-jgrw-ccqr
- **Variant relationship:** Part of the Qualys 2026 Linux privilege escalation
  research (same team that found CrackArmor). TOCTOU race conditions in setuid
  binaries are a well-known bug class with many historical variants (CVE-2019-7304
  snapd, CVE-2021-44731 snap-confine).
- **Naptrace suitability:** GOOD -- TOCTOU race pattern is well-studied with
  historical variants. Mixed Go/C codebase.

---

## 12. Chrome Skia + V8 Zero-Days

- **CVE IDs:**
  - CVE-2026-3909 (Skia OOB write, CVSS 8.8)
  - CVE-2026-3910 (V8 inappropriate implementation, CVSS 8.8)
- **Project:** Chromium / Google Chrome
- **Repo:** https://chromium.googlesource.com/chromium/src
- **Language:** C++ (Skia), C++ (V8)
- **Bug class:** Out-of-bounds write (CWE-787), implementation flaw
- **Severity:** High (both CVSS 8.8), actively exploited
- **Published:** 2026-03-10 (reported), 2026-03-13 (CISA KEV)
- **Description:** CVE-2026-3909 is an out-of-bounds write in the Skia 2D graphics
  library allowing remote code execution via crafted HTML. CVE-2026-3910 is an
  inappropriate implementation in V8 enabling sandbox escape. Both were exploited
  in the wild before patches were available.
- **Patch:** Chrome 146.0.7680.75 (Windows), 146.0.7680.76 (macOS),
  146.0.7680.75 (Linux)
- **Variant relationship:** These two CVEs were patched together but are in
  different components (Skia vs V8). CVE-2026-3909 joins a long line of Skia
  OOB writes in Chrome. CVE-2026-3910 is part of the V8 engine vulnerability
  family.
- **Naptrace suitability:** MODERATE -- Chromium build complexity is a barrier,
  but the vulnerability patterns are highly valuable.

---

## 13. Spring Framework Path Traversal + Security Header Bypass

- **CVE IDs:**
  - CVE-2026-22737 (ScriptTemplateView path traversal, Medium)
  - CVE-2026-22732 (Spring Security response header omission)
- **Project:** Spring Framework / Spring Security
- **Repo:** https://github.com/spring-projects/spring-framework
- **Language:** Java
- **Bug class:** Path traversal (CWE-22), security misconfiguration
- **Severity:** Medium
- **Published:** 2026-03-19/20
- **Description:** CVE-2026-22737: getResource() concatenates resource loader path
  with location parameter without path traversal checks. Attacker who can
  influence template location can read arbitrary files. CVE-2026-22732:
  OnCommittedResponseWrapper silently omits security response headers under
  certain conditions.
- **Variant relationship:** CVE-2026-22737 is a variant of CVE-2025-41242
  (Spring MVC path traversal on non-default servlet containers) and CVE-2024-38819
  (Spring Framework path traversal). All three are path traversal bugs in Spring's
  resource resolution layer. Strong variant family.
- **Naptrace suitability:** GOOD -- Java code, multiple historical variants of
  path traversal in Spring. Tree-sitter Java support available.

---

## Summary Table

| # | CVE ID(s) | Project | Language | Bug Class | Variant Family Size | Suitability |
|---|-----------|---------|----------|-----------|--------------------:|-------------|
| 1 | CVE-2026-1207 | Django | Python | SQL injection | 2+ | EXCELLENT |
| 2 | CVE-2026-1287 | Django | Python | SQL injection | 2+ | EXCELLENT |
| 3 | CVE-2025-15467 | OpenSSL | C | Buffer overflow | 12 | EXCELLENT |
| 4 | CVE-2026-23226 | Linux ksmbd | C | UAF | 4+ | EXCELLENT |
| 5 | CVE-2026-31414 etc. | Linux netfilter | C | Mixed | 6+ | EXCELLENT |
| 6 | CVE-2026-5281 etc. | Chrome Dawn | C++ | UAF | 4+ | HIGH |
| 7 | CVE-2026-23268 etc. | Linux AppArmor | C | Confused deputy | 9 | EXCELLENT |
| 8 | CVE-2026-40176/40261 | Composer | PHP | Cmd injection | 2+ | EXCELLENT |
| 9 | CVE-2026-21877 | n8n | TypeScript | File write RCE | 1 | GOOD |
| 10 | CVE-2026-21637/21710 | Node.js | C++/JS | DoS/proto pollution | 2+ | GOOD |
| 11 | CVE-2026-3888 | snapd | Go/C | TOCTOU race | 3+ | GOOD |
| 12 | CVE-2026-3909/3910 | Chrome | C++ | OOB write/V8 | 2 | MODERATE |
| 13 | CVE-2026-22737/22732 | Spring | Java | Path traversal | 3+ | GOOD |

---

## Recommended Benchmark Corpus (Top 10 Pairs for Naptrace)

Priority ordering for the benchmark corpus in `benchmarks/corpus/`:

1. **Django SQLi pair** (CVE-2026-1207 <-> CVE-2026-1287) -- Same release, same
   class, exact commit SHAs available. Python.
2. **OpenSSL buffer overflow family** (CVE-2025-15467 + CVE-2025-11187 +
   CVE-2026-22795/22796) -- 12 vulns, exact commit SHAs available. C.
3. **Linux netfilter cluster** (CVE-2026-31414/31407/31416/31418/31424) -- 6+
   vulns in same subsystem. C kernel.
4. **AppArmor CrackArmor** (CVE-2026-23268 through CVE-2026-23411) -- 9 variants
   of confused deputy. C kernel.
5. **Chrome Dawn UAF family** (CVE-2026-5281/4676/5284) -- 3+ UAFs same component.
   C++.
6. **Composer command injection pair** (CVE-2026-40176 <-> CVE-2026-40261) -- Twin
   injection bugs, same driver. PHP.
7. **Linux ksmbd UAF** (CVE-2026-23226 + historical CVE-2025-21945/CVE-2023-32256) --
   Multi-year variant family. C kernel.
8. **Spring path traversal** (CVE-2026-22737 + CVE-2025-41242 + CVE-2024-38819) --
   3 variants across releases. Java.
9. **Node.js DoS pair** (CVE-2026-21637 <-> CVE-2026-21710) -- Exception handling
   DoS pattern. C++/JS.
10. **snapd TOCTOU** (CVE-2026-3888 + CVE-2021-44731 + CVE-2019-7304) -- Historical
    variant family in setuid binaries. Go/C.

---

## Notes

- All CVEs listed have public patches. Exact commit SHAs are available for Django,
  OpenSSL, and Node.js. For Linux kernel, Chromium, and others, commits can be
  retrieved from the respective git repositories using the CVE IDs.
- The OpenSSL family is particularly noteworthy because all 12 CVEs were discovered
  by AISLE's autonomous AI analyzer -- directly relevant to Naptrace's mission of
  showing AI-powered variant analysis.
- The Django pair is the cleanest benchmark: two SQL injection CVEs, same codebase,
  same release date, exact commits, Python (easy to parse). Start here.
- For the benchmark corpus (per CLAUDE.md section 10), prioritize CVEs published
  after January 2026 to ensure they are post-training-cutoff for current models.
