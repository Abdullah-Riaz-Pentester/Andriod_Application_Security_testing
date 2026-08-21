# Mobile Application Security Testing (MAST) — Checklist & Master-Guide

> A practical, MASVS/MASTG-aligned toolkit for Android and iOS application penetration testing: a filterable multi-sheet checklist workbook and a step-by-step, publication-grade field manual with exact commands, fallback tooling, vulnerable-vs-secure baselines, and end-to-end exploit chains.

![Focus](https://img.shields.io/badge/focus-Mobile%20AppSec-blue)
![Platforms](https://img.shields.io/badge/platforms-Android%20%7C%20iOS%20%7C%20API-green)
![Aligned](https://img.shields.io/badge/aligned-OWASP%20MASVS%20%2F%20MASTG-orange)
![Tests](https://img.shields.io/badge/test%20cases-225-red)
![Guide](https://img.shields.io/badge/guide%20activities-30-purple)

---

## Overview

This repository packages two companion deliverables for mobile application security assessments:

1. A **testing checklist workbook** (Excel) that inventories 225 test cases across Android, iOS, and shared/API surfaces, plus an advanced full-chain chapter. Each row carries an objective, tools, a step-by-step methodology, and pass/fail criteria, with a status dropdown for tracking an engagement.
2. An **Android MAST Master-Guide** (Markdown) that expands the baseline six-phase Android methodology into 30 detailed activities. Every activity gives exact CLI commands, a fallback protocol for when tooling breaks, confirmed-vulnerable and verified-secure code baselines, and attack-chaining notes.

Use the workbook to plan, scope, and track. Use the guide to actually execute each test with precise commands.

---

## What's inside

| Deliverable | File | Format | Scope |
|---|---|---|---|
| Checklist workbook | `Mobile_Application_Security_Testing_Checklist.xlsx` | Excel (5 sheets) | 225 test cases: Android, iOS, Common & API, Advanced |
| Android master-guide | `Android_MAST_Master_Guide.md` | Markdown | 30 activities across 6 phases, with commands and PoCs |

---

## Repository structure

```text
.
├── README.md                                          # this file
├── Mobile_Application_Security_Testing_Checklist.xlsx  # the 225-test workbook
├── Android_MAST_Master_Guide.md                       # the 30-activity field manual
└── (reference material used to build the above)
```

---

## The checklist workbook

`Mobile_Application_Security_Testing_Checklist.xlsx` is organized into five sheets. Every technology sheet uses the same columns: **Test ID · Test Name · Objective · Tools · Methodology Summary · Pass/Fail Criteria · Status · Notes**, with an autofilter on the header row and a Status dropdown (`Not Started → In Progress → Pass / Fail / N/A / Needs Review`).

| Sheet | Tests | Coverage |
|---|---|---|
| Dashboard | — | Index, how-to-use, and knowledge sources |
| Android | 89 | Manifest & platform config, static analysis & secrets, storage & Keystore, crypto, IPC (intents, providers, receivers, deep links, App Links, PendingIntent), WebView & hybrid, TLS & pinning, auth & biometrics, runtime instrumentation, resilience & anti-RE, native JNI, privacy |
| iOS | 55 | IPA acquisition, Info.plist & entitlements, Keychain & data protection, Secure Enclave, URL schemes & universal links, WKWebView, ATS & pinning, auth & Face ID/Touch ID, swizzling, jailbreak-detection & anti-RE, privacy |
| Common & API | 52 | API recon, authN/authZ, OAuth/OIDC, JWT, BOLA/BFLA, injection, business logic, rate limiting, infra, privacy, reporting discipline |
| Advanced | 29 | Deep reverse engineering & unpacking, custom Frida/Xposed chains, deep-link abuse, crypto exploitation, business-logic chains, attestation defeat, full-chain scenarios |

**How to use it**

1. Open the **Dashboard** sheet and pick the platform tab in scope. Work the **Common & API** sheet on every engagement, because the backend is in scope for both platforms.
2. Read Objective, Tools, and Methodology before executing each row.
3. Track progress in the **Status** column and record evidence in **Notes**.
4. Resilience and Advanced tests are inverted: a "Fail" often means the tester won (a control was bypassed). Read the Pass/Fail wording carefully.
5. Work the **Advanced** sheet last; it chains earlier findings into end-to-end exploitation.

---

## The Android master-guide

`Android_MAST_Master_Guide.md` follows a strict six-phase engagement flow. Findings from early phases feed later ones.

| Phase | Theme | Activities |
|---|---|---|
| 1 | Information Gathering & Reconnaissance | Manifest review, decompilation, drozer attack surface, API endpoint mapping |
| 2 | Static Analysis | SharedPreferences, hardcoded secrets, log leakage, weak crypto |
| 3 | Dynamic & Network Analysis | Traffic interception, pinning bypass, dynamic logcat, app switcher, exported activities, **deep links & App Links**, **broadcast abuse**, **content provider exploitation**, **implicit intent & PendingIntent hijacking** |
| 4 | API & Network Attack | BOLA/IDOR, BFLA, SQL injection, WebView stored XSS, mass assignment |
| 5 | Advanced Local & Runtime | Sandbox data theft, root-detection bypass, WebView JS bridge, biometric bypass |
| 6 | Resilience & Anti-Reversing | Obfuscation, anti-tampering, debugger detection, emulator/root static review |

**Every activity follows the same template:**

```text
Activity X.Y: Name
  - Main Heading:        MASVS category
  - Sub-Heading:         MASTG test ID
  - Risk & Impact:       severity + technical/business impact
  - Primary Tooling
  - Alternate / Fallback Tooling
  - Step-by-Step Methodology     (exact commands)
  - Fallback Execution Workflow  (what to run when the primary tool fails)
  - Vulnerable / Failure State   (confirmed-vulnerable code / output)
  - Secure / Success State       (hardened code = retest oracle)
  - Chaining Vector              (ASCII flow escalating the finding)
```

The guide closes with **Appendix A: End-to-End Chaining Playbook** (9 real attack chains, for example App Link hijack to account takeover, and pinning bypass to mass BOLA extraction) and **Appendix B: Reporting and Retest Discipline**.

---

## Standards alignment

Both deliverables map directly to OWASP standards so findings drop straight into a report.

| Reference | Use |
|---|---|
| OWASP MASVS | Control groups: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE |
| OWASP MASTG | Test IDs (`MASTG-TEST-*`, `MASTG-PLAT-*`, `MASTG-AUTH-*`) cited per activity |
| OWASP API Security Top 10 | BOLA (API1), BFLA (API5), mass assignment (API3), and related API tests |
| OWASP Mobile Top 10 | Cross-referenced throughout the checklist |

---

## Toolkit

The methodologies assume a standard mobile-assessment toolchain:

- **Static:** `jadx`, `apktool`, `dex2jar`, Bytecode Viewer, `class-dump`, Ghidra, MobSF, `apkleaks`
- **Dynamic & instrumentation:** `frida`, `objection`, `drozer`, `adb`, Magisk/Zygisk, `frida-dexdump`, LSPosed
- **Network:** Burp Suite, `mitmproxy`, `apk-mitm`, Wireshark
- **iOS:** `frida-ios-dump`, Hopper, `otool`, palera1n, SSL Kill Switch
- **API:** Burp Suite, `sqlmap`, `ffuf`, `jwt_tool`, Turbo Intruder, Collaborator

---

## Who this is for

Mobile penetration testers, bug bounty hunters, red teamers, and mobile developers who want a concrete definition of "secure" to build and retest against. The Secure/Success State blocks in the guide double as remediation guidance and retest criteria.

---

## Legal & ethical use

This material is for **authorized security testing and education only**. Test only applications and backends you own or have explicit written permission to assess. Unauthorized testing of systems, accounts, or data you do not control is illegal in most jurisdictions. The authors accept no liability for misuse. Follow your program's rules of engagement, avoid bulk-exfiltrating real user data, and extract only the minimum needed to prove impact.

---

## Sources & acknowledgements

Built by synthesizing:

- The OWASP Mobile Application Security project (MASVS and MASTG).
- The OWASP API Security Top 10 and Mobile Top 10.
- A baseline six-phase Android testing checklist, expanded with practical mobile VAPT methodology.
- Public bug bounty write-up patterns and reverse-engineering research.

Reference and course material used during authoring is not redistributed here; consult the original OWASP publications for the authoritative standards.

---

## Contributing

Issues and pull requests are welcome: new test cases, additional fallback tooling, corrected commands, or fresh chaining scenarios. Keep new checklist rows in the existing column format and new guide activities in the fixed activity template so the documents stay consistent.

---

## License

No license is set yet. Until one is added, all rights are reserved by the repository owner. Consider adding an open license (for example MIT for permissive reuse, or CC BY 4.0 for the documentation) if you intend others to reuse this work.
