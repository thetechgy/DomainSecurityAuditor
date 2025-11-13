# Domain Security Auditor (DSA)

> 🚧 **Work in Progress** - There is **no working product** at this point.
> This README explains the design concept and how the project is intended to work once functional.

[![Status](https://img.shields.io/badge/status-active_development-orange)](https://github.com/thetechgy/DomainSecurityAuditor/tree/develop)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-2671E5)](#requirements)
[![Pester](https://img.shields.io/badge/Tests-Pester-blue)](#quality--testing)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

**Domain Security Auditor (DSA)** is a PowerShell-based project that uses [DomainDetective] as the data source and adds a testing layer with [Pester] and reporting layer with [PSWriteHTML] to check domain and email security against best practices or custom baselines.

[DomainDetective]: https://github.com/EvotecIT/DomainDetective
[Pester]: https://github.com/pester/Pester
[PSWriteHTML]: https://github.com/EvotecIT/PSWriteHTML

---

## At a Glance

- **Purpose:** Repeatable, reference-backed checks for domain/email security
- **Stack:** PowerShell 7+, Pester, DomainDetective, PSWriteHTML
- **Output:** HTML first; JSON/CSV/JUnit later for CI/CD

---

## Table of Contents

- [Domain Security Auditor (DSA)](#domain-security-auditor-dsa)
  - [At a Glance](#at-a-glance)
  - [Table of Contents](#table-of-contents)
  - [Who Is This For?](#who-is-this-for)
  - [Goals](#goals)
  - [MVP Scope](#mvp-scope)
  - [Sample Report](#sample-report)
    - [Report Features](#report-features)
    - [Example Output](#example-output)
  - [Architecture](#architecture)
    - [Layers](#layers)
    - [Data Shapes](#data-shapes)
  - [Requirements](#requirements)
  - [Automation Targets](#automation-targets)
  - [Quality \& Testing](#quality--testing)
  - [Roadmap](#roadmap)
    - [Near Term](#near-term)
    - [Medium Term](#medium-term)
    - [Long Term](#long-term)
  - [Contributing](#contributing)
  - [License](#license)
  - [Acknowledgments](#acknowledgments)
    - [Inspiration and Foundations](#inspiration-and-foundations)
    - [Support the Ecosystem](#support-the-ecosystem)
    - [Community References](#community-references)

---

## Who Is This For?

- Individuals or small orgs that want **repeatable** checks with **clear results**
- Consultants who need **consistent evidence** for client reports
- Enterprises planning to **schedule runs** or **integrate with CI/CD**

---

## Goals

- **Trust the data** — Use DomainDetective for domain data collection
- **Focus on testing, not parsing** — Compare data to included best-practice baselines or customer-provided baseline tests
- **Make action clear** — Reports include short explanations and links to reliable sources (RFCs, M3AAWG, dmarc.org)
- **Scale responsibly** — Handle many domains, keep DNS lookups efficient, respect timeouts and rate limits

---

## MVP Scope

- **Inputs:** One domain or a CSV list
- **Test focus areas:** SPF, DKIM, DMARC, MTA-STS, TLS-RPT, MX
- **Classification:** From DomainDetective (Sending-Only, Receiving-Only, Sending and Receiving, or Parked); override via CSV if needed
- **Baselines:** Built-in best practice values based on domain classification

---

## Sample Report

DSA generates comprehensive HTML reports with intuitive modern styling, interactive elements, and detailed test results that make security posture immediately clear while providing relevant remediation steps.

### Report Features

The HTML reports provide:

- **Executive Summary Cards** — At-a-glance view of domains passed, failed, and warnings
- **Per-Domain Assessment** — Expandable sections for each tested domain showing:
  - Overall compliance status (Passed/Failed/Warning)
  - Domain type (Sending-Only, Receiving-Only, Sending and Receiving, or Parked)
  - Individual protocol test results
- **Detailed Test Results** — For each check:
  - Clear pass/fail/warning indicators with visual icons
  - Actual values found (e.g., SPF record content, DKIM key details)
  - Specific recommendations for improvements
  - Direct links to relevant RFCs and best practice guides
- **Interactive Navigation** — Collapsible sections to focus on areas of interest

### Example Output

Here's what a typical report shows:

```
Domain Security Compliance Report
Generated on: September 4, 2025, 2:30 PM EDT
Framework Version: 1.0.0 | Test Suite: Baseline Email Security v1.2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Domains Passed: 2 (Full compliance achieved)
❌ Domains Failed: 1 (Critical issues found)
⚠️  Total Warnings: 2 (Improvements recommended)
🔍 Total Tests Run: 32

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📧 example.com [PASSED]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Production Domain • 14 tests executed

▼ SPF (Sender Policy Framework)
  ✅ SPF Record Presence — Found and properly configured
     → Record: v=spf1 include:_spf.google.com -all
     → DNS Lookups: 2 of 10 allowed
     📖 References: RFC 7208, M3AAWG Best Practices

  ✅ Terminal Mechanism — Hard fail (-all) properly configured
  ✅ DNS Lookup Limit — Within limits (2 lookups used)

▼ DMARC (Domain-based Message Authentication)
  ✅ DMARC Policy Presence — Found with quarantine policy
     → Policy: p=quarantine, sp=quarantine

  ⚠️  DMARC Policy Strength — Consider upgrading to reject
     💡 Recommendation: After monitoring DMARC reports for 2-4 weeks,
        consider upgrading to p=reject for maximum protection.
     📖 References: DMARC Deployment Guide, M3AAWG DMARC Best Practices

▼ DKIM (DomainKeys Identified Mail)
  ✅ DKIM Key Presence — Valid keys found
     → Selectors: google, default
     → Algorithm: RSA

  ✅ DKIM Key Length — Meets requirements (2048 bits)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📧 subsidiary.example.com [FAILED]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▼ DMARC
  ❌ DMARC Record Missing — No DMARC record found
     💡 Recommendation: Implement DMARC policy starting with p=none
        for monitoring, then gradually move to p=quarantine and p=reject.
     📖 References: RFC 7489, DMARC.org Deployment, M3AAWG DMARC Guide
```

> 📸 [View full example report](Examples/domain_compliance_report.html)

---

## Architecture

### Layers

- **Data:** Domain details from DomainDetective (single source of truth)
- **Testing:** Pester-based Compliance Engine runs baselines or custom packs
- **Reporting:** PSWriteHTML for HTML; JSON/CSV/JUnit later for automation

### Data Shapes

- `ComplianceResult` — Result of a single check
- `DomainSecurityProfile` — Overall posture for one domain

---

## Requirements

- **PowerShell 7+**
- **Pester** (current supported release)
- **DomainDetective** module
- **DNS Connectivity** to your resolver (System, Cloudflare, Google, Quad9, etc.)

> Install steps and usage examples will be added once a functional preview exists.

---

## Automation Targets

Runs on common schedulers and CI/CD systems:

- Windows Task Scheduler
- Linux `cron`
- Azure Automation
- Azure DevOps pipelines
- GitHub Actions

> Examples will be added once functional code exists.

---

## Quality & Testing

- **PSScriptAnalyzer** for code style and quality
- **Pester** unit and integration tests

---

## Roadmap

### Near Term

- **Coverage growth:** DNSSEC, DANE, BIMI, DNSBL, CAA, SubdoMailing
- **CI/CD support:** GitHub Actions and Azure DevOps

### Medium Term

- **Notifications:** Teams and webhooks
- **Integrations:** Microsoft 365
- **Compliance mapping:** NIST / ISO 27001
- **Performance tests** for large domain sets
- **Multi-platform CI** (Windows/Linux/macOS)

### Long Term

- **Resilience handling** for rate limits, timeouts, and graceful failure
- **History:** Trending and audit trails
- **UX:** Light/dark theme toggle in the HTML report
- **Integrations:** DNS providers

---

## Contributing

Issues, discussions, and PRs are welcome. When adding or changing baseline rules, include **reliable sources** (RFCs, M3AAWG, dmarc.org) in code comments and, when relevant, in the report output.

> Detailed contributor guidelines will be added once a functional preview exists.

---

## License

**Apache-2.0** — See [LICENSE](LICENSE).

---

## Acknowledgments

### Inspiration and Foundations

- [Maester] — Informed the data-driven, Pester-first approach and overall UX philosophy
- [Przemyslaw Klys / Evotec] — Author of DomainDetective (data source) and PSWriteHTML (reporting), plus many other high-quality PowerShell projects

[Maester]: https://maester.dev/
[Przemyslaw Klys / Evotec]: https://evotec.xyz/

### Support the Ecosystem

If this project helps you, please consider starring, contributing to, or sponsoring:

- [DomainDetective]
- [PSWriteHTML]
- [Maester]

### Community References

Thank you to **RFC contributors**, **M3AAWG**, and **dmarc.org** for the standards and guidance that shape these checks.
