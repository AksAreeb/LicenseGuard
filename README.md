# LicenseGuard

**An Automated Open-Source Compliance & Policy Enforcement Project.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Governance: Enforced](https://img.shields.io/badge/Governance-Enforced-success)](https://github.com/your-username/LicenseGuard)

LicenseGuard is a Governance tool that secures your software supply chain. It automatically audits your project's dependencies against a predefined legal policy, ensuring that no restricted licenses compromise your intellectual property.

Protect your Projects. Use LicenseGuard.



## The Problem
In modern development, a single `npm install` can introduce a library with a **GPL or AGPL license**. For many companies, this creates a "Viral" legal risk that could mandate the open sourcing of their entire private codebase. 

## How It Works
LicenseGuard integrates directly into your **GitHub Actions** workflow:
1. **Intercepts:** Triggers whenever a Pull Request is opened.
2. **Scans:** Analyzes `package.json`, `requirements.txt`, or `go.mod`.
3. **Validates:** Checks licenses against the [Google Deps.dev API](https://deps.dev/).
4. **Enforces:** Blocks the merge if a dependency violates your `policy.json`.



## Configuration
Define your organization's risk tolerance in the `policy.json` file:

```json
{
  "approved": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "restricted": ["GPL-3.0", "AGPL-3.0", "LGPL-3.0"],
  "fail_on_restricted": true
}