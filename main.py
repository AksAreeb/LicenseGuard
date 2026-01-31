#!/usr/bin/env python3
"""
LicenseGuard - Open-Source License Compliance Enforcement

Scans Python dependencies against a policy file and blocks builds when
restricted licenses (e.g., GPL, AGPL) are detected.
"""

import json
import re
import sys
from pathlib import Path

import requests

DEPS_DEV_API_BASE = "https://api.deps.dev/v3alpha"
SYSTEM = "PYPI"
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {"Accept": "application/json"}


def load_policy(policy_path: str) -> dict:
    """Load and validate the policy configuration file."""
    path = Path(policy_path)
    if not path.exists():
        print(f"[LicenseGuard] ERROR: Policy file not found: {policy_path}")
        print("  Please ensure policy.json exists or specify the correct path via policy-path input.")
        sys.exit(2)

    try:
        with open(path, encoding="utf-8") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[LicenseGuard] ERROR: Invalid JSON in policy file: {e}")
        sys.exit(2)

    approved = policy.get("approved", [])
    restricted = policy.get("restricted", [])

    if not isinstance(approved, list) or not isinstance(restricted, list):
        print("[LicenseGuard] ERROR: Policy must define 'approved' and 'restricted' as arrays.")
        sys.exit(2)

    return {"approved": approved, "restricted": restricted}


def parse_requirements(requirements_path: str) -> list[str]:
    """Parse requirements.txt and return normalized package names."""
    path = Path(requirements_path)
    if not path.exists():
        print(f"[LicenseGuard] ERROR: Requirements file not found: {requirements_path}")
        sys.exit(2)

    packages = []
    # PEP 508: package names can be followed by version specifiers, extras, etc.
    pattern = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*([\[<>=!].*)?$")

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle -e / --editable and other options
            if line.startswith("-e ") or line.startswith("--editable "):
                part = line.split(None, 1)[1]
                if "egg=" in part:
                    match = re.search(r"egg=([a-zA-Z0-9][a-zA-Z0-9._-]*)", part)
                    if match:
                        packages.append(match.group(1).lower().replace("_", "-"))
                elif "@" in part or "git+" in part:
                    pkg = part.rstrip("/").split("/")[-1].replace("_", "-").lower()
                    if pkg.endswith(".git"):
                        pkg = pkg[:-4]
                    packages.append(pkg)
                continue
            match = pattern.match(line)
            if match:
                name = match.group(1).lower().replace("_", "-")
                packages.append(name)

    return list(dict.fromkeys(packages))


def get_default_version(package_name: str) -> str | None:
    """Fetch package metadata and return the default (latest) version."""
    url = f"{DEPS_DEV_API_BASE}/systems/{SYSTEM.lower()}/packages/{package_name}"
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        print(f"[LicenseGuard] WARNING: API timeout while fetching package '{package_name}'. Skipping.")
        return None
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"[LicenseGuard] WARNING: Package '{package_name}' not found in registry. Skipping.")
        else:
            print(f"[LicenseGuard] WARNING: API error for '{package_name}' ({e}). Skipping.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[LicenseGuard] WARNING: Network error for '{package_name}': {e}. Skipping.")
        return None

    versions = data.get("versions", [])
    if not versions:
        print(f"[LicenseGuard] WARNING: No versions found for '{package_name}'. Skipping.")
        return None

    for v in versions:
        if v.get("isDefault"):
            return v.get("versionKey", {}).get("version")
    return versions[0].get("versionKey", {}).get("version")


def get_licenses(package_name: str, version: str) -> list[str]:
    """Fetch license information for a specific package version from Deps.dev."""
    url = f"{DEPS_DEV_API_BASE}/systems/{SYSTEM.lower()}/packages/{package_name}/versions/{version}"
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        print(f"[LicenseGuard] WARNING: API timeout for '{package_name}=={version}'. Skipping.")
        return []
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"[LicenseGuard] WARNING: Version '{package_name}=={version}' not found. Skipping.")
        else:
            print(f"[LicenseGuard] WARNING: API error for '{package_name}=={version}' ({e}). Skipping.")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[LicenseGuard] WARNING: Network error for '{package_name}=={version}': {e}. Skipping.")
        return []

    licenses = data.get("licenses", [])
    if not licenses and data.get("licenseDetails"):
        licenses = [d.get("spdx", d.get("license", "")) for d in data["licenseDetails"] if d.get("spdx") or d.get("license")]
    return [str(l) for l in licenses if l]


def _license_matches_restricted(license_expr: str, restricted: str) -> bool:
    """Check if a single license expression matches a restricted identifier."""
    r = restricted.upper()
    # Split SPDX compound expressions (AND, OR, WITH)
    parts = re.split(r"\s+AND\s+|\s+OR\s+|\s+WITH\s+", license_expr, flags=re.I)
    for part in parts:
        part = part.strip().strip("()").upper()
        if part == r or part.startswith(r + "-") or part.startswith(r + "."):
            return True
    return False


def is_restricted(licenses: list[str], restricted: list[str]) -> tuple[bool, list[str]]:
    """
    Check if any license matches a restricted pattern.
    Returns (is_restricted, matched_licenses).
    """
    matched = []
    for lic in licenses:
        for r in restricted:
            if _license_matches_restricted(lic, r):
                matched.append(lic)
                break
    return len(matched) > 0, matched


def main() -> None:
    policy_path = Path(__file__).parent / "policy.json"
    requirements_path = Path(__file__).parent / "requirements.txt"

    if len(sys.argv) > 1:
        policy_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        requirements_path = Path(sys.argv[2])

    print("[LicenseGuard] Scanning dependencies for license compliance...")
    print(f"[LicenseGuard] Policy: {policy_path.resolve()}")
    print(f"[LicenseGuard] Requirements: {requirements_path.resolve()}")

    policy = load_policy(str(policy_path))
    packages = parse_requirements(str(requirements_path))

    if not packages:
        print("[LicenseGuard] No dependencies to scan. Exiting successfully.")
        sys.exit(0)

    restricted_list = policy["restricted"]
    violations = []

    for pkg in packages:
        version = get_default_version(pkg)
        if not version:
            continue
        licenses = get_licenses(pkg, version)
        if not licenses:
            print(f"[LicenseGuard] INFO: No license metadata for '{pkg}=={version}'. Consider verifying manually.")
            continue
        is_restr, matched = is_restricted(licenses, restricted_list)
        if is_restr:
            violations.append((pkg, version, matched))

    if violations:
        print()
        print("=" * 60)
        print("  GOVERNANCE ALERT - Restricted License(s) Detected")
        print("=" * 60)
        print()
        print("The following dependencies use licenses that violate your policy:")
        print()
        for pkg, version, lics in violations:
            print(f"  • {pkg}=={version}")
            print(f"    License(s): {', '.join(lics)}")
        print()
        print("Action required: Remove or replace these dependencies, or update your")
        print("policy.json if an exception is approved by your legal/compliance team.")
        print()
        print("Policy restricted licenses:", ", ".join(restricted_list))
        print("=" * 60)
        sys.exit(1)

    print("[LicenseGuard] All scanned dependencies comply with the license policy.")
    sys.exit(0)


if __name__ == "__main__":
    main()
