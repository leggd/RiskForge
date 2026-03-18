"""
fetch_and_parse_openvas_report.py

Fetch an OpenVAS/GVM report via GMP (TLS) and extract *actionable* findings with:
- host
- port / protocol
- NVT name + OID
- CVSS-like score (OpenVAS <severity> value, 0.0–10.0 scale)
- severity label (threat)
- CVE list (robust extraction with fallback regex)
- QoD
- description/summary + solution (when available)

USAGE:
1) pip install python-gvm lxml
2) Edit HOST/PORT/USERNAME/PASSWORD/REPORT_ID
3) python fetch_and_parse_openvas_report.py
"""

from __future__ import annotations

import json
import re
from typing import Any

from lxml import etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

# ---------------------------
# CONFIG (edit these)
# ---------------------------
HOST = "10.0.96.32"
PORT = 9390
USERNAME="admin"
PASSWORD="378d6918-4340-4cfe-95f7-3f084d826d5d"


# Paste the report_id you got from start_task() or from get_reports/get_tasks listing
REPORT_ID = "fca1552d-57d8-4fc7-934d-54ebd7acf8ba"

# If you want to dump findings as JSON to a file
OUTPUT_JSON_PATH = "findings.json"

# Only keep actionable findings (filters out "Log"/0.0 noise)
FILTER_LOG_AND_ZERO = True

# ---------------------------
# Helpers
# ---------------------------
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def safe_float(s: str | None) -> float | None:
    if not s:
        return None
    s = s.strip()
    try:
        return float(s)
    except ValueError:
        return None


def safe_int(s: str | None) -> int | None:
    if not s:
        return None
    s = s.strip()
    try:
        return int(s)
    except ValueError:
        return None


def text(node: etree._Element | None, path: str) -> str | None:
    """ElementTree .findtext wrapper that returns stripped text or None."""
    if node is None:
        return None
    val = node.findtext(path)
    if val is None:
        return None
    val = val.strip()
    return val if val else None


def xpath_text_first(node: etree._Element | None, xpath_expr: str) -> str | None:
    """Return first non-empty text match for an xpath, else None."""
    if node is None:
        return None
    res = node.xpath(xpath_expr)
    for r in res:
        if isinstance(r, etree._Element):
            t = (r.text or "").strip()
        else:
            t = (str(r) or "").strip()
        if t:
            return t
    return None


def extract_cves_from_nvt(nvt_node: etree._Element | None) -> list[str]:
    """Try to extract CVEs from common NVT fields/refs."""
    if nvt_node is None:
        return []

    cves: set[str] = set()

    # 1) Direct <cve> field sometimes exists (often a space/comma separated string)
    direct = text(nvt_node, "cve")
    if direct:
        for m in CVE_RE.findall(direct):
            cves.add(m.upper())

    # 2) Common: <refs><ref type="cve" id="CVE-...."/>
    for ref in nvt_node.xpath(".//refs/ref[@type='cve']"):
        rid = (ref.get("id") or "").strip()
        if rid and rid.upper().startswith("CVE-"):
            cves.add(rid.upper())

    # 3) Sometimes refs are embedded in other ref ids/urls; pull CVE patterns from @id
    for ref in nvt_node.xpath(".//refs/ref"):
        rid = (ref.get("id") or "").strip()
        if rid:
            for m in CVE_RE.findall(rid):
                cves.add(m.upper())

    return sorted(cves)


def extract_cves_fallback(*blobs: str | None) -> list[str]:
    """Fallback: regex CVEs from any strings provided (e.g., NVT name/description)."""
    cves: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for m in CVE_RE.findall(blob):
            cves.add(m.upper())
    return sorted(cves)


def normalize_port(port_raw: str | None) -> tuple[int | None, str | None, str | None]:
    """
    Port strings often look like:
      - "80/tcp"
      - "21/tcp"
      - "general/tcp"
      - "general/CPE-T"
    Return: (port_num, protocol, port_raw)
    """
    if not port_raw:
        return None, None, None

    port_raw = port_raw.strip()
    if "/" in port_raw:
        left, right = port_raw.split("/", 1)
        proto = right.strip() if right else None
        port_num = int(left) if left.isdigit() else None
        return port_num, proto, port_raw

    if port_raw.isdigit():
        return int(port_raw), None, port_raw

    return None, None, port_raw


def severity_label_from_score(score: float) -> str:
    # Common CVSS bands (v3.x):
    # 0.0 None, 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Log"


def parse_openvas_results(report_xml: etree._Element) -> list[dict[str, Any]]:
    """
    Extract actionable findings from the report XML.
    Uses <severity> as numeric CVSS-like score (0..10 scale) per result.
    Filters out informational log/0.0 results if configured.
    """
    findings: list[dict[str, Any]] = []

    # Usual structure: <report><results><result>...</result></results></report>
    results = report_xml.findall(".//report/results/result")
    if not results:
        # fallback (rare)
        results = report_xml.findall(".//results/result")

    for r in results:
        host = text(r, "host")
        port_raw = text(r, "port")
        threat = text(r, "threat")  # "Log", "Low", "Medium", "High" (sometimes)
        severity_score = safe_float(text(r, "severity"))

        # Basic filter: ignore items without numeric severity
        if severity_score is None:
            continue

        # Filter out informational noise
        if FILTER_LOG_AND_ZERO:
            if severity_score <= 0.0:
                continue
            if threat and threat.strip().lower() == "log":
                continue

        port_num, protocol, port_raw_norm = normalize_port(port_raw)

        nvt = r.find("nvt")
        nvt_oid = nvt.get("oid") if nvt is not None else None
        nvt_name = text(nvt, "name") if nvt is not None else text(r, "name") or "Unknown NVT"

        description = text(r, "description")
        # Solution is often under nvt, but may not always be present in the chosen report format
        solution = text(nvt, "solution") if nvt is not None else None

        # QoD (quality of detection)
        qod_val = safe_int(text(r, "qod/value"))

        # CVE extraction: structured first, then regex fallback (name/description)
        cves = extract_cves_from_nvt(nvt)
        if not cves:
            cves = extract_cves_fallback(nvt_name, description)

        # If threat label missing, derive from numeric severity score
        if not threat:
            threat = severity_label_from_score(severity_score)

        findings.append(
            {
                "host": host,
                "port": port_num,
                "protocol": protocol,
                "port_raw": port_raw_norm,
                "nvt_oid": nvt_oid,
                "nvt_name": nvt_name,
                "cvss_score": severity_score,  # <-- use this as your CVSS-like score
                "severity_label": threat,
                "cves": cves,  # list[str]
                "qod": qod_val,
                "description": description,
                "solution": solution,
            }
        )

    return findings


def main() -> None:
    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        # details=True is important to get results
        report_xml = gmp.get_report(REPORT_ID, details=True)

        findings = parse_openvas_results(report_xml)

        print(f"Extracted actionable findings: {len(findings)}")

        # Print first 15 findings as proof
        for f in findings[:15]:
            print("-" * 70)
            print(f"Host: {f['host']}")
            print(f"Port: {f['port']}/{f['protocol']} (raw={f['port_raw']})")
            print(f"NVT: {f['nvt_name']} (OID={f['nvt_oid']})")
            print(f"CVSS-like score (severity): {f['cvss_score']} | Label: {f['severity_label']}")
            print(f"CVEs: {', '.join(f['cves']) if f['cves'] else 'None'}")
            print(f"QoD: {f['qod']}")
            if f["solution"]:
                print(f"Solution (snippet): {f['solution'][:220]}")

        # Dump to JSON for easy next steps (DB ingest)
        with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as fp:
            json.dump(findings, fp, indent=2, ensure_ascii=False)

        print(f"\nSaved findings JSON to: {OUTPUT_JSON_PATH}")


if __name__ == "__main__":
    main()