from lxml import etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST="10.0.96.32"; PORT=9390
USERNAME="admin"; PASSWORD="378d6918-4340-4cfe-95f7-3f084d826d5d"
REPORT_ID="7c12faca-cf12-46be-ae05-fb00d0cd5a26"

def first_text(node, path):
    x = node.find(path)
    return (x.text or "").strip() if x is not None and x.text else None

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)

    report_xml = gmp.get_report(REPORT_ID, details=True)

    results = report_xml.findall(".//report/results/result")
    print("Result count:", len(results))

    for r in results[:10]:
        host = first_text(r, "host")
        port = first_text(r, "port")          # often like "80/tcp"
        severity = first_text(r, "severity")  # numeric score used by OpenVAS per result
        threat = first_text(r, "threat")      # may be High/Medium/etc (optional)

        nvt = r.find("nvt")
        nvt_name = first_text(nvt, "name") if nvt is not None else None
        nvt_oid = nvt.get("oid") if nvt is not None else None

        # CVEs may be in <nvt><cve>...</cve> depending on version
        cve = first_text(nvt, "cve") if nvt is not None else None

        print("-" * 60)
        print("Host:", host)
        print("Port:", port)
        print("NVT:", nvt_name, "| OID:", nvt_oid)
        print("Severity:", severity, "| Threat:", threat)
        print("CVE:", cve)