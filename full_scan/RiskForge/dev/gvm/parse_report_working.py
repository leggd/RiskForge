from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST="10.0.96.32"; PORT=9390
USERNAME="admin"; PASSWORD="378d6918-4340-4cfe-95f7-3f084d826d5d"
REPORT_ID="28870702-47fb-4732-893a-53c99edb9ca7"

def first_text(node, path):
    if node is None:
        return None
    x = node.find(path)
    return (x.text or "").strip() if x is not None and x.text else None

def extract_cves_from_nvt(nvt_node):
    if nvt_node is None:
        return []
    cves = []
    for ref in nvt_node.findall(".//refs/ref"):
        if (ref.get("type") or "").lower() == "cve":
            cve_id = ref.get("id")
            if cve_id:
                cves.append(cve_id.strip())
    return cves

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)

    report_xml = gmp.get_report(
        report_id=REPORT_ID,
        details=True,
        filter_string="rows=1000"
    )

results = report_xml.findall(".//report/results/result")

# helper to extract severity
def get_severity(result):
    sev = result.findtext("severity")
    try:
        return float(sev)
    except:
        return 0.0

# sort highest severity first
results_sorted = sorted(results, key=get_severity, reverse=True)

print("Result count:", len(results_sorted))

for r in results_sorted[:10]:   # show top 50
    host = first_text(r, "host")
    port = first_text(r, "port")
    severity = first_text(r, "severity")
    threat = first_text(r, "threat")

    nvt = r.find("nvt")
    nvt_name = first_text(nvt, "name") if nvt is not None else None
    nvt_oid = nvt.get("oid") if nvt is not None else None
    solution = first_text(nvt, "solution") if nvt is not None else None

    cves = extract_cves_from_nvt(nvt)

    print("-" * 60)
    print("Host:", host)
    print("Port:", port)
    print("NVT:", nvt_name)
    print("Severity:", severity)
    print("CVEs:", ", ".join(cves) if cves else "None")
    print("Solution:", solution)