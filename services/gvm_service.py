from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from datetime import datetime

# GVM connection configuration (scanner host and credentials)
# Will change to .env at production
HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

def start_gvm_scan(target_ip):
    """
    Initiate a GVM vulnerability scan for a single target IP.

    Creates a target and task in GVM, starts the scan and attempts to
    retrieve the associated report ID. Returns the task ID and report ID
    """

    # GVM scan configuration identifiers
    SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
    PORT_LIST_ID   = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"

    # Establish TLS connection to GVM
    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    # Open GVM session
    with GMP(connection=connection, transform=transform) as gmp:
        # Authenticate with GVM
        gmp.authenticate(USERNAME, PASSWORD)

        # Generate timestamp to ensure unique target/task names
        now = str(datetime.utcnow())

        # Create scan target for provided IP
        target_resp = gmp.create_target(
            name="RiskForge Target " + target_ip + " " + now,
            hosts=[target_ip],
            port_list_id=PORT_LIST_ID)
        target_id = target_resp.get("id")

        # Create scan task linked to the target
        task_resp = gmp.create_task(
            name="RiskForge Task " + target_ip + " " + now,
            config_id=SCAN_CONFIG_ID,
            target_id=target_id,
            scanner_id=SCANNER_ID)
        task_id = task_resp.get("id")

        # Start the scan task
        gmp.start_task(task_id)

        # Attempt to retrieve report ID immediately (may not yet exist)
        report_id = None

        # Fetch tasks and locate the created task
        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")

        if t is not None:
            # Extract current report ID if available
            current_report = t.find("./current_report/report")
            if current_report is not None:
                report_id = current_report.get("id")

        # Return identifiers for tracking scan progress and results
        return task_id, report_id
    
def get_gvm_task_status(task_id):
    """
    Retrieve the current status and progress of a GVM scan task

    Queries GVM for the specified task ID, extracts the task status and
    progress percentage, returns them in a usable format
    """

    # Establish TLS connection to GVM
    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    # Open GVM session
    with GMP(connection=connection, transform=transform) as gmp:
        # Authenticate with GVM
        gmp.authenticate(USERNAME, PASSWORD)

        # Retrieve list of tasks and locate the requested task
        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")

        # If task cannot be found, return default unknown state
        if t is None:
            return "Unknown", 0

        # Extract status and progress values from XML
        status = (t.findtext("./status") or "").strip()
        progress = (t.findtext("./progress") or "0").strip()

        # Convert progress to integer and normalise edge cases
        try:
            progress = int(progress)

            # GVM returns -1 when completed, changed to 100 for readability
            if progress == -1:
                progress = 100

        except:
            # Fallback if conversion fails
            progress = 0

        # Return current task status and progress percentage
        return status, progress

def get_gvm_findings(report_id, limit=200):
    """
    Retrieve and process findings from a GVM report.

    Fetches the specified report from GVM, extracts individual results,
    sorts them by severity and returns a list of simplified finding
    dictionaries containing key vulnerability information
    """
        
    # Establish TLS connection to GVM
    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    # Open GVM session and authenticate
    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        # Retrieve full report with detailed results
        report_xml = gmp.get_report(
            report_id=report_id,
            details=True,
            filter_string="rows=1000")

    # Extract all results from report XML
    results = report_xml.findall(".//report/results/result")

    # Helper function to convert severity to float
    # Used for sorting results by severity (highest first)
    def severity_float(result):
        severity_text = result.findtext("severity")
        try:
            return float(severity_text)
        except Exception:
            return 0.0

    # Sort results by severity in descending order
    results_sorted = sorted(results, key=severity_float, reverse=True)

    findings = []

    # Process top results up to specified limit
    for result in results_sorted[:limit]:

        # Extract basic fields from result
        port = (result.findtext("port") or "").strip() or None

        sev_text = (result.findtext("severity") or "").strip()
        try:
            severity = float(sev_text) if sev_text else 0.0
        except Exception:
            severity = 0.0

        # Extract NVT (vulnerability test) details
        nvt = result.find("nvt")
        nvt_name = None
        solution = None
        cves = []

        if nvt is not None:
            # Vulnerability name
            nvt_name = (nvt.findtext("name") or "").strip() or None

            # Recommended solution
            solution = (nvt.findtext("solution") or "").strip() or None

            # Extract CVE references
            for ref in nvt.findall(".//refs/ref"):
                ref_type = (ref.get("type") or "").lower()

                # Only include CVE references
                if ref_type == "cve":
                    cve_id = ref.get("id")
                    if cve_id:
                        cves.append(cve_id.strip())

        # Append processed finding to results list
        findings.append({
            "port": port,
            "cvss_score": severity,
            "nvt_name": nvt_name,
            "cves": cves,
            "solution": solution,
        })

    # Return parsed list of findings
    return findings