import threading
import time
from db import execute_query
from services.gvm_services import get_gvm_task_status
from services.gvm_services import get_gvm_findings
from services.scoring_service import riskforge_score_calc

def store_findings(scan_id, asset_id, findings, created_by, min_score=4.0):
    """
    Stores parsed scan findings in the findings table and auto-creates
    tickets for findings above the RiskForge score threshold.

    Parameters:
        scan_id (int): ID of the scan the findings belong to
        asset_id (int): ID of the scanned asset
        findings (list): List of finding dictionaries
        created_by (int): user_id of the person creating tickets
        min_score (float): minimum RiskForge score required to create a ticket
    """

    # Fetch asset criticality and exposure for score calculation
    sql = """
    SELECT criticality, exposure
    FROM assets
    WHERE asset_id = %s
    """
    asset = execute_query(sql,(asset_id),"one")

    criticality = asset["criticality"] if asset else "MEDIUM"
    exposure = asset["exposure"] if asset else "PUBLIC"

    for f in findings:

        port = f.get("port")
        cvss_score = f.get("cvss_score") or 0
        nvt_name = f.get("nvt_name") or "Unnamed finding"
        solution = f.get("solution") or ""

        cves_list = f.get("cves", [])
        cves = ", ".join(cves_list)

        riskforge_score = riskforge_score_calc(float(cvss_score), criticality, exposure)

        if riskforge_score is None:
            riskforge_score = 0

        sql = """
        INSERT INTO findings(
        scan_id, 
        asset_id, 
        nvt_name, 
        port, 
        cvss_score, 
        cves, 
        solution, 
        riskforge_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(
            sql,
            (
                scan_id,
                asset_id,
                nvt_name,
                port,
                cvss_score,
                cves,
                solution,
                riskforge_score
            )
        )

        # Auto-create ticket if RiskForge score meets threshold
        if float(riskforge_score) >= float(min_score):
            if riskforge_score >= 9:
                priority = "Critical"
            elif riskforge_score >= 7:
                priority = "High"
            elif riskforge_score >= 4:
                priority = "Medium"
            else:
                priority = "Low"

            title = nvt_name

            description = (
                f"Source: Scan #{scan_id}\n"
                f"Asset ID: {asset_id}\n"
                f"Port: {port or '-'}\n"
                f"CVSS: {cvss_score}\n"
                f"RiskForge Score: {riskforge_score}\n"
                f"CVEs: {cves if cves else 'None'}\n\n"
                f"Solution:\n{solution if solution else 'No solution provided.'}"
            )

            ticket_sql = """
            INSERT INTO tickets (
            asset_id,
            scan_id,
            created_by,
            title,
            priority,
            status,
            description,
            riskforge_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            execute_query(
                ticket_sql, 
                (
                    asset_id,
                    scan_id,
                    created_by,
                    title,
                    priority,
                    "Open",
                    description,
                    riskforge_score
                )
            )

def check_active_scans():
    """
    Finds all scans that are still in progress and polls
    GVM to update their status and progress in the database.
    """
    sql = """
    SELECT scan_id, gvm_task_id, engine
    FROM scans
    WHERE engine IN ('GVM', 'Full')
    AND status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed', 'GVM Complete')
    AND gvm_task_id IS NOT NULL
    """
    active_scans = execute_query(sql, None, "all")

    for scan in active_scans:
        scan_id = scan["scan_id"]
        task_id = scan["gvm_task_id"]
        engine = scan["engine"]

        status, progress = get_gvm_task_status(task_id)

        # Debug Print
        print(f"Scan {scan_id} is currently {status} and is at {progress}%")

        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

        if status in FINISHED_STATES:
            # For Full scans mark GVM complete but don't close the scan yet
            if engine == "Full":
                new_status = "GVM Complete"
            else:
                new_status = status

            sql = """
            UPDATE scans
            SET status=%s, progress=%s, finished_at=NOW()
            WHERE scan_id=%s
            """
            execute_query(sql, (new_status, progress, scan_id))
        else:
            sql = """
            UPDATE scans
            SET status=%s, progress=%s
            WHERE scan_id=%s
            """
            execute_query(sql, (status, progress, scan_id))

def check_finished_scans():
    """
    Closes out Full scans where both GVM and AI are complete,
    and parses GVM findings for any completed scans not yet processed.
    """
    
    # Close Full scans where GVM is done and AI is already done
    sql = """
    SELECT scan_id
    FROM scans
    WHERE engine = 'Full'
    AND status = 'GVM Complete'
    AND ai_complete = 1
    """
    ready_to_close = execute_query(sql, None, "all")

    for scan in ready_to_close:
        sql = """
        UPDATE scans
        SET status = 'Done'
        WHERE scan_id = %s
        """
        execute_query(sql, (scan["scan_id"]))

    # Parse GVM findings for completed scans not yet processed
    sql = """
    SELECT scan_id, asset_id, gvm_report_id, started_by
    FROM scans
    WHERE engine IN ('GVM', 'Full')
    AND status = 'Done'
    AND findings_parsed = 0
    AND gvm_report_id IS NOT NULL
    """
    finished_scans = execute_query(sql, None, "all")

    for scan in finished_scans:
        scan_id = scan["scan_id"]
        asset_id = scan["asset_id"]
        report_id = scan["gvm_report_id"]
        created_by = scan["started_by"]

        try:
            findings = get_gvm_findings(report_id, limit=200)

            store_findings(scan_id, asset_id, findings, created_by)

            sql = """
            UPDATE scans
            SET findings_parsed = 1
            WHERE scan_id = %s
            """
            execute_query(sql, (scan_id))

            print("Auto-parsed findings for scan " + str(scan_id))

        except Exception as e:
            print("Error auto-parsing scan " + str(scan_id) + ": " + str(e))

def start_worker():
    """
    Starts the background worker thread that monitors active scans
    """
    print("Worker running...")
    worker_thread = threading.Thread(target=worker_loop)
    worker_thread.daemon = True
    worker_thread.start()

def worker_loop():
    """
    Runs continuously in the background and checks every 30 seconds
    """
    while True:
        print("Checking for scans...")
        check_active_scans()
        check_finished_scans()
        time.sleep(30)