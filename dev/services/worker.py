import threading
import time
def check_active_scans():
    from app import execute_query
    from services.gvm_service import get_gvm_task_status

    sql = """
    SELECT scan_id, gvm_task_id, engine FROM scans
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

        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

        if status in FINISHED_STATES:
            # For Full scans, mark GVM as complete but don't close the scan yet
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
    Finds all completed scans that have not had their findings
    stored yet and processes them automatically.
    """
    from app import execute_query
    from services.findings_service import store_findings


    # Check for Full scans ready to close
    sql = """
    SELECT scan_id, status, ai_complete FROM scans
    WHERE engine = 'Full'
    AND status = 'GVM Complete'
    AND ai_complete = 1
    """
    ready_to_close = execute_query(sql, None, "all")
    
    # Also close out Full scans where GVM is done and AI is already done
    sql = """
    SELECT scan_id FROM scans
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
        execute_query(sql, (scan["scan_id"],))

    # Debug — show all Full scans current state
    sql = """
    SELECT scan_id, status, ai_complete, findings_parsed FROM scans
    WHERE engine = 'Full'
    """
    full_scans = execute_query(sql, None, "all")
    print("All Full scans: " + str(full_scans))

    sql = sql = """
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
            from services.gvm_service import get_gvm_findings
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
    Starts the background worker thread that monitors active scans.
    Runs as a daemon so it stops automatically when the app stops.
    """
    thread = threading.Thread(target=worker_loop)
    thread.daemon = True
    thread.start()

def worker_loop():
    while True:
        check_active_scans()
        check_finished_scans()
        time.sleep(30)