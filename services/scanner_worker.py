import threading
import time
from db import execute_query
from services.gvm_service import get_gvm_task_status
from services.gvm_service import get_gvm_findings
from services.findings_service import store_findings, prioritise_findings
from services.ticket_service import create_tickets

# Finished scan states returned by GVM
FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

def check_active_scans():
    """
    Monitor active scans and update their status from GVM

    Queries the database for scans that are still in progress, retrieves
    their latest status and progress from GVM and updates the database.
    Handles standalone GVM scans and the GVM element of full scans
    """
    # Query all scans that are still active and have a GVM task ID
    sql = """
    SELECT scan_id, gvm_task_id, engine
    FROM scans
    WHERE engine IN ('GVM', 'Full')
    AND status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed', 'GVM Complete')
    AND gvm_task_id IS NOT NULL
    """
    active_scans = execute_query(sql, None, "all")

    # Iterate through each active scan and poll GVM for updates
    for scan in active_scans:
        scan_id = scan["scan_id"]
        task_id = scan["gvm_task_id"]
        engine = scan["engine"]

        # Retrieve current status and progress from GVM
        status, progress = get_gvm_task_status(task_id)

        # If GVM scan has finished
        if status in FINISHED_STATES:
            # For Full scans, mark only the GVM phase as complete
            if engine == "Full":
                new_status = "GVM Complete"
            else:
                # For GVM-only scans, use final status directly
                new_status = status

            # Update scan with final status, progress and completion timestamp
            sql = """
            UPDATE scans
            SET status=%s, progress=%s, finished_at=NOW()
            WHERE scan_id=%s
            """
            execute_query(sql, (new_status, progress, scan_id))

        else:
            # Update scan with current in-progress status and progress
            sql = """
            UPDATE scans
            SET status=%s, progress=%s
            WHERE scan_id=%s
            """
            execute_query(sql, (status, progress, scan_id))

def check_finished_scans():
    """
    Finalise completed scans and process any outstanding GVM findings

    Identifies full scans where both AI and GVM phases are complete and
    marks them as done. Retrieves and processes GVM findings for
    completed scans that have not yet been parsed including storing,
    prioritising and ticket creation.
    """

    # Retrieve Full scans where GVM has completed and AI phase is already done
    sql = """
    SELECT scan_id
    FROM scans
    WHERE engine = 'Full'
    AND status = 'GVM Complete'
    AND ai_complete = 1
    """
    ready_to_close = execute_query(sql, None, "all")

    # Mark these scans as fully completed
    for scan in ready_to_close:
        sql = """
        UPDATE scans
        SET status = 'Done'
        WHERE scan_id = %s
        """
        execute_query(sql, (scan["scan_id"]))

    # Select scans that are finished but the findings have not been processed
    sql = """
    SELECT scan_id, asset_id, gvm_report_id, started_by
    FROM scans
    WHERE engine IN ('GVM', 'Full')
    AND status = 'Done'
    AND findings_parsed = 0
    AND gvm_report_id IS NOT NULL
    """
    finished_scans = execute_query(sql, None, "all")

    # Iterate through completed scans and process findings
    for scan in finished_scans:
        scan_id = scan["scan_id"]
        asset_id = scan["asset_id"]
        report_id = scan["gvm_report_id"]
        created_by = scan["started_by"]

        try:
            # Retrieve findings from GVM report
            findings = get_gvm_findings(report_id, limit=100)

            # Store findings and calculate RiskForge scores
            findings = store_findings(scan_id, asset_id, findings)

            # Apply PoC prioritisation logic
            findings = prioritise_findings(findings)
            
            # Create tickets from prioritised findings
            create_tickets(scan_id, asset_id, findings, created_by)

            # Mark findings as processed to prevent duplicate processing
            sql = """
            UPDATE scans
            SET findings_parsed = 1
            WHERE scan_id = %s
            """
            execute_query(sql, (scan_id))

            # Update last_scanned_at time on asset record
            sql = """
            UPDATE assets
            SET last_scanned_at = NOW()
            WHERE asset_id = %s
            """
            execute_query(sql, (asset_id))
            # Debug print
            #print("Auto-parsed findings for scan " + str(scan_id))

        except Exception as e:
            # Handle parsing errors without stopping the worker
            print("Error auto-parsing scan " + str(scan_id) + ": " + str(e))

def start_worker():
    """
    Start the background worker for scan monitoring

    Launches a thread that continuously checks scan progress
    and processes completed scans without blocking main application
    """
    # Create background thread for worker loop
    worker_thread = threading.Thread(target=worker_loop)

    # Set as daemon so it stops when main application exits
    worker_thread.daemon = True

    # Start worker thread
    worker_thread.start()


def worker_loop():
    """
    Continuously monitor and process scans at regular intervals

    Infinite loop to periodically check active scans for status
    updates and processes completed scans every 30 seconds
    """
    while True:
        # Poll active scans for status updates from GVM
        check_active_scans()

        # Process completed scans and parse findings
        check_finished_scans()

        # Wait before next loop
        time.sleep(30)