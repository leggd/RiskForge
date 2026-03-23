from flask import Blueprint, render_template, request, redirect, session
from db import execute_query
from services.audit_service import log_event
from services.gvm_service import start_gvm_scan, get_gvm_task_status, get_gvm_findings
from services.scanner_service import run_scan_thread, run_full_ai_thread
import threading

scans_bp = Blueprint("scans", __name__)

@scans_bp.route("/scans", methods=["GET"])
def scans():
    """
    Render the scans page

    Displays scan history and provides a list of assets for
    initiating new scans
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Retrieve scan history with associated asset details
        sql = """
        SELECT 
        scans.scan_id,
        scans.engine,
        scans.status,
        scans.progress,
        scans.started_at,
        scans.finished_at,
        assets.name AS asset_name,
        assets.ip_address
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        ORDER BY scans.started_at DESC
        """
        scan_list = execute_query(sql, None, "all")

        # Retrieve list of active (non-retired) assets for scan selection
        sql = """
        SELECT asset_id, name 
        FROM assets 
        WHERE retired = FALSE 
        ORDER BY name ASC
        """
        asset_list = execute_query(sql, None, "all")

    except Exception as e:
        # Fallback to empty lists if database query fails
        scan_list = []
        asset_list = []
        print("Error loading scans: " + str(e))

    # Render scans page with history and available assets
    return render_template(
        "scans.html",
        scans=scan_list,
        assets=asset_list,
        username=session["username"],
        role=session["role"])

@scans_bp.route("/scans", methods=["POST"])
def start_scan():
    """
    Start a new scan for a selected asset

    Supports GVM, AI and combined scanning, validates the request,
    prevents duplicate active scans and initiates background workers
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # Retrieve selected asset and scan engine from form input
    asset_id = request.form.get("asset_id")
    engine = request.form.get("engine")

    # Validate required asset selection
    if not asset_id:
        return redirect("/scans")

    try:
        # Retrieve target IP address for selected asset
        sql = """
        SELECT ip_address
        FROM assets
        WHERE asset_id = %s
        """
        asset = execute_query(sql, (asset_id,), "one")

        # Handle missing asset record
        if asset is None:
            return redirect("/scans")

        target_ip = asset["ip_address"]

        # Check for existing active scan on this asset
        sql = """
        SELECT scan_id FROM scans 
        WHERE asset_id = %s 
        AND status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed', 'GVM Complete')
        """
        exists = execute_query(sql, (asset_id,), "one")

        if exists:
            return "Scan already running for this asset"

        # Handle GVM-only scan
        if engine == "GVM":
            task_id, report_id = start_gvm_scan(target_ip)

            sql = """
            INSERT INTO scans(
            asset_id,
            started_by,
            engine, 
            gvm_task_id, 
            gvm_report_id,
            status,
            progress) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            scan_id = execute_query(
                sql,
                (
                    asset_id,
                    session["user_id"],
                    "GVM",
                    task_id,
                    report_id,
                    "Requested",
                    0
                )
            )

            # Record audit log for GVM scan start
            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"GVM scan started for asset_id={asset_id}, task_id={task_id}"
            )

        # Handle AI-only scan
        elif engine == "AI":
            sql = """
            INSERT INTO scans(
            asset_id,
            started_by,
            engine,
            status,
            progress)
            VALUES (%s, %s, %s, %s, %s)
            """
            scan_id = execute_query(
                sql,
                (
                    asset_id,
                    session["user_id"],
                    "AI",
                    "Running",
                    0
                )
            )

            # Record audit log for AI scan start
            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"AI scan started for asset_id={asset_id}"
            )

            # Start AI scan in background thread
            user_id = session["user_id"]
            ai_solo_scan_thread = threading.Thread(
                target=run_scan_thread,
                args=(scan_id, target_ip, asset_id, user_id))
            ai_solo_scan_thread.daemon = True
            ai_solo_scan_thread.start()

        # Handle combined (GVM + AI) scan
        elif engine == "Full":
            task_id, report_id = start_gvm_scan(target_ip)

            sql = """
            INSERT INTO scans (
            asset_id,
            started_by,
            engine,
            gvm_task_id,
            gvm_report_id,
            status,
            progress)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            scan_id = execute_query(
                sql,
                (
                    asset_id,
                    session["user_id"],
                    "Full",
                    task_id,
                    report_id,
                    "Running",
                    0
                )
            )

            # Record audit log for full scan start
            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"Full scan started for asset_id={asset_id}"
            )

            # Start combined scan in background thread
            user_id = session["user_id"]
            full_scan_thread = threading.Thread(
                target=run_full_ai_thread,
                args=(scan_id, target_ip, asset_id, user_id))
            full_scan_thread.daemon = True
            full_scan_thread.start()

        else:
            # Handle invalid scan engine selection (should never happen)
            print("Unknown engine selected: " + str(engine))

    # Handle unexpected errors during scan initialisation
    except Exception as e:
        print("Error starting scan: " + str(e))

    # Redirect back to scans page after request handling
    return redirect("/scans")

@scans_bp.route("/scans/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    """
    Render the scan detail page

    Displays detailed information for a specific scan and supports
    optional refresh via the ?refresh=1 to update progress for active scans
    """
    FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")
    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # Determine whether refresh mode is enabled
    refresh = request.args.get("refresh") == "1"

    try:
        # Retrieve scan details with associated asset information
        sql = """
        SELECT
        scans.*,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        WHERE scans.scan_id = %s
        """
        scan = execute_query(sql, (scan_id,), "one")

        # Return 404 if scan does not exist (should never happen)
        if scan is None:
            return "Scan not found", 404

        # Refresh scan status and progress if requested
        if refresh:
            # Only update if scan is still active
            if scan["status"] not in FINISHED_STATES:
                # Get updated GVM scan progress if applicable
                if scan["engine"] == "GVM" and scan["gvm_task_id"]:
                    status, progress = get_gvm_task_status(scan["gvm_task_id"])

                    # Mark scan as finished if finished state observed
                    if status in FINISHED_STATES:
                        sql = """
                        UPDATE scans
                        SET status=%s,
                        progress=%s,
                        finished_at=NOW()
                        WHERE scan_id=%s
                        """
                        execute_query(sql, (status, progress, scan_id))
                    else:
                        # Update scan progress while still running
                        sql = """
                        UPDATE scans
                        SET status=%s, progress=%s
                        WHERE scan_id=%s
                        """
                        execute_query(sql, (status, progress, scan_id))

            # Re-fetch scan after refresh update
            sql = """
            SELECT
            scans.*,
            assets.name AS asset_name,
            assets.ip_address AS asset_ip
            FROM scans
            JOIN assets ON scans.asset_id = assets.asset_id
            WHERE scans.scan_id = %s
            """
            scan = execute_query(sql, (scan_id,), "one")

        # Fetch live findings from GVM for display    
        # Only retrieve GVM findings when scan is complete and report exists
        findings = []
        if (scan["engine"] == "GVM" or scan["engine"] == "Full"
            and scan["status"] in FINISHED_STATES
            and scan.get("gvm_report_id")):
            try:
                findings = get_gvm_findings(scan["gvm_report_id"], limit=200)
            except Exception as e:
                # Handle errors during GVM findings retrieval
                print("Error fetching GVM findings: " + str(e))
                findings = []

        # Retrieve stored findings from database for this scan
        sql = """
        SELECT nvt_name, port, cvss_score, riskforge_score, cves, solution
        FROM findings
        WHERE scan_id = %s
        ORDER BY riskforge_score DESC
        """
        stored_findings = execute_query(sql, (scan_id,), "all")

        # Render scan detail page with scan data and findings
        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            stored_findings=stored_findings,
            username=session["username"],
            role=session["role"])

    # Handle unexpected errors during scan retrieval
    except Exception as e:
        return "Error loading scan: " + str(e)