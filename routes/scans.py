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
    Displays scan history and asset list for scan launching.
    """
    if "user_id" not in session:
        return redirect("/login")

    try:
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

        sql = """
        SELECT asset_id, name 
        FROM assets 
        WHERE retired = FALSE 
        ORDER BY name ASC
        """
        asset_list = execute_query(sql, None, "all")

    except Exception as e:
        scan_list = []
        asset_list = []
        print("Error loading scans: " + str(e))

    return render_template(
        "scans.html",
        scans=scan_list,
        assets=asset_list,
        username=session["username"],
        role=session["role"]
    )

@scans_bp.route("/scans", methods=["POST"])
def start_scan():
    """
    Handles launching a new scan for a selected asset.
    Supports GVM, AI and Both running together.
    """
    if "user_id" not in session:
        return redirect("/login")

    asset_id = request.form.get("asset_id")
    engine = request.form.get("engine")

    if not asset_id:
        return redirect("/scans")

    try:
        sql = """
        SELECT ip_address
        FROM assets
        WHERE asset_id = %s
        """
        asset = execute_query(sql, (asset_id,), "one")

        if asset is None:
            print("Asset not found")
            return redirect("/scans")

        target_ip = asset["ip_address"]

        sql = """
        SELECT scan_id FROM scans 
        WHERE asset_id = %s 
        AND status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed', 'GVM Complete')
        """
        exists = execute_query(sql, (asset_id,), "one")

        if exists:
            return "Scan already running for this asset"

        # GVM Scan Handler
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

            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"GVM scan started for asset_id={asset_id}, task_id={task_id}"
            )

        # AI Scan Handler
        elif engine == "AI":
            sql = """
            INSERT INTO scans (
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

            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"AI scan started for asset_id={asset_id}"
            )

            user_id = session["user_id"]

            ai_solo_scan_thread = threading.Thread(target=run_scan_thread, args=(scan_id, target_ip, asset_id, user_id))
            ai_solo_scan_thread.daemon = True
            ai_solo_scan_thread.start()

        # Full Scan Handler
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

            log_event(
                session["user_id"],
                "START_SCAN",
                "SCAN",
                scan_id,
                f"Full scan started for asset_id={asset_id}"
            )

            user_id = session["user_id"]
            full_scan_thread = threading.Thread(target=run_full_ai_thread, args=(scan_id, target_ip, asset_id, user_id))
            full_scan_thread.daemon = True
            full_scan_thread.start()

        else:
            print("Unknown engine selected: " + str(engine))

    except Exception as e:
        print("Error starting scan: " + str(e))

    return redirect("/scans")

@scans_bp.route("/scans/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    """
    Displays detailed information for a specific scan.
    Enables optional refresh via ?refresh=1 parameter
    to update progress for active scans.
    """
    if "user_id" not in session:
        return redirect("/login")

    refresh = request.args.get("refresh") == "1"

    try:
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

        if scan is None:
            return "Scan not found", 404

        if refresh:
            FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

            if scan["status"] not in FINISHED_STATES:
                if scan["engine"] == "GVM" and scan["gvm_task_id"]:
                    status, progress = get_gvm_task_status(scan["gvm_task_id"])

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
        findings = []
        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")
        if (scan["engine"] == "GVM" or scan["engine"] == "Full"
            and scan["status"] in FINISHED_STATES
            and scan.get("gvm_report_id")):
            try:
                findings = get_gvm_findings(scan["gvm_report_id"], limit=200)
            except Exception as e:
                print("Error fetching GVM findings: " + str(e))
                findings = []

        # Fetch stored findings from database for this scan
        sql = """
        SELECT nvt_name, port, cvss_score, riskforge_score, cves, solution
        FROM findings
        WHERE scan_id = %s
        ORDER BY riskforge_score DESC
        """
        stored_findings = execute_query(sql, (scan_id,), "all")

        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            stored_findings=stored_findings,
            username=session["username"],
            role=session["role"],
        )

    except Exception as e:
        return "Error loading scan: " + str(e)