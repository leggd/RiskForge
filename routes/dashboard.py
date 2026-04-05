from flask import Blueprint, render_template, redirect, session, abort
from services.system_health import check_gvm_connection, check_ai_connection, check_db_connection, check_web_server
from db import execute_query

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
def dashboard():
    """
    Render the dashboard page
    """
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Get system statuses
        gvm_status = check_gvm_connection()
        ai_status = check_ai_connection()
        db_status = check_db_connection()
        web_status = check_web_server()

        # Assets
        sql = "SELECT COUNT(*) AS count FROM assets WHERE retired = FALSE"
        active_assets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM assets WHERE retired = TRUE"
        retired_assets = execute_query(sql, None, "one")["count"]

        total_assets = active_assets + retired_assets

        # Scans
        sql = "SELECT COUNT(*) AS count FROM scans"
        total_scans = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM scans WHERE status NOT IN ('Done','Stopped','Interrupted','Aborted','Failed')"
        active_scans = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM scans WHERE status = 'Done'"
        completed_scans = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM scans WHERE status = 'Failed'"
        failed_scans = execute_query(sql, None, "one")["count"]

        # Findings
        sql = "SELECT COUNT(*) AS count FROM findings"
        total_findings = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM findings WHERE riskforge_score >= 9"
        critical_findings = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM findings WHERE riskforge_score >= 7 AND riskforge_score < 9"
        high_findings = execute_query(sql, None, "one")["count"]

        # Tickets
        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status = 'Open'"
        open_tickets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status = 'In Progress'"
        in_progress_tickets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status='Open' AND priority='Critical'"
        critical_tickets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status='Open' AND priority='High'"
        high_tickets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status='Open' AND priority='Medium'"
        medium_tickets = execute_query(sql, None, "one")["count"]

        sql = "SELECT COUNT(*) AS count FROM tickets WHERE status='Open' AND priority='Low'"
        low_tickets = execute_query(sql, None, "one")["count"]

        # Most affected assets
        sql = """
        SELECT 
        assets.name,
        COUNT(findings.finding_id) AS finding_count,
        MAX(findings.riskforge_score) AS max_score
        FROM findings
        JOIN assets ON findings.asset_id = assets.asset_id
        GROUP BY assets.asset_id
        ORDER BY max_score DESC, finding_count DESC
        LIMIT 5
        """
        top_assets = execute_query(sql, None, "all")

        # Recent scans
        sql = """
        SELECT scans.status, scans.progress, scans.started_at, assets.name AS asset_name
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        ORDER BY scans.started_at DESC
        LIMIT 5
        """
        recent_scans = execute_query(sql, None, "all")

    except Exception as e:
        print(e)
        abort(500, description="Dashboard failed to load due to database error")

    metrics = {
        "total_assets":total_assets,
        "active_assets":active_assets,
        "retired_assets":retired_assets,
        "total_scans":total_scans,
        "active_scans":active_scans,
        "completed_scans":completed_scans,
        "failed_scans":failed_scans,
        "total_findings":total_findings,
        "critical_findings":critical_findings,
        "high_findings":high_findings,
        "open_tickets":open_tickets,
        "in_progress_tickets":in_progress_tickets,
        "critical_tickets":critical_tickets,
        "high_tickets":high_tickets,
        "medium_tickets":medium_tickets,
        "low_tickets":low_tickets}

    return render_template(
        "dashboard.html",
        metrics=metrics,
        top_assets=top_assets,
        recent_scans=recent_scans,
        gvm_status=gvm_status,
        ai_status=ai_status,
        db_status=db_status,
        web_status=web_status,
        username=session["username"],
        role=session["role"])