from flask import Blueprint, render_template, redirect, session
from db import execute_query

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
def dashboard():
    """
    Render the dashboard page

    Retrieves platform metrics including assets, scans, findings
    and tickets and passes them to the template
    """
    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Obtain active asset count
        sql = """
        SELECT COUNT(*) AS count
        FROM assets
        WHERE retired = FALSE
        """
        active_assets = execute_query(sql, None, "one")
        active_assets = active_assets["count"]

        # Obtain retired asset count
        sql = """
        SELECT COUNT(*) AS count 
        FROM assets 
        WHERE retired = TRUE
        """
        retired_assets = execute_query(sql, None, "one")
        retired_assets = retired_assets["count"]

        # Calculate total number of assets
        total_assets = active_assets + retired_assets

        # Obtain total scan count
        sql = """
        SELECT COUNT(*) AS count
        FROM scans
        """
        total_scans = execute_query(sql, None, "one")
        total_scans = total_scans["count"]

        # Obtain number of scans in progress
        sql = """
        SELECT COUNT(*) AS count
        FROM scans
        WHERE status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed')
        """
        active_scans = execute_query(sql, None, "one")
        active_scans = active_scans["count"]

        # Obtain total findings count
        sql = """
        SELECT COUNT(*) AS count
        FROM findings
        """
        total_findings = execute_query(sql, None, "one")
        total_findings = total_findings["count"]

        # Obtain count of critical findings (riskforge score >= 9)
        sql = """
        SELECT COUNT(*) AS count
        FROM findings
        WHERE riskforge_score >= 9
        """
        critical_findings = execute_query(sql, None, "one")
        critical_findings = critical_findings["count"]

        # Obtain count of high findings (riskforge store 7 to < 9)
        sql = """
        SELECT COUNT(*) AS count
        FROM findings 
        WHERE riskforge_score >= 7 AND riskforge_score < 9
        """
        high_findings = execute_query(sql, None, "one")
        high_findings = high_findings["count"]

        # Obtain count of open tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        """
        open_tickets = execute_query(sql, None, "one")
        open_tickets = open_tickets["count"]

        # Obtain count of in-progress tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'In Progress'
        """
        in_progress_tickets = execute_query(sql, None, "one")
        in_progress_tickets = in_progress_tickets["count"]

        # Obtain count of open critical-priority tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Critical'
        """
        critical_tickets = execute_query(sql, None, "one")
        critical_tickets = critical_tickets["count"]

        # Obtain count of open high-priority tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'High'
        """
        high_tickets = execute_query(sql, None, "one")
        high_tickets = high_tickets["count"]

        # Obtain count of open medium-priority tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Medium'
        """
        medium_tickets = execute_query(sql, None, "one")
        medium_tickets = medium_tickets["count"]

        # Obtain count of open low-priority tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Low'
        """
        low_tickets = execute_query(sql, None, "one")
        low_tickets = low_tickets["count"]

    except Exception as e:
        # Fallback to zero values if a database error occurs
        print("Dashboard DB error:", e)
        active_assets = 0
        retired_assets = 0
        total_assets = 0
        total_scans = 0
        active_scans = 0
        total_findings = 0
        critical_findings = 0
        high_findings = 0
        open_tickets = 0
        in_progress_tickets = 0
        critical_tickets = 0
        high_tickets = 0
        medium_tickets =0
        low_tickets = 0

    # Aggregate all metrics for template rendering
    metrics = {
        "total_assets":total_assets,
        "active_assets":active_assets,
        "retired_assets":retired_assets,
        "total_scans":total_scans,
        "active_scans":active_scans,
        "total_findings":total_findings,
        "critical_findings":critical_findings,
        "high_findings":high_findings,
        "open_tickets":open_tickets,
        "in_progress_tickets":in_progress_tickets,
        "critical_tickets":critical_tickets,
        "high_tickets":high_tickets,
        "medium_tickets":medium_tickets,
        "low_tickets":low_tickets,
    }

    # Render dashboard page with metrics
    return render_template(
        "dashboard.html",
        metrics=metrics,
        username=session["username"],
        role=session["role"])