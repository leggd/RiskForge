from flask import Blueprint, render_template, request, redirect, session, abort
from services.auth_utils import require_role
from db import execute_query

audit_bp = Blueprint("audit", __name__)

@audit_bp.route("/audit")
def audit_logs():
    """
    Render audit log page

    Displays recent system and user activity from audit_log table
    with optional filtering
    """

    if "user_id" not in session:
        return redirect("/login")

    if not require_role("ADMIN"):
        abort(403)

    # Retrieve optional filter parameters from query string
    action = request.args.get("action")
    user = request.args.get("user")

    try:
        # Retrieve audit logs with associated users
        sql = """
        SELECT
        audit_log.created_at,
        audit_log.action,
        audit_log.details,
        audit_log.ip_address,
        users.username
        FROM audit_log
        LEFT JOIN users ON audit_log.user_id = users.user_id
        WHERE 1=1
        """

        # Retrieve users for dropdown
        users_sql = """
        SELECT user_id, username
        FROM users
        WHERE retired = FALSE
        ORDER BY username ASC
        """
        users = execute_query(users_sql, None, "all")

        filter_parameters = []

        # Apply action filter if provided
        if action is not None and action != "":
            sql += " AND audit_log.action = %s"
            filter_parameters.append(action)

        # Apply user filter if provided
        if user is not None and user != "":
            if user == "SYSTEM":
                sql += " AND audit_log.user_id IS NULL"
            else:
                sql += " AND audit_log.user_id = %s"
                filter_parameters.append(user)

        # Order by created descending order
        sql += " ORDER BY audit_log.created_at DESC"

        filter_parameters = tuple(filter_parameters)

        # Execute built query with chosen filter parameters 
        logs = execute_query(sql, filter_parameters, "all")

    except Exception as e:
        logs = []
        users = []

    return render_template(
        "audit.html",
        logs=logs,
        users=users,
        username=session["username"],
        role=session["role"])