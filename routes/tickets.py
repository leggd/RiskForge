from flask import Blueprint, render_template, request, redirect, session, abort
from db import execute_query
from services.audit_service import log_event
from services.auth_utils import require_role
from services.ai_service import generate_ai

tickets_bp = Blueprint("tickets", __name__)

@tickets_bp.route("/tickets", methods=["GET"])
def tickets():
    """
    Render the tickets page

    Displays all tickets with optional filtering by status and
    priority, ordered by risk score and creation date
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # Retrieve optional filter parameters from query string
    status = request.args.get("status")
    priority = request.args.get("priority")
    asset_id = request.args.get("asset_id")

    try:
        # Retrieve tickets with associated asset details
        sql = """
        SELECT
        tickets.ticket_id,
        tickets.title,
        tickets.priority,
        tickets.status,
        tickets.created_at,
        tickets.closed_at,
        tickets.riskforge_score,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM tickets
        JOIN assets ON tickets.asset_id = assets.asset_id
        WHERE 1=1
        """
        # Retrieve active assets for filter dropdown
        assets_sql = """
        SELECT asset_id, name
        FROM assets
        WHERE retired = FALSE
        ORDER BY name ASC
        """
        asset_list = execute_query(assets_sql, None, "all")
        
        filter_parameters = []

        # Apply status filter if provided
        if status is not None and status != "":
            sql += " AND tickets.status = %s"
            filter_parameters.append(status)

        # Apply priority filter if provided
        if priority is not None and priority != "":
            sql += " AND tickets.priority = %s"
            filter_parameters.append(priority)
        
        # Apply asset filter if provided
        if asset_id is not None and asset_id != "":
            sql += " AND tickets.asset_id = %s"
            filter_parameters.append(asset_id)

        # Apply ordering by risk score and creation date
        sql += "ORDER BY riskforge_score DESC, created_at DESC"
        filter_parameters = tuple(filter_parameters)

        # Obtain ticket list with applied filters
        ticket_list = execute_query(sql, filter_parameters, "all")

    except Exception as e:
        # Fallback to empty list if database query fails
        ticket_list = []
        print("Error loading tickets: " + str(e))

    # Render tickets page with retrieved data
    return render_template(
        "tickets.html",
        tickets=ticket_list,
        assets=asset_list,
        username=session["username"],
        role=session["role"])

@tickets_bp.route("/tickets/<int:ticket_id>", methods=["GET"])
def ticket_detail(ticket_id):
    """
    Render the ticket detail page

    Displays a single ticket with associated asset information
    and provides a status update interface.
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Retrieve ticket details with associated asset information
        sql = """
        SELECT
        tickets.*,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM tickets
        JOIN assets ON tickets.asset_id = assets.asset_id
        WHERE tickets.ticket_id = %s
        """
        ticket = execute_query(sql, (ticket_id), "one")

        # Handle missing ticket record (should never happen)
        if ticket is None:
            return "Ticket not found"

        # Render ticket detail page with retrieved data
        return render_template(
            "ticket_detail.html",
            ticket=ticket,
            username=session["username"],
            role=session["role"])

    # Handle unexpected errors during retrieval
    except Exception as e:
        return "Error loading ticket: " + str(e)

@tickets_bp.route("/tickets/<int:ticket_id>/update", methods=["POST"])
def update_ticket(ticket_id):
    """
    Update a ticket

    Validates status changes, enforces reason when closing,
    updates the ticket record and logs status transition.
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")
    
    # RBAC for ticket updating
    if not require_role("ADMIN"):
        abort(403, description="Only admins can update tickets")
        
    # Retrieve form input
    status = request.form.get("status", "Open").strip()
    closed_reason = request.form.get("closed_reason", "").strip()

    # Enforce reason when closing a ticket
    if status == "Closed" and not closed_reason:
        return redirect(f"/tickets/{ticket_id}?err=reason_required")

    try:
        # Retrieve current ticket status for comparison
        sql = """
        SELECT status
        FROM tickets
        WHERE ticket_id = %s
        """
        current_ticket = execute_query(sql, (ticket_id), "one")

        # Handle missing ticket record (should never happen)
        if current_ticket is None:
            return "Ticket not found"

        old_status = current_ticket["status"]

        # Handle ticket closure (set reason and timestamp)
        if status == "Closed":
            sql = """
            UPDATE tickets
            SET status=%s,
            closed_reason=%s,
            closed_at=NOW()
            WHERE ticket_id=%s
            """
            execute_query(sql, (status, closed_reason, ticket_id))

            # Record audit log for ticket closure
            log_event(
                session["user_id"],
                "TICKET_CLOSED",
                "TICKET",
                ticket_id,
                f"Ticket closed. Reason: {closed_reason}"
            )

        else:
            # Handle reopening or status change (clear closure fields)
            sql = """
            UPDATE tickets
            SET status=%s,
            closed_reason=NULL,
            closed_at=NULL
            WHERE ticket_id=%s
            """
            execute_query(sql, (status, ticket_id))
       
        # Log status change if different from previous state
        if old_status != status:
            log_event(
                session["user_id"],
                "TICKET_STATUS_CHANGE",
                "TICKET",
                ticket_id,
                f"Ticket status changed from {old_status} to {status}"
            )

        # Redirect to ticket detail page after update
        return redirect(f"/tickets/{ticket_id}")
    
    # Handle unexpected errors during update
    except Exception as e:
        return "Error updating ticket: " + str(e)

@tickets_bp.route("/tickets/<int:ticket_id>/ai", methods=["POST"])
def generate_ticket_ai(ticket_id):
    """
    Generate AI analysis for a ticket and store the result
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")
    
    # RBAC for ai generation
    if not require_role("ADMIN"):
        abort(403, description="Only admins can generate AI summaries")

    # Get ticket from DB
    sql = "SELECT * FROM tickets WHERE ticket_id = %s"
    ticket = execute_query(sql, (ticket_id), "one")

    if not ticket:
        abort(404)

    # Run AI using description
    description = ticket.get("description", "")
    ai_output = generate_ai(description)

    # Save result to DB
    sql = """
    UPDATE tickets
    SET ai_summary = %s,
    ai_generated_at = NOW()
    WHERE ticket_id = %s
    """
    execute_query(sql, (ai_output, ticket_id))

    # Go back to specific ticket detail page
    return redirect(f"/tickets/{ticket_id}")