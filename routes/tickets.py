from flask import Blueprint, render_template, request, redirect, session
from db import execute_query
from services.audit_service import log_event

tickets_bp = Blueprint("tickets", __name__)

@tickets_bp.route("/tickets", methods=["GET"])
def tickets():
    """
    Display all tickets (newest first).
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")
    status = request.args.get("status")
    priority = request.args.get("priority")
    
    try:
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
        filter_parameters = []

        # Filter by status
        if status is not None and status != "":
            sql = sql + " AND tickets.status = %s"
            filter_parameters.append(status)

        # Filter by priority
        if priority is not None and priority != "":
            sql = sql + " AND tickets.priority = %s"
            filter_parameters.append(priority)

        # Always add ordering at the end
        sql = sql + " ORDER BY tickets.created_at DESC"
        filter_parameters = tuple(filter_parameters)
        # Execute query
        ticket_list = execute_query(sql, filter_parameters, "all")

    except Exception as e:
        ticket_list = []
        print("Error loading tickets:", e)

    return render_template(
        "tickets.html",
        tickets=ticket_list,
        username=session["username"],
        role=session["role"])

@tickets_bp.route("/tickets/<int:ticket_id>", methods=["GET"])
def ticket_detail(ticket_id):
    """
    Display a single ticket and show a simple status update form.
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")

    try:
        sql = """
        SELECT
        tickets.*,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM tickets
        JOIN assets ON tickets.asset_id = assets.asset_id
        WHERE tickets.ticket_id = %s
        """
        ticket = execute_query(sql, (ticket_id),"one")

        if ticket is None:
            return "Ticket not found"

        return render_template(
            "ticket_detail.html",
            ticket=ticket,
            username=session["username"],
            role=session["role"])

    except Exception as e:
        return "Error loading ticket: " + str(e)

@tickets_bp.route("/tickets/<int:ticket_id>/update", methods=["POST"])
def update_ticket(ticket_id):
    """
    Update ticket status and optional closed reason
    If the status is set to Closed, a reason is required
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")

    # Obtain data from page forms
    status = request.form.get("status", "Open").strip()
    closed_reason = request.form.get("closed_reason", "").strip()

    # If user closes ticket, force a reason
    if status == "Closed" and not closed_reason:
        return redirect(f"/tickets/{ticket_id}?err=reason_required")

    try:
        sql = """
        SELECT status
        FROM tickets
        WHERE ticket_id = %s
        """
        current_ticket = execute_query(sql, (ticket_id), "one")

        if current_ticket is None:
            return "Ticket not found"

        old_status = current_ticket["status"]

        # If closing set closed_at and store reason values
        if status == "Closed":
            sql = """
            UPDATE tickets
            SET status=%s,
            closed_reason=%s,
            closed_at=NOW()
            WHERE ticket_id=%s
            """
            execute_query(sql,(status, closed_reason, ticket_id,))

            log_event(
                session["user_id"],
                "TICKET_CLOSED",
                "TICKET",
                ticket_id,
                f"Ticket closed. Reason: {closed_reason}"
            )

        else:
            # If re-opening clear close fields
            sql = """
            UPDATE tickets
            SET status=%s,
                closed_reason=NULL,
                closed_at=NULL
            WHERE ticket_id=%s
            """
            execute_query(sql, (status, ticket_id,))
       
        if old_status != status:
            log_event(
                session["user_id"],
                "TICKET_STATUS_CHANGE",
                "TICKET",
                ticket_id,
                f"Ticket status changed from {old_status} to {status}"
            )
        return redirect(f"/tickets/{ticket_id}")
    
    except Exception as e:
        return "Error updating ticket: " + str(e)