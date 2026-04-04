from db import execute_query
from flask import request, has_request_context

def log_event(user_id, action, entity_type, entity_id=None, details=None):
    """
    Record an audit log entry for actions within the app

    Captures the acting user, action type, affected entity, optional details
    and the originating IP address, then stores the record in the audit_log table
    """
    try:
        # Obtain IP address only if a user initiated audit log
        ip_address = None
        if has_request_context():
            ip_address = request.remote_addr

        # Insert audit log record into database
        sql = """
        INSERT INTO audit_log (
        user_id, 
        action, 
        entity_type, 
        entity_id, 
        details, 
        ip_address
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """

        execute_query(
            sql,
            (
                user_id,
                action,
                entity_type,
                entity_id,
                details,
                ip_address
            )
        )

    except Exception as e:
        print("Audit Log Error: " + str(e))