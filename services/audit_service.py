from db import execute_query
from flask import request

def log_event(user_id, action, entity_type, entity_id=None, details=None):
    """
    Inserts an entry into the audit_log table
    """
    try:
        ip_address = request.remote_addr

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