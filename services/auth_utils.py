from flask import session

def require_role(required_role):
    """
    Checks if the current session user has the required role.
    Returns True if allowed, False otherwise.
    """
    return session.get("role") == required_role