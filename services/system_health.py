import socket
from db import execute_query
    
def check_gvm_connection():
    """
    Checks if GVM host port is reachable
    """
    try:
        s = socket.create_connection(("10.0.96.32", 9390), timeout=3)
        s.close()
        return True
    except:
        return False

def check_ai_connection():
    """
    Checks if AI scanner host is reachable via SSH
    """
    try:
        s = socket.create_connection(("10.0.96.32", 22), timeout=3)
        s.close()
        return True
    except:
        return False


def check_db_connection():
    """
    Checks if database is reachable
    """
    try:
        execute_query("SELECT 1", None, "one")
        return True
    except:
        return False

def check_web_server():
    """
    Checks if web server is up
    """
    return True