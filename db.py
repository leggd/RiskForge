import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """
    Create and return a database connection

    Uses environment variables to configure a MySQL connection
    and returns a connection with a dictionary cursor
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor)

def execute_query(query, params=None, fetch="none"):
    """
    Execute a database query

    Handles connection management, executes the query with optional
    parameters and returns results based on the specified fetch mode
    """

    # Establish database connection and create cursor
    conn = get_db_connection()
    cur = conn.cursor()

    # Execute query with optional parameters
    cur.execute(query, params)

    result = None

    # Determine fetch behaviour
    if fetch == "none":
        # Commit SQL transaction and capture last inserted row ID
        conn.commit()
        last_row_id = cur.lastrowid
    elif fetch == "one":
        # Retrieve a single result row
        result = cur.fetchone()
    elif fetch == "all":
        # Retrieve all result rows
        result = cur.fetchall()

    # Close cursor and connection to release resources
    cur.close()
    conn.close()

    # Return result or last inserted ID
    if fetch == "none":
        return last_row_id
    else:
        return result