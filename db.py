import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """
    Creates and returns a MySQL connection using environment variables
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor
    )

def execute_query(query, params=None, fetch="none"):
    """
    Handles running SQL queries to reduce repeating connection code
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)

    result = None

    if fetch == "none":
        conn.commit()
        last_row_id = cur.lastrowid
    elif fetch == "one":
        result = cur.fetchone()
    elif fetch == "all":
        result = cur.fetchall()

    cur.close()
    conn.close()

    if fetch == "none":
        return last_row_id
    else:
        return result