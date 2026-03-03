import os
from flask import Flask, request, redirect, url_for, session, render_template
import pymysql
from dotenv import load_dotenv
import bcrypt
from pymysql.err import IntegrityError
from services.gvm_service import start_gvm_scan, get_gvm_task_status
from services.remote_scanner import run_ai_scan
import json
import datetime

# Load environment variables for DB details, api keys etc
load_dotenv()

# Initiate Flask application object
app = Flask(__name__)

# Set flask secret key for secure signed in sessions
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

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
        cursorclass=pymysql.cursors.DictCursor)

def log_event(user_id, action, entity_type, entity_id=None, details=None):
    """
    Inserts an entry into the audit_log table
    """
    try:
        ip_address = request.remote_addr

        conn = get_db_connection()
        cur = conn.cursor()

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

        cur.execute(
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
        conn.commit()
        
        cur.close()
        conn.close()

    except Exception as e:
        print("Audit Log Error:" + str(e))

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user authentication

    On GET request it displays login form (base_public.html+login.html)
    On POST request it obtains and validates submitted credentials,
    verifies password hash and creates session if successful
    """
    error = None
    if request.method == "POST":
        # Retrieve submitted credentials
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Obtain user record by entered username
            cur.execute("SELECT * FROM users WHERE username = %s",(username,))
            user = cur.fetchone()
            
            cur.close()
            conn.close()

            if user is None:
                # Log failed login attempt from unknown user + error message
                error = "User does not exist, contact your Administrator"
                log_event(
                    None,
                    "LOGIN_FAILED",
                    "USER",
                    None,
                    f"Attempted login with unknown username: {username}"
                )
            else:
                # Compare stored password with stored bcrpyt hash
                password_bytes = password.encode("utf-8")
                stored_hash_bytes = user["password_hash"].encode("utf-8")
                
                if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                    # Create session after successful authentication
                    session["user_id"] = user["user_id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    # Log successful login attempt and redirect to dashboard
                    log_event(
                        user["user_id"],
                        "LOGIN_SUCCESS",
                        "USER",
                        None,
                        f"User: {username} logged in successfully."
                        )
                    return redirect(url_for("dashboard"))
                else:
                    # Log incorrect credentials attempt
                    error = "Incorrect username or password"
                    log_event(
                        user["user_id"],
                        "LOGIN_FAILED",
                        "USER",
                        None,
                        f"User: {username} attempted login with incorrect password."
                        )
        
        # Handle any DB connection errors gracefully and pass to web page
        except Exception as e:
            error = str(e)
    # Display rendered login.html template and pass errors if appropriate
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    """
    Display main dashboard page for authenticate users,
    Redirects to login page if there is no active session
    """
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    return render_template(
        "dashboard.html",
        username=session['username'],
        role=session['role'])

@app.route("/logout")
def logout():
    """
    Log the current user out by clearing the session,
    redirect to log in page after
    """
    session.clear()
    return redirect(url_for("login"))

@app.route("/assets", methods=["GET", "POST"])
def assets():
    """
    Display and manage active assets.

    On GET request it retrieves and displays all non-retired assets
    On POST request it validates and inserts new assets into the database
    """
    # Require Authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    error = None
    success = None

    # Handle new asset submission from submitted form
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        asset_type = request.form.get("asset_type", "")
        exposure = request.form.get("exposure", "")
        criticality = request.form.get("criticality", "")
        
        # Basic validation and error message assignment
        if not name or not ip_address:
            error = "Name and/or IP address are required."
        else:
            try:
                conn = get_db_connection()
                cur = conn.cursor()

                # Insert new asset record to database
                sql = """
                INSERT INTO assets (
                name, 
                ip_address,
                asset_type,
                exposure,
                criticality
                ) 
                VALUES (%s, %s, %s, %s, %s)
                """
                cur.execute(
                    sql, 
                    (
                        name,
                        ip_address,
                        asset_type,
                        exposure,
                        criticality
                    )
                )
                conn.commit()

                cur.close()
                conn.close()

                success = "Asset added successfully."
            
            except Exception as e:
                error = "Error adding asset: " + str(e)
    
    # Retrieve all active assets to display in the table
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM assets WHERE retired = FALSE ORDER BY created_at DESC"
            )
        
        asset_list = cur.fetchall()

        cur.close()
        conn.close()

    # Catch DB error, create empty asset list and generate error string
    except Exception as e:
        asset_list = []
        error = "Database error: " + str(e)
    # Pass required data for rendering asset template
    return render_template(
        "assets.html",
        assets=asset_list,
        error=error,
        success=success,
        username=session["username"],
        role=session["role"])

@app.route("/assets/<int:asset_id>", methods=["GET"])
def asset_detail(asset_id):
    """
    Displays detailed information for a specific asset
    Enables optional edit mode via ?edit=1 parameter
    """
    # Require authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Determine if error mode needs to be enabled
    edit_mode = request.args.get("edit") == "1"

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Retrieve asset record by asset_id
        cur.execute(
            "SELECT * FROM assets WHERE asset_id = %s",
            (asset_id)
        )

        asset = cur.fetchone()

        cur.close()
        conn.close()

        # Will redirect to custom 404 page/error later
        if asset is None:
            return "Asset not found", 404

        return render_template(
            "asset_detail.html",
            asset=asset,
            edit_mode=edit_mode,
            username=session["username"],
            role=session["role"])

    except Exception as e:
        return "Error loading asset: " + str(e)

@app.route("/assets/<int:asset_id>/update", methods=["POST"])
def update_asset(asset_id):
    """
    Route to update an existing asset record

    Validates submitted form data and applies changes to the database

    Redirects back to edit mode if validation fails or a duplicate IP
    constraint triggered
    """

    # Require Authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Retrieve updated form values for asset
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "")
    exposure = request.form.get("exposure", "")
    criticality = request.form.get("criticality", "")

    # Error handling for empty name or IP
    if not name or not ip_address:
        return redirect(url_for("asset_detail",asset_id=asset_id)+"?edit=1")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Update record to new values by asset_id
        sql = """
        UPDATE assets
        SET name=%s,
        ip_address=%s,
        asset_type=%s,
        exposure=%s,
        criticality=%s
        WHERE asset_id=%s
        """
        cur.execute(sql, (name, ip_address, asset_type, exposure, criticality, asset_id))
        conn.commit()

        cur.close()
        conn.close()

        # Log asset update event
        log_event(
            session["user_id"],
            "UPDATE_ASSET",
            "ASSET",
            asset_id,
            f"Updated asset to name={name}, ip={ip_address},\
             type={asset_type}, exposure={exposure}, criticality={criticality}")

        return redirect(url_for("asset_detail", asset_id=asset_id))

    # Handle DB error due to unique IP constraint
    except IntegrityError:
        return redirect(url_for("asset_detail", asset_id=asset_id) + "?edit=1&err=duplicate_ip")
    
    # Handle any other error and provide error
    except Exception as e:
        return "Error updating asset: " + str(e)

@app.route("/assets/<int:asset_id>/retire", methods=["POST"])
def retire_asset(asset_id):
    """
    Soft delete an asset from visible list by setting retired flag to TRUE
    Redirects back to the assets list after completion
    """
    # Require authentication
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Update asset record to mark as retired instead of deleting
        cur.execute("UPDATE assets SET retired = TRUE WHERE asset_id = %s", (asset_id,))
        conn.commit()

        cur.close()
        conn.close()

        return redirect(url_for("assets"))

    except Exception as e:
        return f"Error retiring asset: " + str(e)

@app.route("/scans", methods=["GET", "POST"])
def scans():
    """
    Scan history page and scan launcher

    On POST it starts a new scan for a selected asset using the chosen engine (GVM or AI)
    On GET it updates progress for any running GVM scans and displays scan history
    """
    # Require Authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Handle new scan requrest
    if request.method == "POST":
        # Obtain asset_id and engine from form input
        asset_id = request.form.get("asset_id")
        engine = request.form.get("engine") 

        if asset_id:
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                # Obtain asset ip_address record using asset_id
                cur.execute(
                    "SELECT ip_address FROM assets WHERE asset_id = %s",
                    (asset_id)
                )

                asset = cur.fetchone()

                if asset is None:
                    # Handle missing asset, needs conversion to web page error
                    print("Asset not found")

                # Extract target_ip from obtained asset record
                target_ip = asset["ip_address"]

                # GVM Scan Handler
                if engine == "GVM":
                    # Obtain GVM task_id and report_id from GVM process
                    task_id, report_id = start_gvm_scan(target_ip)

                    sql = """
                    INSERT INTO scans (
                    asset_id,
                    started_by,
                    engine, 
                    gvm_task_id, 
                    gvm_report_id,
                    status,
                    progress) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """
                    # Insert scan record into database
                    cur.execute(
                        sql,
                        (
                            asset_id,
                            session["user_id"],
                            "GVM",
                            task_id,
                            report_id,
                            "Requested",
                            0
                        )
                    )
                    conn.commit()

                # AI Scan Handler
                elif engine == "AI":
                    sql = """
                    INSERT INTO scans (
                    asset_id,
                    started_by,
                    engine,
                    status,
                    progress)
                    VALUES (%s, %s, %s, %s, %s)
                    """
                    cur.execute(
                        sql,
                        (
                            asset_id,
                            session["user_id"],
                            "AI",
                            "Running",
                            0
                        )
                    )
                    scan_id = cur.lastrowid
                    conn.commit()
                    # Obtain scanner output (need to adapt scanner script yet)
                    result = run_ai_scan(target_ip) 

                    # Update scan status in database if failed
                    if result is None:
                        sql = """
                        UPDATE scans
                        SET status=%s,
                        error_message=%s,
                        finished_at=NOW()
                        WHERE scan_id=%s
                        """
                        cur.execute(
                            sql,
                            (
                                "Failed",
                                "AI scanner returned no data (check Kali script/output)",
                                scan_id
                            )
                        )
                        conn.commit()

                    else:
                        # When scanner app is configured to output json
                        # Will get the following
                        # scanner_output = raw tool logs
                        # ai_verdict = the AI final report
                        scanner_output = json.dumps(result)

                        sql = """
                        UPDATE scans
                        SET status=%s,
                        progress=%s,
                        scanner_output=%s,
                        finished_at=NOW()
                        WHERE scan_id=%s
                        """
                        cur.execute(
                            sql,
                            (
                                "Done",
                                100,
                                scanner_output,
                                scan_id
                            )
                        )
                        conn.commit()
                else:
                    # Error handling if web page allows unspecified engine
                    print("Unknown engine selected: ", engine)

                cur.close()
                conn.close()

            except Exception as e:
                print("Error starting scan: "  + str(e))
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Update progress for active GVM scans by polling GVM engine
        sql = """
        SELECT scan_id, gvm_task_id, status
        FROM scans
        WHERE engine = 'GVM' AND gvm_task_id IS NOT NULL
        """
        cur.execute(sql)   
        all_scans = cur.fetchall()

        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

        for scan in all_scans:
            scan_id = scan["scan_id"]
            task_id = scan["gvm_task_id"]
            current_status = scan["status"]

            # Skip scans already completed
            if current_status in FINISHED_STATES:
                continue

            # Obtain up to date status and progress from GVM engine
            status, progress = get_gvm_task_status(task_id)

            # Update scan record with finished state or current progress
            if status in FINISHED_STATES:
                sql = """
                UPDATE scans
                SET status=%s, progress=%s, finished_at=NOW()
                WHERE scan_id=%s
                """
                cur.execute(sql, (status, progress, scan_id))
            else:
                sql = """
                UPDATE scans
                SET status=%s, progress=%s
                WHERE scan_id=%s 
                """
                cur.execute(sql, (status, progress, scan_id))
        conn.commit()

        cur.close()
        conn.close()

    except Exception as e:
        print("Error updating scan progress: " + str(e))

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Obtain all scans and join with associated assets
        sql = """
        SELECT 
        scans.scan_id,
        scans.engine,
        scans.status,
        scans.progress,
        scans.started_at,
        scans.finished_at,
        assets.name AS asset_name,
        assets.ip_address
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        ORDER BY scans.started_at DESC
        """
        cur.execute(sql)

        scan_list = cur.fetchall()

        # Filter out retired assets
        sql = """
        SELECT asset_id, name 
        FROM assets 
        WHERE retired = FALSE 
        ORDER BY name ASC
        """
        cur.execute(sql)

        asset_list = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        scan_list = []
        asset_list = []
        print("Error loading scans: " + str(e))

    return render_template(
        "scans.html",
        scans=scan_list,
        assets=asset_list,
        username=session["username"],
        role=session["role"])


@app.route("/scans/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    """
    Displays detailed information for a specific scan

    Enables optional refresh via ?refresh=1 parameter
    to update progress for active scans
    """
    # Require Authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check for refresh argument from browser page
    refresh = request.args.get("refresh") == "1"

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Retrieve specific scan and asset details
        sql = """
        SELECT
        scans.*,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        WHERE scans.scan_id = %s
        """
        cur.execute(sql,(scan_id,))
        scan = cur.fetchone()

        if scan is None:
            cur.close()
            conn.close()
            # Return error, 404 page to come
            return "Scan not found", 404


        if refresh:
            FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

            # Only refresh unfinished scans
            if scan["status"] not in FINISHED_STATES:

                # Obtain latest status and progress from GVM engine
                if scan["engine"] == "GVM" and scan["gvm_task_id"]:
                    status, progress = get_gvm_task_status(scan["gvm_task_id"])
                    # Update status if finished or progress if not finished
                    if status in FINISHED_STATES:
                        sql = """
                        UPDATE scans
                        SET status=%s, progress=%s, finished_at=NOW()
                        WHERE scan_id=%s
                        """
                        cur.execute(sql,(status, progress, scan_id))
                    else:
                        sql = """
                        UPDATE scans
                        SET status=%s, progress=%s
                        WHERE scan_id=%s
                        """
                        cur.execute(sql,(status, progress, scan_id))
                    conn.commit()

                # If it is an AI scan it just reloads the page.

            # Re fetch scan data after potential updates to show updated info
            sql = """
            SELECT
            scans.*,
            assets.name AS asset_name,
            assets.ip_address AS asset_ip
            FROM scans
            JOIN assets ON scans.asset_id = assets.asset_id
            WHERE scans.scan_id = %s
            """
            cur.execute(sql, (scan_id,))
            scan = cur.fetchone()

        cur.close()
        conn.close()

        return render_template(
            "scan_detail.html",
            scan=scan,
            username=session["username"],
            role=session["role"])
    
    except Exception as e:
        return "Error loading scan: " + str(e)


@app.route("/scans/<int:scan_id>/ticket/new", methods=["GET", "POST"])
def ticket_from_scan(scan_id):
    """
    Create a new ticket linked to a scan
    On GET request it shows a pre-filled ticket form using scan output
    On POST request it validates input and inserts a new ticket into database
    """
    # Require authentication
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Obtain scan and asset info from database
            sql = """
            SELECT
            scans.*,
            assets.name AS asset_name,
            assets.ip_address AS asset_ip
            FROM scans
            JOIN assets ON scans.asset_id = assets.asset_id
            WHERE scans.scan_id = %s
            """
            cur.execute(sql,(scan_id))
            scan = cur.fetchone()

            cur.close()
            conn.close()

            if scan is None:
                # Error handling if no scan
                return "Scan not found", 404

            # Generate title with scan information
            default_title = (
            f"Ticket from {scan['engine']} scan on {scan['asset_name']}")

            # Generate default descript, prefer AI verdict, raw output then blank
            default_desc = ""
            if scan.get("ai_verdict"):
                default_desc = scan["ai_verdict"]
            elif scan.get("scanner_output"):
                default_desc = scan["scanner_output"]

            # Return generated defaults to web page renderer
            return render_template(
                "ticket_new.html",
                scan=scan,
                default_title=default_title,
                default_desc=default_desc,
                username=session["username"],
                role=session["role"])

        # This code block runs if POST request
        # Obtain form data
        title = request.form.get("title", "").strip()
        priority = request.form.get("priority", "Medium")
        status = request.form.get("status", "Open")
        description = request.form.get("description", "").strip()

        # Error handling (improve later)
        if not title:
            cur.close()
            conn.close()
            return "Title is required", 400

        # Obtain asset_id from scans
        sql = """
        SELECT asset_id FROM scans WHERE scan_id = %s
        """
        cur.execute(sql,(scan_id,))
        scan_row = cur.fetchone()

        #Error handling (improve later)
        if scan_row is None:
            cur.close()
            conn.close()
            return "Scan not found", 404

        # Create new ticket using obtained form data
        sql = """
        INSERT INTO tickets (
        asset_id,
        scan_id,
        created_by,
        title,
        priority,
        status,
        description)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cur.execute(
            sql,
            (
                scan_row["asset_id"],
                scan_id,
                session["user_id"],
                title,
                priority,
                status,
                description
            )
        )
        conn.commit()
        
        cur.close()
        conn.close()

        return redirect("/scans/" + str(scan_id))

    except Exception as e:
        return "Error creating ticket: " + str(e)

# Run Server
if __name__ == "__main__":
    app.run(debug=True)
