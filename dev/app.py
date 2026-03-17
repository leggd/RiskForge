import os
from flask import Flask, request, redirect, session, render_template
import pymysql
from dotenv import load_dotenv
import bcrypt
from pymysql.err import IntegrityError
from services.gvm_service import start_gvm_scan, get_gvm_task_status
from services.remote_scanner import run_ping_sweep, run_os_detection, run_ai_scan
from services.gvm_service import get_gvm_findings
from services.findings_service import store_findings
import json
import ipaddress
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

def execute_query(query, params=None, fetch="none"):
    """
    Handles running SQL queries to reduce repeating connection codes
    """
    # Open a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()
    # Run the query, passing parameters seperately to prevent SQL injection
    cur.execute(query, params)

    # Commit changes for saving INSERT, UPDATE or DELETE queries
    if fetch == "none":
        conn.commit()
        last_row_id = cur.lastrowid

    # For SELECT, fetch and return the required data
    if fetch == "one":
        # Obtain single row as dictionary and obtain last row ID
        result = cur.fetchone()
    elif fetch == "all":
        # Return all rows as list of dictionaries
        result = cur.fetchall()
    else:
        result = None

    # Gracefully end session and DB connection when finished
    cur.close()
    conn.close()

    # Return row(s) or last_row_id to specified variable
    if fetch == "none":
        return last_row_id
    else:
        return result
    
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
            sql = "SELECT * FROM users WHERE username = %s"
            # Obtain user record by entered username
            user = execute_query(sql,(username),"one")

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
                        f"User: {username} logged in successfully.")
                    return redirect("/dashboard")
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
    Display main dashboard page for authenticated users
    Queries platform metrics and passes them to the template
    """
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Obtain active asset count
        sql = """
        SELECT COUNT(*) AS count
        FROM assets
        WHERE retired = FALSE
        """
        active_assets = execute_query(sql, None, "one")
        active_assets = active_assets["count"]

        # Obtain retired asset count
        sql = """
        SELECT COUNT(*) AS count 
        FROM assets 
        WHERE retired = TRUE
        """
        retired_assets = execute_query(sql, None, "one")
        retired_assets = retired_assets["count"]

        # Calculate total amount of assets regardless of status
        total_assets = active_assets + retired_assets

        # Obtain total scan count
        sql = """
        SELECT COUNT(*) AS count
        FROM scans
        """
        total_scans = execute_query(sql, None, "one")
        total_scans = total_scans["count"]

        # Obtain number of scans in progress
        sql = """
        SELECT COUNT(*) AS count
        FROM scans
        WHERE status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed')
        """
        active_scans = execute_query(sql, None, "one")
        active_scans = active_scans["count"]

        # Obtain all findings count
        sql = """
        SELECT COUNT(*) AS count
        FROM findings
        """
        total_findings = execute_query(sql, None, "one")
        total_findings = total_findings["count"]

        # Obtain findings with highest cvss score
        sql = """
        SELECT COUNT(*) AS count
        FROM findings
        WHERE cvss_score >= 9
        """
        critical_findings = execute_query(sql, None, "one")
        critical_findings = critical_findings["count"]

        # Obtain findings with high-ish score
        sql = """
        SELECT COUNT(*) AS count
        FROM findings 
        WHERE cvss_score >= 7 AND cvss_score < 9
        """
        high_findings = execute_query(sql, None, "one")
        high_findings = high_findings["count"]

        # Obtain count of open tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        """
        open_tickets = execute_query(sql, None, "one")
        open_tickets = open_tickets["count"]

        # Obtain count of in progress tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'In Progress'
        """
        in_progress_tickets = execute_query(sql, None, "one")
        in_progress_tickets = in_progress_tickets["count"]

        # Obtain count of open critical tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Critical'
        """
        critical_tickets = execute_query(sql, None, "one")
        critical_tickets = critical_tickets["count"]

        # Obtain count of open high tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'High'
        """
        high_tickets = execute_query(sql, None, "one")
        high_tickets = high_tickets["count"]

        # Obtain count of open medium tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Medium'
        """
        medium_tickets = execute_query(sql, None, "one")
        medium_tickets = medium_tickets["count"]

        # Obtain count of open low tickets
        sql = """
        SELECT COUNT(*) AS count
        FROM tickets
        WHERE status = 'Open'
        AND priority = 'Low'
        """
        low_tickets = execute_query(sql, None, "one")
        low_tickets = low_tickets["count"]


    except Exception as e:
        # On DB error, pass empty/zero data so the page still renders
        print("Dashboard DB error:", e)
        active_assets = retired_assets = total_assets = 0
        total_scans = active_scans = 0
        total_findings = critical_findings = high_findings = 0
        open_tickets = in_progress_tickets = 0
        critical_tickets = high_tickets = medium_tickets = low_tickets = 0

    metrics = {
        "total_assets":        total_assets,
        "active_assets":       active_assets,
        "retired_assets":      retired_assets,
        "total_scans":         total_scans,
        "active_scans":        active_scans,
        "total_findings":      total_findings,
        "critical_findings":   critical_findings,
        "high_findings":       high_findings,
        "open_tickets":        open_tickets,
        "in_progress_tickets": in_progress_tickets,
        "critical_tickets":    critical_tickets,
        "high_tickets":        high_tickets,
        "medium_tickets":      medium_tickets,
        "low_tickets":         low_tickets,
    }

    return render_template(
        "dashboard.html",
        metrics=metrics,
        username=session["username"],
        role=session["role"]
    )

@app.route("/logout")
def logout():
    """
    Log the current user out by clearing the session,
    redirect to log in page after
    """
    if "user_id" in session:
        log_event(
            session["user_id"],
            "LOGOUT",
            "USER",
            session["user_id"],
            f"User {session['username']} logged out."
        )
    session.clear()
    return redirect("/login")

@app.route("/assets", methods=["GET", "POST"])
def assets():
    """
    Display and manage active assets.

    On GET request it retrieves and displays all non-retired assets
    and runs a ping sweep to discover hosts on the network.
    On POST request it validates and inserts new assets into the database.
    """
    # Require Authentication
    if "user_id" not in session:
        return redirect("/login")

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
            # Attempt to make ipaddress object for input handling
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                error = "Invalid IP address format."
            if not error:
                try:
                    sql = """
                    SELECT asset_id FROM assets
                    WHERE ip_address = %s OR name = %s
                    """
                    exists = execute_query(sql, (ip_address, name), "one")
                    if exists:
                        error = "Asset with that name or IP address already exists"
                    else:
                        try:
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
                            asset_id = execute_query(
                                sql, 
                                (
                                    name,
                                    ip_address,
                                    asset_type,
                                    exposure,
                                    criticality
                                )
                            )

                            log_event(
                                session["user_id"],
                                "CREATE_ASSET",
                                "ASSET",
                                asset_id,
                                "Created asset name=" + name + ", ip=" + ip_address
                            )

                            success = "Asset added successfully."   
                        except Exception as e:
                            error = "Error adding asset: " + str(e)
                except Exception as e:
                    error = "Wider Error: " + str(e)

    # Run ping sweep to discover hosts on the network
    # Returns empty list if Kali is unreachable
    subnet = "10.0.96.0/24"
    discovered_hosts = run_ping_sweep(subnet)

    # If a specific IP was clicked, run OS detection on it
    selected_ip = request.args.get("ip")
    selected_os = None

    if selected_ip:
        result = run_os_detection(selected_ip)
        if result:
            selected_os = result["os"]

    # Retrieve all active assets to display in the table
    try:
        sql = """
        SELECT * FROM assets 
        WHERE retired = FALSE
        ORDER BY created_at DESC
        """        
        asset_list = execute_query(sql, None, "all")

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
        discovered_hosts=discovered_hosts,
        selected_ip=selected_ip,
        selected_os=selected_os,
        username=session["username"],
        role=session["role"]
    )

@app.route("/assets/<int:asset_id>", methods=["GET"])
def asset_detail(asset_id):
    """
    Displays detailed information for a specific asset
    Enables optional edit mode via ?edit=1 parameter
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")

    # Determine if error mode needs to be enabled
    edit_mode = request.args.get("edit") == "1"

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Retrieve asset record by asset_id
        sql = """
        SELECT * FROM assets
        WHERE asset_id = %s        
        """

        asset = execute_query(sql,(asset_id),"one")

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
        return redirect("/login")

    # Retrieve updated form values for asset
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "")
    exposure = request.form.get("exposure", "")
    criticality = request.form.get("criticality", "")

    # Error handling for empty name or IP
    if not name or not ip_address:
        return redirect(f"/assets/{asset_id}?edit=1")

    try:
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
        execute_query(
            sql, 
            (
                name,
                ip_address,
                asset_type,
                exposure,
                criticality,
                asset_id
            )
        )

        # Log asset update event
        log_event(
            session["user_id"],
            "UPDATE_ASSET",
            "ASSET",
            asset_id,
            f"Updated asset to name={name}, ip={ip_address},\
             type={asset_type}, exposure={exposure}, criticality={criticality}")

        return redirect(f"/assets/{asset_id}")

    # Handle DB error due to unique IP constraint
    except IntegrityError:
        return redirect(f"/assets/{asset_id}?edit=1&err=duplicate_ip")
    
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
        return redirect("/login")
    
    try:
        # Update asset record to mark as retired instead of deleting
        sql ="""
        UPDATE assets 
        SET retired = TRUE 
        WHERE asset_id = %s
        """              
        execute_query(sql, (asset_id))

        log_event(
            session["user_id"],
            "RETIRE_ASSET",
            "ASSET",
            asset_id,
            f"Asset {asset_id} marked as retired"
        )

        return redirect("/assets")

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
        return redirect("/login")

    # Handle new scan requrest
    if request.method == "POST":
        # Obtain asset_id and engine from form input
        asset_id = request.form.get("asset_id")
        engine = request.form.get("engine") 

        if asset_id:
            try:
                sql = """
                SELECT ip_address
                FROM assets
                WHERE asset_id = %s
                """
                # Obtain asset ip_address record using asset_id
                asset = execute_query(sql, (asset_id),"one")

                if asset is None:
                    # Handle missing asset, needs conversion to web page error
                    print("Asset not found")

                # Extract target_ip from obtained asset record
                target_ip = asset["ip_address"]

                sql = """
                SELECT scan_id FROM scans 
                WHERE asset_id = %s 
                AND status NOT IN ('Done', 'Stopped', 'Interrupted', 'Aborted', 'Failed')
                """
                exists = execute_query(sql,(asset_id),"one")
                
                if exists:
                    # Display error webpage, will implement inside page later
                    return "Scan already running for this asset"
                else:
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
                        scan_id = execute_query(
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

                        log_event(
                            session["user_id"],
                            "START_SCAN",
                            "SCAN",
                            scan_id,
                            f"GVM scan started for asset_id={asset_id}, task_id={task_id}"
                        )

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
                        scan_id = execute_query(
                            sql,
                            (
                                asset_id,
                                session["user_id"],
                                "AI",
                                "Running",
                                0
                            )
                        )
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
                            execute_query(
                                sql,
                                (
                                    "Failed",
                                    "AI scanner returned no data (check Kali script/output)",
                                    scan_id
                                )
                            )

                            log_event(
                                session["user_id"],
                                "SCAN_FAILED",
                                "SCAN",
                                scan_id,
                                "AI scanner returned no data"
                            )

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
                            execute_query(
                                sql,
                                (
                                    "Done",
                                    100,
                                    scanner_output,
                                    scan_id
                                )
                            )
                            
                            log_event(
                                session["user_id"],
                                "SCAN_COMPLETED",
                                "SCAN",
                                scan_id,
                                f"AI scan completed successfully for asset_id={asset_id}"
                            )
                    else:
                        # Error handling if web page allows unspecified engine
                        print("Unknown engine selected: ", engine)
            except Exception as e:
                print("Error starting scan: "  + str(e))
    try:
        # Update progress for active GVM scans by polling GVM engine
        sql = """
        SELECT scan_id, gvm_task_id, status
        FROM scans
        WHERE engine = 'GVM' AND gvm_task_id IS NOT NULL
        """
        
        all_scans = execute_query(sql,None,"all")

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
                SET status=%s,
                progress=%s,
                finished_at = NOW()
                WHERE scan_id=%s
                """
                execute_query(sql, (status, progress, scan_id))
                # Update asset record last_scanned_at time
                sql = """
                UPDATE assets
                SET last_scanned_at = NOW()
                WHERE asset_id = %s
                """
                execute_query(sql,(asset_id))
                if status in ("Failed", "Aborted", "Interrupted"):
                    log_event(
                        session["user_id"],
                        "SCAN_FAILED",
                        "SCAN",
                        scan_id,
                        f"GVM scan finished with failure status={status}"
                )
                elif status == "Done":
                      log_event(
                          session["user_id"],
                          "SCAN_COMPLETED",
                          "SCAN",
                          scan_id,
                          f"GVM scan completed successfully (progress={progress}%)"
                      )
            else:
                sql = """
                UPDATE scans
                SET status=%s, progress=%s
                WHERE scan_id=%s 
                """
                execute_query(sql, (status, progress, scan_id))

    except Exception as e:
        print("Error updating scan progress: " + str(e))

    try:
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
        scan_list = execute_query(sql,None,"all")

        # Filter out retired assets
        sql = """
        SELECT asset_id, name 
        FROM assets 
        WHERE retired = FALSE 
        ORDER BY name ASC
        """

        asset_list = execute_query(sql,None,"all")

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
    Displays detailed information for a specific scan.
    Enables optional refresh via ?refresh=1 parameter
    to update progress for active scans.
    """
    if "user_id" not in session:
        return redirect("/login")

    refresh = request.args.get("refresh") == "1"

    try:
        sql = """
        SELECT
        scans.*,
        assets.name AS asset_name,
        assets.ip_address AS asset_ip
        FROM scans
        JOIN assets ON scans.asset_id = assets.asset_id
        WHERE scans.scan_id = %s
        """
        scan = execute_query(sql, (scan_id,), "one")

        if scan is None:
            return "Scan not found", 404

        if refresh:
            FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

            if scan["status"] not in FINISHED_STATES:
                if scan["engine"] == "GVM" and scan["gvm_task_id"]:
                    status, progress = get_gvm_task_status(scan["gvm_task_id"])

                    if status in FINISHED_STATES:
                        sql = """
                        UPDATE scans
                        SET status=%s,
                        progress=%s,
                        finished_at=NOW()
                        WHERE scan_id=%s
                        """
                        execute_query(sql, (status, progress, scan_id))
                    else:
                        sql = """
                        UPDATE scans
                        SET status=%s, progress=%s
                        WHERE scan_id=%s
                        """
                        execute_query(sql, (status, progress, scan_id))

            # Re-fetch scan after refresh update
            sql = """
            SELECT
            scans.*,
            assets.name AS asset_name,
            assets.ip_address AS asset_ip
            FROM scans
            JOIN assets ON scans.asset_id = assets.asset_id
            WHERE scans.scan_id = %s
            """
            scan = execute_query(sql, (scan_id,), "one")

        # Fetch live findings from GVM for display
        findings = []
        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")
        if (scan["engine"] == "GVM"
            and scan["status"] in FINISHED_STATES
            and scan.get("gvm_report_id")):
            try:
                findings = get_gvm_findings(scan["gvm_report_id"], limit=200)
            except Exception as e:
                print("Error fetching GVM findings: " + str(e))
                findings = []

        # Fetch stored findings from database for this scan
        sql = """
        SELECT nvt_name, port, cvss_score, riskforge_score, cves, solution
        FROM findings
        WHERE scan_id = %s
        ORDER BY riskforge_score DESC
        """
        stored_findings = execute_query(sql, (scan_id,), "all")

        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            stored_findings=stored_findings,
            username=session["username"],
            role=session["role"],
        )

    except Exception as e:
        return "Error loading scan: " + str(e)

@app.route("/scans/<int:scan_id>/parse_findings", methods=["POST"])
def parse_findings(scan_id):
    """
    Parse findings from the GVM report and store them in findings table
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")

    try:
        # Obtain asset_id and report_id to parse and store findings
        sql = """
        SELECT asset_id, engine, gvm_report_id
        FROM scans 
        WHERE scan_id = %s
        """
        scan = execute_query(sql,(scan_id),"one")
        # Return various errors as HTML page (will use error display logic later)
        if scan is None:
            return "Scan not found"

        if scan["engine"] != "GVM":
            return "This scan is not a GVM scan"

        if not scan["gvm_report_id"]:
            return "No GVM report ID found for this scan"
        # Obtain findings list from GVM for particular scan, 200 max
        findings = get_gvm_findings(scan["gvm_report_id"], limit=200)

        store_findings(
            scan_id=scan_id,
            asset_id=scan["asset_id"],
            findings=findings,
            created_by=session["user_id"],
            min_score=5.0,
        )

        return redirect(f"/scans/{scan_id}")

    except Exception as e:
        return "Error parsing/storing findings: " + str(e)

@app.route("/tickets", methods=["GET"])
def tickets():
    """
    Display all tickets (newest first).
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")

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
        ORDER BY tickets.created_at DESC
        """
        ticket_list = execute_query(sql,None,"all")

    except Exception as e:
        ticket_list = []
        print("Error loading tickets:", e)

    return render_template(
        "tickets.html",
        tickets=ticket_list,
        username=session["username"],
        role=session["role"])

@app.route("/tickets/<int:ticket_id>", methods=["GET"])
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

@app.route("/tickets/<int:ticket_id>/update", methods=["POST"])
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
        # If closing set closed_at and store reason values
        if status == "Closed":
            sql = """
            UPDATE tickets
            SET status=%s,
            closed_reason=%s,
            closed_at=NOW()
            WHERE ticket_id=%s
            """
            execute_query(sql,(status, closed_reason, ticket_id))

        else:
            # If re-opening clear close fields
            sql = """
            UPDATE tickets
            SET status=%s,
            closed_reason=NULL,
            closed_at=NULL
            WHERE ticket_id=%s
            """
            execute_query(sql, (status, ticket_id))
       
        return redirect(f"/tickets/{ticket_id}")

    except Exception as e:
        return "Error updating ticket: " + str(e)
    
# Run Server
if __name__ == "__main__":
    app.run(debug=True)