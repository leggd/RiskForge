import os
from flask import Flask, request, redirect, url_for, session, render_template
import pymysql
from dotenv import load_dotenv
import bcrypt
from pymysql.err import IntegrityError
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from datetime import datetime

# Load environment variables
load_dotenv()

# Initiate Flask object
app = Flask(__name__)

# Secret key for session management
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
"""
Inserts an entry into the audit_log table.

Parameters:
    user_id     -> ID of the user performing the action
    action      -> String describing the action (e.g. 'CREATE_ASSET')
    entity_type -> Type of entity affected (e.g. 'ASSET', 'USER')
    entity_id   -> Optional ID of the affected entity
    details     -> Optional descriptive text
"""
def log_event(user_id, action, entity_type, entity_id=None, details=None):
    try:
        # Get client IP address from request
        ip_address = request.remote_addr

        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
        INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
        VALUES (%s, %s, %s, %s, %s, %s)
        """

        cur.execute(sql, (
            user_id,
            action,
            entity_type,
            entity_id,
            details,
            ip_address
        ))

        conn.commit()

        cur.close()
        conn.close()

    except Exception as e:
        # Do NOT crash the app if logging fails
        print(f"AUDIT LOG ERROR: {e}")

# Create and return a MySQL connection
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor)

def start_gvm_scan(target_ip):
    """
    Starts a GVM scan for a single IP.
    Returns: task_id, report_id (may be None)
    """

    HOST = "10.0.96.32"
    PORT = 9390
    USERNAME = "admin"
    PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

    SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
    PORT_LIST_ID   = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"

    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Create target
        target_resp = gmp.create_target(
            name="RiskForge Target " + target_ip + " " + now,
            hosts=[target_ip],
            port_list_id=PORT_LIST_ID
        )
        target_id = target_resp.get("id")

        # Create task
        task_resp = gmp.create_task(
            name="RiskForge Task " + target_ip + " " + now,
            config_id=SCAN_CONFIG_ID,
            target_id=target_id,
            scanner_id=SCANNER_ID
        )
        task_id = task_resp.get("id")

        # Start task
        gmp.start_task(task_id)

        # Immediately try to get report ID
        report_id = None

        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")
        if t is not None:
            current_report = t.find("./current_report/report")
            if current_report is not None:
                report_id = current_report.get("id")

        return task_id, report_id
def get_gvm_task_status(task_id):
    """
    Gets status and progress from GVM for a given task_id.
    Returns: status_string, progress_int
    """

    HOST = "10.0.96.32"
    PORT = 9390
    USERNAME = "admin"
    PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")

        if t is None:
            return "Unknown", 0

        status = (t.findtext("./status") or "").strip()
        progress = (t.findtext("./progress") or "0").strip()

        try:
            progress = int(progress)
        except:
            progress = 0

        return status, progress
# Login Route (If request isn't POST, it defaults to GET to show login page)
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    # If request is POST, process credentials
    if request.method == "POST":
        # Assign username and password variable from form data
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        # Attempt to access MySQL database
        try:
            # Initiate DB connection and cursor variables
            conn = get_db_connection()
            cur = conn.cursor()
            # Parameterised SQL query to obtain record from usernae
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            # Obtain user record from cursor and assign to user variable
            user = cur.fetchone()
            # Gracefully close cursor and DB connection sessions
            cur.close()
            conn.close()

            # If user does not exist
            if user is None:
                error = "User does not exist, contact your Administrator"
                log_event(None,"LOGIN_FAILED","USER",None,f"Attempted login with unknown username: '{username}'")
            else:
                # Encode entered password for bcrypt comparison
                password_bytes = password.encode("utf-8")
                # Encode stored password hash from database for comparison
                stored_hash_bytes = user["password_hash"].encode("utf-8")
                # Verify entered password against stored hash
                if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                    # Store user info in session and redirect to dashboard
                    session["user_id"] = user["user_id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    log_event(user["user_id"],"LOGIN_SUCCESS","USER",None,f"User: {username} logged in successfully.")
                    return redirect(url_for("dashboard"))
                else:
                    error = "Incorrect username or password"
                    log_event(user["user_id"],"LOGIN_FAILED","USER",None,f"User: {username} attempted login with incorrect password.")
        # Catch error and display on webpage as error if DB connection issue
        except Exception as e:
            error = e
    return render_template("login.html", error=error)

# Dashboard Route (Protected Route)
@app.route("/dashboard")
def dashboard():
    # Check if user is has logged in and immediately redirect to login page if false
    if "user_id" not in session:
        return redirect(url_for("login"))
    # Show dashboard and pass username and role variables to render
    return render_template("dashboard.html", username=session['username'], role=session['role'])

# Logout Route
@app.route("/logout")
def logout():
    # Clear session to require login for dashboard access
    session.clear()
    return redirect(url_for("login"))

# Display asset inventory and handle new asset record creation
@app.route("/assets", methods=["GET", "POST"])
def assets():
    # Check if user is has logged in and immediately redirect to login page if false
    if "user_id" not in session:
        return redirect(url_for("login"))

    error = None
    success = None

    # If POST request from add asset form submission
    if request.method == "POST":
        # Assign asset attributes to variables from form data
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        asset_type = request.form.get("asset_type", "")
        exposure = request.form.get("exposure", "")
        criticality = request.form.get("criticality", "")

        # Basic validation
        if not name or not ip_address:
            error = "Name and/or IP address are required."
        else:
            # Attempt to access MySQL database
            try:
                # Initiate DB connection and cursor variables
                conn = get_db_connection()
                cur = conn.cursor()
                # Assign SQL statement string variable
                sql = """
                INSERT INTO assets (name, ip_address, asset_type, exposure, criticality)
                VALUES (%s, %s, %s, %s, %s)"""
                # Execute asset INSERT query specifiying attributes
                cur.execute(sql, (name, ip_address, asset_type, exposure, criticality))
                # Commit changes to database
                conn.commit()
                # Gracefully close cursor and DB connection sessions
                cur.close()
                conn.close()
                # Generate success message string to pass to html template
                success = "Asset added successfully."
            except Exception as e:
                error = "Error adding asset: " + e

    # Fetch assets to display on page each time is loads
    try:
        # Initiate DB connection and cursor variables
        conn = get_db_connection()
        cur = conn.cursor()
        # Execute SQL statement to obtain all active assets by added date descending
        cur.execute("SELECT * FROM assets WHERE retired = FALSE ORDER BY created_at DESC")
        # Obtain full query output from curser and assign to variable
        asset_list = cur.fetchall()
        # Gracefully close cursor and DB connection sessions
        cur.close()
        conn.close()

    except Exception as e:
        # Create empty table for error handling
        asset_list = []
        error = "Database error: " + e

    # Show asset list and pass assets dict, messages, user details to render page
    return render_template(
        "assets.html",
        assets=asset_list,
        error=error,
        success=success,
        username=session["username"],
        role=session["role"]
    )

@app.route("/assets/<int:asset_id>", methods=["GET"])
def asset_detail(asset_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    edit_mode = request.args.get("edit") == "1"

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM assets WHERE asset_id = %s", (asset_id,))
        asset = cur.fetchone()

        cur.close()
        conn.close()

        if asset is None:
            return "Asset not found", 404

        return render_template(
            "asset_detail.html",
            asset=asset,
            edit_mode=edit_mode,
            username=session["username"],
            role=session["role"]
        )

    except Exception as e:
        return "Error loading asset: " + str(e)

@app.route("/assets/<int:asset_id>/update", methods=["POST"])
def update_asset(asset_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Optional: only admins can edit assets
    # if session.get("role") != "ADMIN":
    #     return "Forbidden", 403

    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "")
    exposure = request.form.get("exposure", "")
    criticality = request.form.get("criticality", "")

    # Basic validation
    if not name or not ip_address:
        return redirect(url_for("asset_detail", asset_id=asset_id) + "?edit=1")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
        UPDATE assets
        SET name=%s, ip_address=%s, asset_type=%s, exposure=%s, criticality=%s
        WHERE asset_id=%s
        """
        cur.execute(sql, (name, ip_address, asset_type, exposure, criticality, asset_id))
        conn.commit()

        cur.close()
        conn.close()

        # Audit log (recommended)
        log_event(
            session["user_id"],
            "UPDATE_ASSET",
            "ASSET",
            asset_id,
            f"Updated asset to name={name}, ip={ip_address}, type={asset_type}, exposure={exposure}, criticality={criticality}"
        )

        # Back to read-only view
        return redirect(url_for("asset_detail", asset_id=asset_id))

    except IntegrityError:
        # This will catch duplicate IP address because ip_address is UNIQUE :contentReference[oaicite:1]{index=1}
        return redirect(url_for("asset_detail", asset_id=asset_id) + "?edit=1&err=duplicate_ip")

    except Exception as e:
        return "Error updating asset: " + str(e)

@app.route("/assets/<int:asset_id>/retire", methods=["POST"])
def retire_asset(asset_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Mark asset as retired
        cur.execute("UPDATE assets SET retired = TRUE WHERE asset_id = %s", (asset_id,))
        conn.commit()

        cur.close()
        conn.close()

        # After retiring, send user back to assets list
        return redirect(url_for("assets"))

    except Exception as e:
        return f"Error retiring asset: " + e

@app.route("/scans", methods=["GET", "POST"])
def scans():

    # ----------------------------------
    # REQUIRE LOGIN
    # ----------------------------------
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ----------------------------------
    # HANDLE NEW SCAN REQUEST (POST)
    # ----------------------------------
    if request.method == "POST":
        asset_id = request.form.get("asset_id")

        if asset_id:
            try:
                conn = get_db_connection()
                cur = conn.cursor()

                # Get IP address for selected asset
                cur.execute("SELECT ip_address FROM assets WHERE asset_id = %s", (asset_id,))
                asset = cur.fetchone()

                if asset is None:
                    raise Exception("Asset not found")

                target_ip = asset["ip_address"]

                # Start real GVM scan
                task_id, report_id = start_gvm_scan(target_ip)

                # Insert new scan record
                cur.execute("""
                    INSERT INTO scans 
                    (asset_id, started_by, gvm_task_id, gvm_report_id, status, progress)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    asset_id,
                    session["user_id"],
                    task_id,
                    report_id,
                    "Requested",   # Start as Requested (GVM will update)
                    0
                ))

                conn.commit()
                cur.close()
                conn.close()

            except Exception as e:
                print("Error starting real scan:", e)

    # ----------------------------------
    # UPDATE SCAN PROGRESS FROM GVM
    # ----------------------------------
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get ALL scans
        cur.execute("SELECT scan_id, gvm_task_id, status FROM scans")
        all_scans = cur.fetchall()

        FINISHED_STATES = ("Done", "Stopped", "Interrupted", "Aborted", "Failed")

        for scan in all_scans:

            scan_id = scan["scan_id"]
            task_id = scan["gvm_task_id"]
            current_status = scan["status"]

            # Skip already finished scans
            if current_status in FINISHED_STATES:
                continue

            # Ask GVM for latest status
            status, progress = get_gvm_task_status(task_id)

            print("Updating scan:", scan_id, "| GVM status:", status, "| Progress:", progress)

            # If finished, set finished_at
            if status in FINISHED_STATES:
                cur.execute("""
                    UPDATE scans
                    SET status=%s, progress=%s, finished_at=NOW()
                    WHERE scan_id=%s
                """, (status, progress, scan_id))
            else:
                cur.execute("""
                    UPDATE scans
                    SET status=%s, progress=%s
                    WHERE scan_id=%s
                """, (status, progress, scan_id))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("Error updating scan progress:", e)

    # ----------------------------------
    # LOAD SCAN LIST FOR DISPLAY
    # ----------------------------------
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT 
                scans.scan_id,
                scans.status,
                scans.progress,
                scans.started_at,
                scans.finished_at,
                assets.name AS asset_name,
                assets.ip_address
            FROM scans
            JOIN assets ON scans.asset_id = assets.asset_id
            ORDER BY scans.started_at DESC
        """)

        scan_list = cur.fetchall()

        # Load active assets for dropdown
        cur.execute("""
            SELECT asset_id, name 
            FROM assets 
            WHERE retired = FALSE 
            ORDER BY name ASC
        """)

        asset_list = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        scan_list = []
        asset_list = []
        print("Error loading scans:", e)

    # ----------------------------------
    # RENDER PAGE
    # ----------------------------------
    return render_template(
        "scans.html",
        scans=scan_list,
        assets=asset_list,
        username=session["username"],
        role=session["role"]
    )
# Run Server
if __name__ == "__main__":
    app.run(debug=True)
