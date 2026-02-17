import os
from flask import Flask, request, redirect, url_for, session, render_template
import pymysql
from dotenv import load_dotenv
import bcrypt

# Load environment variables
load_dotenv()

# Initiate Flask object
app = Flask(__name__)

# Secret key for session management
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Create and return a MySQL connection
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor)

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
                    return redirect(url_for("dashboard"))
                else:
                    error = "Incorrect username or password"
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

@app.route("/assets/<int:asset_id>")

def asset_detail(asset_id):
    # Check if user is has logged in and immediately redirect to login page if false
    if "user_id" not in session:
        return redirect(url_for("login"))
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch one asset by primary key
        cur.execute("SELECT * FROM assets WHERE asset_id = %s", (asset_id,))
        asset = cur.fetchone()

        cur.close()
        conn.close()

        # If no asset found, return 404
        if asset is None:
            return "Asset not found", 404

        return render_template(
            "asset_detail.html",
            asset=asset,
            username=session["username"],
            role=session["role"])

    except Exception as e:
        return f"Error loading asset: " + e

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
    
# Admin Account Seeding Form (ONE TIME USE FORM TO CREATE ADMIN CREDENTIALS)
# @app.route("/admin_form")
# def admin_form():
#     return """
#     <form method="POST" action="/seed_admin">
#         <input name="username" placeholder="Username">
#         <input name="password" type="password" placeholder="Password">
#         <button type="submit">Create Admin</button>
#     </form>
#     """

# Temporary Admin Seed Route (ONE TIME USE FUNCTION TO INSERT ADMIN RECORD INTO DB)
# @app.route("/seed_admin", methods=["POST"])
# def seed_admin():
#     # Retrieve username and password from admin seed form data
#     username = request.form.get("username", "").strip()
#     password = request.form.get("password", "")
#     try:
#         # Encode entered password for bcrypt operations
#         password_bytes = password.encode("utf-8")
#         # Generate password hash from entered password with salt
#         password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
#         # Decode hash back to string for storing in DB
#         password_hash_str = password_hash.decode("utf-8")
#         # Initiate DB connection and cursor variables
#         conn = get_db_connection()
#         cur = conn.cursor()
#         # SQL query variable assigned as string
#         sql = """
#         INSERT INTO users (username, password_hash, role)
#         VALUES (%s, %s, 'ADMIN');
#         """
#         # Execute query specifiying username and password hash for %s
#         cur.execute(sql, (username, password_hash_str))
#         # Commit changes to database
#         conn.commit()
#         # Gracefully close cursor and DB connection sessions
#         cur.close()
#         conn.close()

#     except Exception as e:
#         return "Error: " + e

# Users Table Setup Form (ONE TIME USE ROUTE TO CREATE USERS TABLE)
# @app.route("/setup_users_table")
# def setup_users_table():
#     # SQL statement to create the users table
#     create_table_sql = """
#     CREATE TABLE IF NOT EXISTS users (
#         user_id INT AUTO_INCREMENT PRIMARY KEY,
#         username VARCHAR(50) NOT NULL UNIQUE,
#         password_hash VARCHAR(255) NOT NULL,
#         role ENUM('ADMIN', 'VIEWER') NOT NULL DEFAULT 'VIEWER',
#         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"""
#     try:
#         # Initiate DB connection and cursor variables
#         conn = get_db_connection()
#         cur = conn.cursor()
#         # Execute the CREATE TABLE query
#         cur.execute(create_table_sql)
#         # Commit the change to database
#         conn.commit()
#         # Gracefully close cursor and DB connection sessions
#         cur.close()
#         conn.close()
#         return "Users table created"

#     except Exception as e:
#         return "Error" + e

# Run Server
if __name__ == "__main__":
    app.run(debug=True)
