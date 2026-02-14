import os
from flask import Flask, request, redirect, url_for, session, render_template
import pymysql
from dotenv import load_dotenv
import bcrypt

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secret key is required for session management
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


def get_db_connection():
    """
    Creates and returns a new MySQL connection.
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor
    )


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  -> Show login form
    POST -> Process login credentials
    """
    error = None
    
    # If request is POST, process credentials
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Parameterised query prevents SQL injection
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()

            cur.close()
            conn.close()

            # If user does not exist
            if user is None:
                error = "User does not exist"
            else:

                # bcrypt expects bytes
                password_bytes = password.encode("utf-8")
                stored_hash_bytes = user["password_hash"].encode("utf-8")

                # Verify password against stored hash
                if bcrypt.checkpw(password_bytes, stored_hash_bytes):

                    # Store user info in session
                    session["user_id"] = user["user_id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]

                    return redirect(url_for("dashboard"))
                else:
                    error = "Incorrect username or password"

        except Exception as e:
            error = e
    
    return render_template("login.html", error=error)

# Dashboard Route
@app.route("/dashboard")
def dashboard():
    """
    Example protected route.
    Only accessible if logged in.
    """

    # Check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session['username'], role=session['role'])

# Logout Route
@app.route("/logout")
def logout():
    """
    Clears session and logs user out.
    """

    session.clear()
    return redirect(url_for("login"))

# Admin Account Seeing Form
@app.route("/admin_form")
def admin_form():
    return """
    <form method="POST" action="/seed_admin">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Create Admin</button>
    </form>
    """

# Temporary Admin Seed Route (DELETE LATER)
@app.route("/seed_admin", methods=["GET", "POST"])
def seed_admin():
    """
    GET  -> Shows usage instructions
    POST -> Creates an ADMIN user using form data
    """

    # If someone visits this route in the browser (GET request)
    if request.method == "GET":
        return (
            "POST to this route with form fields 'username' and 'password' "
            "to create an ADMIN user. Remove this route after use."
        )

    # Retrieve username and password from form data
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Basic validation
    if username == "" or password == "":
        return "Username and password are required.", 400

    try:
        # Convert password string to bytes (bcrypt requires bytes)
        password_bytes = password.encode("utf-8")

        # Generate bcrypt hash (includes salt automatically)
        password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        # Convert hash back to string for storing in MySQL
        password_hash_str = password_hash.decode("utf-8")

        # Open database connection
        conn = get_db_connection()
        cur = conn.cursor()

        # Insert new ADMIN user using parameterised query
        # (%s prevents SQL injection)
        sql = """
        INSERT INTO users (username, password_hash, role)
        VALUES (%s, %s, 'ADMIN');
        """
        cur.execute(sql, (username, password_hash_str))

        # Commit changes to database
        conn.commit()

        # Close connection
        cur.close()
        conn.close()

        return f"Admin user '{username}' created successfully. Remove this route now."

    except Exception as e:
        return f"Error creating admin user: {e}", 500

@app.route("/setup_users_table")
def setup_users_table():
    """
    Creates the users table in the database.
    Safe to run multiple times because of IF NOT EXISTS.
    """

    # SQL statement to create the users table
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('ADMIN', 'VIEWER') NOT NULL DEFAULT 'VIEWER',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """

    try:
        # Open database connection
        conn = get_db_connection()
        cur = conn.cursor()

        # Execute the CREATE TABLE statement
        cur.execute(create_table_sql)

        # Commit the change (required for DDL operations)
        conn.commit()

        # Close cursor and connection
        cur.close()
        conn.close()

        return "Users table created successfully (or already exists)."

    except Exception as e:
        return f"Error creating users table: {e}", 500

# Run Server
if __name__ == "__main__":
    app.run(debug=True)
