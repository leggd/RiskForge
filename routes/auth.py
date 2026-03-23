from flask import Blueprint, render_template, request, redirect, session
import bcrypt
from db import execute_query
from services.audit_service import log_event

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Authenticate a user

    Validates submitted credentials, establishes a session on success
    and logs authentication events.
    """

    # UI message placeholder
    error = None

    if request.method == "POST":
        # Retrieve form input
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            # Retrieve user record by username
            sql = "SELECT * FROM users WHERE username = %s"
            user = execute_query(sql, (username,), "one")

            # Handle unknown user
            if user is None:
                error = "User does not exist, contact your Administrator"
                log_event(
                    None,
                    "LOGIN_FAILED",
                    "USER",
                    None,
                    f"Attempted login with unknown username: {username}"
                )
            else:
                # Compare submitted password with stored hash
                password_bytes = password.encode("utf-8")
                stored_hash_bytes = user["password_hash"].encode("utf-8")

                if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                    # Create session for authenticated user
                    session["user_id"] = user["user_id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]

                    # Log successful login event
                    log_event(
                        user["user_id"],
                        "LOGIN_SUCCESS",
                        "USER",
                        None,
                        f"User: {username} logged in successfully."
                    )

                    # Redirect to dashboard after successful login
                    return redirect("/dashboard")
                else:
                    # Handle incorrect password
                    error = "Incorrect username or password"
                    log_event(
                        user["user_id"],
                        "LOGIN_FAILED",
                        "USER",
                        None,
                        f"User: {username} attempted login with incorrect password."
                    )

        # Handle unexpected errors during authentication
        except Exception as e:
            error = str(e)

    # Render login page with any error messages
    return render_template("login.html", error=error)

@auth_bp.route("/logout")
def logout():
    """
    Log out the current user

    Clears the session, records a logout event and redirects
    to the login page
    """

    # Log logout event if user is currently authenticated
    if "user_id" in session:
        log_event(
            session["user_id"],
            "LOGOUT",
            "USER",
            session["user_id"],
            f"User {session['username']} logged out."
        )

    # Clear session data to remove authentication state
    session.clear()

    # Redirect to login page after logout
    return redirect("/login")