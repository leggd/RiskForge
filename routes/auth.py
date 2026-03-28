from flask import Blueprint, render_template, request, redirect, session
import bcrypt
from db import execute_query
from services.audit_service import log_event
from datetime import datetime, timedelta

auth_bp = Blueprint("auth", __name__)

# updates the database to refresh contents to unlock account 
def unlock_account(user_id):
    try:
        sql = """UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = %s"""
        execute_query(sql, (user_id,))
    except Exception as e:
        print(f"error unlocking account: {e}")

# updates database with the failed attempts number 
def failed_log(user_id, failed_attempts):
    try: 
        sql = """UPDATE users SET failed_attempts = %s WHERE user_id = %s"""
        execute_query(sql, (failed_attempts, user_id))
    except Exception as e:
        print(f"error updating failed attempts: {e}")

# locks the specific account 
def lock_account(user_id, locked_out_minutes):
    try:
        locked_until = datetime.now() + timedelta(minutes=locked_out_minutes)
        sql = "UPDATE users SET locked_until = %s WHERE user_id = %s"
        execute_query(sql, (locked_until, user_id))
    except Exception as e:
        print(f"error locking account: {e}")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Authenticate a user

    Validates submitted credentials, establishes a session on success,
    enforces account lockout on repeated failures and logs authentication events.
    """

    error = None

    # Lockout config
    MAX_LOGIN = 5
    LOCKOUT_MINUTES = 15

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            sql = "SELECT * FROM users WHERE username = %s"
            user = execute_query(sql, (username,), "one")

            # Prevent login if user account retired
            if user and user["retired"]:
                error = "Account is disabled"

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
                # Check if account is locked
                if user["locked_until"] and datetime.now() < user["locked_until"]:
                    unlock_time = user["locked_until"].strftime("%H:%M")
                    error = f"Account locked. Try again after {unlock_time}"

                else:
                    password_bytes = password.encode("utf-8")
                    stored_hash_bytes = user["password_hash"].encode("utf-8")

                    if bcrypt.checkpw(password_bytes, stored_hash_bytes):

                        # Reset failed attempts on success
                        unlock_account(user["user_id"])

                        # Create session
                        session["user_id"] = user["user_id"]
                        session["username"] = user["username"]
                        session["role"] = user["role"]

                        log_event(
                            user["user_id"],
                            "LOGIN_SUCCESS",
                            "USER",
                            None,
                            f"User: {username} logged in successfully."
                        )

                        return redirect("/dashboard")

                    else:
                        # Failed login
                        error = "Incorrect username or password"

                        log_event(
                            user["user_id"],
                            "LOGIN_FAILED",
                            "USER",
                            None,
                            f"User: {username} attempted login with incorrect password."
                        )

                        # Increment failed attempts
                        new_attempts = user["failed_attempts"] + 1
                        failed_log(user["user_id"], new_attempts)

                        # Lock account if threshold reached
                        if new_attempts >= MAX_LOGIN:
                            lock_account(user["user_id"], LOCKOUT_MINUTES)
                            error = f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes"
                        else:
                            remaining = MAX_LOGIN - new_attempts
                            error = f"Incorrect credentials, {remaining} attempts remaining"

        except Exception as e:
            error = str(e)

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