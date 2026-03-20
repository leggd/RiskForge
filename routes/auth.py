from flask import Blueprint, render_template, request, redirect, session
import bcrypt
from db import execute_query
from services.audit_service import log_event

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user authentication
    """
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            sql = "SELECT * FROM users WHERE username = %s"
            user = execute_query(sql, (username), "one")

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
                password_bytes = password.encode("utf-8")
                stored_hash_bytes = user["password_hash"].encode("utf-8")

                if bcrypt.checkpw(password_bytes, stored_hash_bytes):
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
                    error = "Incorrect username or password"
                    log_event(
                        user["user_id"],
                        "LOGIN_FAILED",
                        "USER",
                        None,
                        f"User: {username} attempted login with incorrect password."
                    )

        except Exception as e:
            error = str(e)

    return render_template("login.html", error=error)

@auth_bp.route("/logout")
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