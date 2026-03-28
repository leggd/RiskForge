from flask import Blueprint, render_template, request, redirect, session, abort
import bcrypt
from db import execute_query

users_bp = Blueprint("users_bp", __name__)

@users_bp.route("/users", methods=["GET"])
def users():
    """
    Display list of users and user creation form.
    """

    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "ADMIN":
        abort(403, description="User management is restricted to admins")

    error = None

    try:
        sql = """
        SELECT user_id, username, role
        FROM users
        WHERE retired = FALSE
        ORDER BY username ASC
        """
        users_list = execute_query(sql, None, "all")

    except Exception as e:
        users_list = []
        error = str(e)

    return render_template(
        "users.html",
        users=users_list,
        error=error,
        username=session["username"],
        role=session["role"])

@users_bp.route("/users/create", methods=["POST"])
def create_user():
    """
    Handle creation of a new user account with role assignment
    """

    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "ADMIN":
        abort(403, description="User creation is restricted to administrators")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "VIEWER")

    VALID_ROLES = ["ADMIN", "VIEWER"]

    # Get users list for re-render if needed
    sql = """
    SELECT user_id, username, role
    FROM users
    WHERE retired = FALSE
    ORDER BY username ASC
    """
    users_list = execute_query(sql, None, "all")

    # Validation
    if not username or not password:
        return render_template(
            "users.html",
            users=users_list,
            error="Username and password required",
            username=session["username"],
            role=session["role"])

    if role not in VALID_ROLES:
        return render_template(
            "users.html",
            users=users_list,
            error="Invalid role selected",
            username=session["username"],
            role=session["role"])

    try:
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(password_bytes, salt)
        password_hash = hashed_pw.decode("utf-8")

        sql = """
        INSERT INTO users(
        username,
        password_hash,
        role)
        VALUES (%s, %s, %s)
        """
        execute_query(sql, (username, password_hash, role))

        return redirect("/users")

    except Exception as e:
        return render_template(
            "users.html",
            users=users_list,
            error="Failed to create user",
            username=session["username"],
            role=session["role"])

@users_bp.route("/users/<int:user_id>", methods=["GET"])
def user_detail(user_id):
    """
    Display detailed information for a specific user.
    """

    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "ADMIN":
        abort(403, description="User management is restricted to administrators")

    try:
        sql = """
        SELECT user_id, username, role, retired
        FROM users
        WHERE user_id = %s
        """
        user = execute_query(sql, (user_id), "one")

        if user is None:
            abort(404)

        return render_template(
            "user_detail.html",
            user=user,
            username=session["username"],
            role=session["role"])

    except Exception as e:
        return "Error loading user: " + str(e)

@users_bp.route("/users/<int:user_id>/retire", methods=["POST"])
def retire_user(user_id):
    """
    Soft delete a user account by marking it as retired.
    """

    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "ADMIN":
        abort(403, description="User retirement is restricted to administrators")

    # Fetch users list for re-render if needed
    sql = """
    SELECT user_id, username, role
    FROM users
    WHERE retired = FALSE
    ORDER BY username ASC
    """
    users_list = execute_query(sql, None, "all")

    # Prevent self delete
    if user_id == session["user_id"]:
        return render_template(
            "users.html",
            users=users_list,
            error="You cannot retire your own account",
            username=session["username"],
            role=session["role"])

    try:
        sql = """
        UPDATE users
        SET retired = TRUE
        WHERE user_id = %s
        """
        execute_query(sql, (user_id))

        return redirect("/users")

    except Exception:
        return render_template(
            "users.html",
            users=users_list,
            error="Failed to retire user",
            username=session["username"],
            role=session["role"])