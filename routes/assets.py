from flask import Blueprint, render_template, request, redirect, session
from db import execute_query
from pymysql.err import IntegrityError
from services.audit_service import log_event
from services.scanner_service import run_ping_sweep, run_os_detection
import ipaddress

assets_bp = Blueprint("assets", __name__)

@assets_bp.route("/assets", methods=["GET", "POST"])
def assets():
    """
    Display and manage active assets
    """
    if "user_id" not in session:
        return redirect("/login")

    error = None
    success = None

    # Add asset block
    if request.method == "POST":
        # Obtain html form data
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        asset_type = request.form.get("asset_type", "")
        exposure = request.form.get("exposure", "")
        criticality = request.form.get("criticality", "")
        
        # Error handling for duplicates and IP format
        if not name or not ip_address:
            error = "Name and/or IP address are required."
        else:
            # Attempt to create ipaddress object from user input IP
            # If unsuccessful, generate error message and don't add asset
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                error = "Invalid IP address format."

            # Input validation passed, check for duplicate asset attributes
            if not error:
                try:
                    sql = """
                    SELECT asset_id
                    FROM assets
                    WHERE ip_address = %s OR name = %s
                    """
                    exists = execute_query(sql,(ip_address, name),"one")

                    # If record is returned, duplicate asset name or IP found
                    if exists:
                        error = "Asset with that name or IP address already exists"
                    
                    # All validation passed, insert new asset record into database
                    # Immediately obtain asset_id from newly inserted record for audit
                    else:
                        try:
                            sql = """
                            INSERT INTO assets(
                            name, 
                            ip_address,
                            asset_type,
                            exposure,
                            criticality)
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

    # Discover all Online/Active hosts on subnet using nmap, stored as list
    subnet = "10.0.96.0/24"
    discovered_hosts = run_ping_sweep(subnet)

    # Obtain 'clicked' IP from Network Discovery list
    selected_ip = request.args.get("ip")
    selected_os = None

    # Obtain OS best guess from nmap
    if selected_ip:
        result = run_os_detection(selected_ip)
        if result:
            selected_os = result["os"]

    # Obtain full list of stored, active assets
    try:
        sql = """
        SELECT * FROM assets 
        WHERE retired = FALSE
        ORDER BY created_at DESC
        """        
        asset_list = execute_query(sql, None, "all")

    # Catch error and assign empty list to prevent crashing
    except Exception as e:
        asset_list = []
        error = "Database error: " + str(e)

    return render_template(
        "assets.html",
        assets=asset_list,
        error=error,
        success=success,
        discovered_hosts=discovered_hosts,
        selected_ip=selected_ip,
        selected_os=selected_os,
        username=session["username"],
        role=session["role"])

@assets_bp.route("/assets/<int:asset_id>", methods=["GET"])
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

@assets_bp.route("/assets/<int:asset_id>/update", methods=["POST"])
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

@assets_bp.route("/assets/<int:asset_id>/retire", methods=["POST"])
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