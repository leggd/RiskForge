from flask import Blueprint, render_template, request, redirect, session
from db import execute_query
from pymysql.err import IntegrityError
from services.audit_service import log_event
from services.scanner_service import run_ping_sweep, run_os_detection
import ipaddress

assets_bp = Blueprint("assets", __name__)

@assets_bp.route("/assets", methods=["GET"])
def assets():
    """
    Render the assets page

    Displays stored assets, performs network discovery on a predefined
    subnet and optionally performs OS detection on a selected host
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # UI message placeholders
    error = None
    success = None

    # Discover active hosts on subnet using ping sweep (nmap)
    subnet = "10.0.96.0/24"
    discovered_hosts = run_ping_sweep(subnet)

    # Get selected IP from query parameters
    selected_ip = request.args.get("ip")
    selected_os = None

    # Perform OS detection if an IP is selected
    if selected_ip:
        result = run_os_detection(selected_ip)
        if result:
            selected_os = result["os"]

    # Retrieve all non-retired assets from database
    try:
        sql = """
        SELECT * FROM assets 
        WHERE retired = FALSE
        ORDER BY created_at DESC
        """
        asset_list = execute_query(sql, None, "all")

    # Handle database errors gracefully
    except Exception as e:
        asset_list = []
        error = "Database error: " + str(e)

    # Render template with asset and discovery data with error/success
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

@assets_bp.route("/assets", methods=["POST"])
def add_asset():
    """
    Create a new asset

    Validates user input, checks for duplicate assets, inserts the record
    into the database and logs the creation event.
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # UI message placeholder
    error = None

    # Retrieve form inputs
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "")
    exposure = request.form.get("exposure", "")
    criticality = request.form.get("criticality", "")

    # Validate required fields
    if not name or not ip_address:
        error = "Name and/or IP address are required"
    else:
        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            error = "Invalid IP address format."

        # If validation passes, check for duplicate name or IP
        if not error:
            try:
                sql = """
                SELECT asset_id
                FROM assets
                WHERE ip_address = %s OR name = %s
                """
                exists = execute_query(sql, (ip_address, name), "one")

                # Duplicate asset found
                if exists:
                    error = "Asset with that name or IP address already exists"

                # Insert new asset and log event
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
                        # Record audit log for asset creation
                        log_event(
                            session["user_id"],
                            "CREATE_ASSET",
                            "ASSET",
                            asset_id,
                            "Created asset name=" + name + ", ip=" + ip_address
                        )

                    except Exception as e:
                        error = "Error adding asset: " + str(e)

            except Exception as e:
                error = "Wider Error: " + str(e)

    # Redirect back to assets page after form submission
    return redirect("/assets")

@assets_bp.route("/assets/<int:asset_id>", methods=["GET"])
def asset_detail(asset_id):
    """
    Render the asset detail page

    Displays detailed information for a specific asset and supports
    optional edit mode via ?edit=1
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # Determine whether edit mode is enabled
    edit_mode = request.args.get("edit") == "1"

    try:
        # Retrieve asset record by asset_id
        sql = """
        SELECT * FROM assets
        WHERE asset_id = %s        
        """
        asset = execute_query(sql, (asset_id), "one")

        # Return 404 if asset does not exist
        if asset is None:
            return "Asset not found", 404

        # Render asset detail page with optional edit mode
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
    Update an existing asset

    Validates submitted form data, applies changes to the database
    and redirects back to edit mode if validation fails
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")

    # Retrieve form input
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "")
    exposure = request.form.get("exposure", "")
    criticality = request.form.get("criticality", "")

    # Validate required fields
    if not name or not ip_address:
        return redirect(f"/assets/{asset_id}?edit=1")

    # Validate IP address format
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return redirect(f"/assets/{asset_id}?edit=1")
    
    try:
        # Update asset record with new values
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

        # Record audit log for asset update
        log_event(
            session["user_id"],
            "UPDATE_ASSET",
            "ASSET",
            asset_id,
            f"Updated asset to name={name}, ip={ip_address},\
             type={asset_type}, exposure={exposure}, criticality={criticality}"
        )

        # Redirect to asset detail page after successful update
        return redirect(f"/assets/{asset_id}")

    # Handle duplicate IP db constraint
    except IntegrityError:
        return redirect(f"/assets/{asset_id}?edit=1&err=duplicate_ip")
    
    # Handle any other errors during update
    except Exception as e:
        return "Error updating asset: " + str(e)

@assets_bp.route("/assets/<int:asset_id>/retire", methods=["POST"])
def retire_asset(asset_id):
    """
    Retire an asset

    Marks the asset as retired instead of deleting it and redirects
    back to the assets list
    """

    # Ensure user is authenticated via session cookie
    if "user_id" not in session:
        return redirect("/login")
    
    try:
        # Mark asset as retired (soft delete)
        sql = """
        UPDATE assets 
        SET retired = TRUE 
        WHERE asset_id = %s
        """              
        execute_query(sql, (asset_id,))

        # Record audit log for asset retirement
        log_event(
            session["user_id"],
            "RETIRE_ASSET",
            "ASSET",
            asset_id,
            f"Asset {asset_id} marked as retired"
        )

        # Redirect to assets list after successful retirement
        return redirect("/assets")

    except Exception as e:
        return "Error retiring asset: " + str(e)