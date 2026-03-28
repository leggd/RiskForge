import paramiko
import json
from db import execute_query
from services.findings_service import store_findings, prioritise_findings
from services.ticket_service import create_tickets
from services.audit_service import log_event
import os
from dotenv import load_dotenv

load_dotenv()
KALI_HOST = os.getenv("SCANNER_HOST")
KALI_USER = os.getenv("KALI_USER")
KALI_PASS = os.getenv("KALI_PASS")
REMOTE_SCRIPT = os.getenv("REMOTE_SCRIPT")

def run_terminal(command):
    """
    Connects to Kali via SSH and runs a command
    Returns the output as a string or None if connection fails
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=KALI_HOST,
            username=KALI_USER,
            password=KALI_PASS
        )

        stdin, stdout, stderr = client.exec_command(command)

        output = stdout.read().decode().strip()
        return output

    except Exception as e:
        print("SSH connection failed:")
        print(e)
        return None

def run_ping_sweep(subnet):
    """
    Perform a network discovery scan using nmap to identify live hosts

    Executes a ping sweep against the specified subnet via the remote Kali
    host, parses the output and returns a list of active IP addresses
    Returns an empty list if the scan cannot be executed
    """
    # Generate nmap ping sweep command
    command = "nmap -sn " + subnet

    # Execute command obtaining raw output
    output = run_terminal(command)

    # If SSH or command execution fails, return empty result
    if output is None:
        return []

    # Split output into individual lines for parsing
    output = output.splitlines()

    ips = []

    # Parse nmap output to extract discovered IP addresses
    for line in output:
        if "Nmap scan report for" in line:

            # Extract IP address from output line
            ip = line.replace("Nmap scan report for", "")
            ip = ip.strip()
            ip = ip.strip("()")

            # Exclude default gateway (hardcoded for now)
            if ip != "10.0.96.1":
                ips.append(ip)

    # Return list of active hosts
    return ips

def run_os_detection(ip):
    """
    Perform OS detection on a target host using nmap

    Executes an nmap OS detection scan via the remote Kali host, parses the
    output to determine the most likely operating system and returns a
    dictionary containing the IP and detected OS. Returns None if the scan
    cannot be executed
    """
    # Generate nmap OS detection command
    command = "nmap -O --osscan-guess " + ip

    # Execute command and obtain raw output
    output = run_terminal(command)

    # If SSH or command execution fails, return None
    if output is None:
        return None

    # Default OS value if no match found
    os_name = "Unknown"

    # Split output into lines for parsing
    output = output.splitlines()

    # Parse nmap output for OS detection results
    for line in output:

        # Preferred match detailed OS identification
        if "OS details:" in line:
            os_name = line.replace("OS details:", "")
            os_name = os_name.strip()
            break

        # Fallback match to an aggressive OS guess
        if "Aggressive OS guesses:" in line:
            os_name = line.replace("Aggressive OS guesses:", "")
            os_name = os_name.split("(")[0]
            os_name = os_name.strip()
            break

    # Return result dict
    return {"ip": ip, "os": os_name}

def run_ai_scan(target_ip, scan_id=None):
    """
    Execute the AI scanner on a remote Kali host and process the output

    Connects via SSH, runs the remote scanning script, streams output to the
    database if a scan_id is provided, extracts the final JSON result from the
    output and returns it as a Python dictionary. Returns None on failure
    """
    # Initialise SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to remote Kali machine
        client.connect(
            hostname=KALI_HOST,
            username=KALI_USER,
            password=KALI_PASS
        )

        # Build command to execute remote scanner script
        # -u ensures unbuffered output for real-time interaction
        command = "python3 -u " + REMOTE_SCRIPT + " " + target_ip

        # Execute command on remote host
        stdin, stdout, stderr = client.exec_command(command)

        # Accumulate scanner output
        output = ""

        # Stream output as the scan runs
        for line in stdout:
            if line is None:
                continue

            # Append new output to cumulative string
            output = output + line

            # If scan_id provided, update scanner_output column in database
            if scan_id:
                sql = """
                UPDATE scans
                SET scanner_output = %s
                WHERE scan_id = %s
                """
                execute_query(sql, (output, scan_id))

        # Close SSH connection after command completes
        client.close()

        # Locate the line containing final JSON output marker
        result_line = None
        for line in output.splitlines():
            if "RISKFORGE_OUTPUT:" in line:
                result_line = line
                break

        # If no final output marker found, return None
        if result_line is None:
            print("No RISKFORGE_OUTPUT found in scanner output")
            return None

        # Extract JSON string from output line
        json_str = result_line.replace("RISKFORGE_OUTPUT:", "")

        # Parse JSON string into Python dictionary
        data = json.loads(json_str)

        # Return structured scan result
        return data

    except Exception as e:
        # Graceful error handling
        print("SSH connection failed:")
        print(e)
        return None

def run_scan_thread(scan_id, target_ip, asset_id, user_id):
    """
    Execute an AI scan in a background thread and process results

    Runs the AI scanner, handles failure conditions, stores findings,
    applies prioritisation, creates tickets and updates the scan record
    with final status and results
    """

    # Log scan start
    log_event(
        None,
        "SCAN_STARTED",
        "SCAN",
        scan_id,
        f"Scan started for asset {asset_id} ({target_ip})"
    )

    # Execute AI scan and retrieve structured result
    result = run_ai_scan(target_ip, scan_id)

    # Handle scan failure (no data returned)
    if result is None:
        sql = """
        UPDATE scans
        SET status=%s,
        error_message=%s,
        finished_at=NOW()
        WHERE scan_id=%s
        """
        execute_query(sql, ("Failed", "AI scanner returned no data", scan_id))

        # Log failure
        log_event(
            None,
            "SCAN_FAILED",
            "SCAN",
            scan_id,
            "AI scanner returned no data"
        )

    else:
        # Extract findings and summary from scan result
        findings = result.get("findings", [])
        summary = result.get("summary", "")

        # Store findings in database and calculate RiskForge scores
        findings = store_findings(scan_id, asset_id, findings)
        
        # Apply PoC prioritisation logic
        findings = prioritise_findings(findings)

        # Log findings processed
        log_event(
            None,
            "FINDINGS_PROCESSED",
            "SCAN",
            scan_id,
            f"{len(findings)} findings processed"
        )

        # Create tickets from prioritised findings
        create_tickets(scan_id, asset_id, findings, user_id)

        # Log ticket creation
        log_event(
            None,
            "TICKETS_CREATED",
            "SCAN",
            scan_id,
            "Tickets created from scan findings"
        )

        # Update scan record with completion status and AI verdict
        sql = """
        UPDATE scans
        SET status=%s,
        progress=%s,
        ai_verdict=%s,
        finished_at=NOW(),
        findings_parsed=1
        WHERE scan_id=%s
        """
        execute_query(sql, ("Done", 100, summary, scan_id))

        # Log completion
        log_event(
            None,
            "SCAN_COMPLETED",
            "SCAN",
            scan_id,
            "Scan completed successfully"
        )

        # Update last_scanned_at time on asset record
        sql = """
        UPDATE assets
        SET last_scanned_at = NOW()
        WHERE asset_id = %s
        """
        execute_query(sql, (asset_id))

def run_full_ai_thread(scan_id, target_ip, asset_id, user_id):
    """
    Execute the AI portion of a full scan in a background thread

    Runs the AI scanner alongside an existing GVM scan, processes and stores
    findings, creates tickets, and updates the scan record. If both AI and GVM
    processes are complete, the scan is marked as fully done.
    """

    # Log AI phase start
    log_event(
        None,
        "AI_SCAN_STARTED",
        "SCAN",
        scan_id,
        f"AI scan started for asset {asset_id} ({target_ip})"
    )

    # Execute AI scan and retrieve result
    result = run_ai_scan(target_ip, scan_id)

    # Handle AI scanner failure
    if result is None:
        sql = """
        UPDATE scans
        SET error_message=%s
        WHERE scan_id=%s
        """
        execute_query(sql, ("AI scanner returned no data", scan_id))

        # Log failure
        log_event(
            None,
            "AI_SCAN_FAILED",
            "SCAN",
            scan_id,
            "AI scanner returned no data"
        )

    else:
        # Extract findings and summary from AI scan result
        findings = result.get("findings", [])
        summary = result.get("summary", "")

        # Store findings and calculate RiskForge scores
        findings = store_findings(scan_id, asset_id, findings)
        
        # Apply prioritisation logic to select key findings
        findings = prioritise_findings(findings)

        # Log findings processed
        log_event(
            None,
            "AI_FINDINGS_PROCESSED",
            "SCAN",
            scan_id,
            f"{len(findings)} findings processed"
        )

        # Create remediation tickets from prioritised findings
        create_tickets(scan_id, asset_id, findings, user_id)

        # Log ticket creation
        log_event(
            None,
            "AI_TICKETS_CREATED",
            "SCAN",
            scan_id,
            "Tickets created from AI scan"
        )

        # Update scan with AI results and mark AI phase complete
        sql = """
        UPDATE scans
        SET ai_verdict=%s, ai_complete=1
        WHERE scan_id=%s
        """
        execute_query(sql, (summary, scan_id))

        # Log AI completion
        log_event(
            None,
            "AI_SCAN_COMPLETED",
            "SCAN",
            scan_id,
            "AI scan phase completed"
        )

    # Check if GVM scan has completed
    sql = """
    SELECT status 
    FROM scans 
    WHERE scan_id = %s
    """
    current = execute_query(sql, (scan_id), "one")

    # If GVM is complete, mark entire scan as Done
    if current and current["status"] == "GVM Complete":
        sql = """
        UPDATE scans
        SET status='Done'
        WHERE scan_id=%s
        """
        execute_query(sql, (scan_id))

        # Log full scan completion
        log_event(
            None,
            "FULL_SCAN_COMPLETED",
            "SCAN",
            scan_id,
            "Full scan (GVM + AI) completed"
        )
        
        # Update last_scanned_at time on asset record
        sql = """
        UPDATE assets
        SET last_scanned_at = NOW()
        WHERE asset_id = %s
        """
        execute_query(sql, (asset_id))