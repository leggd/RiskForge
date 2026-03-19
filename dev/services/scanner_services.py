import paramiko
import json
from db import execute_query

KALI_HOST = "10.0.96.32"
KALI_USER = "kali"
KALI_PASS = "kali"
REMOTE_SCRIPT = "/home/kali/remote_test/scanner.py"


def run_terminal(command):
    """
    Connects to Kali via SSH and runs a command.
    Returns the output as a string, or None if connection fails.
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
    Runs a fast nmap ping sweep against a subnet.
    Returns a list of live IP addresses, or empty list if Kali is unreachable.
    """
    command = "nmap -sn " + subnet
    output = run_terminal(command)

    if output is None:
        return []

    output = output.splitlines()

    ips = []

    for line in output:
        if "Nmap scan report for" in line:
            ip = line.replace("Nmap scan report for", "")
            ip = ip.strip()
            ip = ip.strip("()")
            if ip != "10.0.96.1":
                ips.append(ip)

    return ips


def run_os_detection(ip):
    """
    Runs nmap OS detection against a single IP.
    Returns a dict {"ip": ..., "os": ...}, or None if Kali is unreachable.
    """
    command = "nmap -O --osscan-guess " + ip
    output = run_terminal(command)

    if output is None:
        return None

    os_name = "Unknown"

    output = output.splitlines()

    for line in output:
        if "OS details:" in line:
            os_name = line.replace("OS details:", "")
            os_name = os_name.strip()
            break
        if "Aggressive OS guesses:" in line:
            os_name = line.replace("Aggressive OS guesses:", "")
            os_name = os_name.split("(")[0]
            os_name = os_name.strip()
            break

    return {"ip": ip, "os": os_name}


def run_ai_scan(target_ip, scan_id=None):
    """
    Connects to Kali via SSH, runs the remote scanner script,
    and returns the JSON result as a Python dictionary.
    Streams output to scanner_output column in scans table if scan_id provided.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=KALI_HOST,
            username=KALI_USER,
            password=KALI_PASS
        )

        command = "python3 -u " + REMOTE_SCRIPT + " " + target_ip

        stdin, stdout, stderr = client.exec_command(command)

        output = ""

        for line in stdout:
            if line is None:
                continue
            output = output + line

            if scan_id:
                from app import execute_query
                sql = """
                UPDATE scans
                SET scanner_output = %s
                WHERE scan_id = %s
                """
                execute_query(sql, (output, scan_id))

        client.close()

        # Find the line containing our JSON output
        result_line = None
        for line in output.splitlines():
            if "RISKFORGE_OUTPUT:" in line:
                result_line = line
                break

        if result_line is None:
            print("No RISKFORGE_OUTPUT found in scanner output")
            return None

        json_str = result_line.replace("RISKFORGE_OUTPUT:", "")
        data = json.loads(json_str)

        return data

    except Exception as e:
        print("SSH connection failed:")
        print(e)
        return None


def run_scan_thread(scan_id, target_ip, asset_id, user_id):
    """
    Background thread for AI scans.
    Runs the AI scanner and stores findings and verdict.
    """
    from services.scanner_worker import store_findings

    result = run_ai_scan(target_ip, scan_id)

    if result is None:
        sql = """
        UPDATE scans
        SET status=%s,
        error_message=%s,
        finished_at=NOW()
        WHERE scan_id=%s
        """
        execute_query(sql, ("Failed", "AI scanner returned no data", scan_id))

    else:
        findings = result.get("findings", [])
        summary = result.get("summary", "")

        store_findings(scan_id, asset_id, findings, user_id)

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


def run_full_ai_thread(scan_id, target_ip, asset_id, user_id):
    """
    Background thread for Full scans.
    Runs the AI scanner in parallel with GVM.
    """
    from services.scanner_worker import store_findings

    result = run_ai_scan(target_ip, scan_id)

    if result is None:
        sql = """
        UPDATE scans
        SET error_message=%s
        WHERE scan_id=%s
        """
        execute_query(sql, ("AI scanner returned no data", scan_id))

    else:
        findings = result.get("findings", [])
        summary = result.get("summary", "")

        store_findings(scan_id, asset_id, findings, user_id)

        sql = """
        UPDATE scans
        SET ai_verdict=%s, ai_complete=1
        WHERE scan_id=%s
        """
        execute_query(sql, (summary, scan_id))

    # Check if GVM is also done — if so mark the whole scan as Done
    sql = """
    SELECT status FROM scans WHERE scan_id = %s
    """
    current = execute_query(sql, (scan_id,), "one")

    if current and current["status"] == "GVM Complete":
        sql = """
        UPDATE scans
        SET status='Done'
        WHERE scan_id=%s
        """
        execute_query(sql, (scan_id,))