import paramiko
import json

KALI_HOST = "10.0.96.32"
KALI_USER = "kali"
KALI_PASS = "kali"
REMOTE_SCRIPT = "/home/kali/remote_test/test_script.py"

def run_terminal(command):
    # Create SSH client
    client = paramiko.SSHClient()

    # Auto-accept unknown host keys (OK for testing)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to Kali
        client.connect(
            hostname=KALI_HOST,
            username=KALI_USER,
            password=KALI_PASS
        )

        stdin, stdout, stderr = client.exec_command(command)

        # Read output
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
            ips.append(ip.strip())
            if ip.strip() == '10.0.96.1':
                ips.remove('10.0.96.1')
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
            break
        if "Aggressive OS guesses:" in line:
            line = line.replace("Aggressive OS guesses:", "")
            os_name = line.split("(")[0].strip()
            break
    
    return {"ip": ip, "os": os_name}

def run_ai_scan(target_ip):
    """
    Connects to Kali via SSH,
    runs the remote scanner script,
    and returns the JSON result as a Python dictionary.
    """

    # Create SSH client
    client = paramiko.SSHClient()

    # Auto-accept unknown host keys (OK for testing)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to Kali
        client.connect(
            hostname=KALI_HOST,
            username=KALI_USER,
            password=KALI_PASS
        )

        # Build command string
        command = "python3 -u " + REMOTE_SCRIPT + " " + target_ip

        # Run remote command
        stdin, stdout, stderr = client.exec_command(command)

        # Read output
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        # Close connection
        client.close()

        # If there was an error, print it and return None
        if error:
            print("Remote scanner error:")
            print(error)
            return None

        # Convert JSON string into Python dictionary
        data = json.loads(output)

        return data

    except Exception as e:
        print("SSH connection failed:")
        print(e)
        return None