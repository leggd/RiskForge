# Handles connecting to the Kali machine
# and running the lads scanner script remotely.
import paramiko
import json


# ----------------------------------------------------
# CONNECTION SETTINGS (testing only – will move to .env later)
# ----------------------------------------------------

KALI_HOST = "10.0.96.32"
KALI_USER = "kali"
KALI_PASS = "kali"
REMOTE_SCRIPT = "/home/kali/remote_test/test_script.py"

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